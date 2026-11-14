/**
 * Attack surface graph: Internet, then the way in (internet gateway or load
 * balancer), then exposed resources and load balancer targets, grouped into
 * lanes by account, Region and VPC. Used full-size with pan and zoom on the
 * Attack graph page, and compact on the dashboard.
 */
import { h, s } from './dom.js';
import type { Row, Severity } from './data.js';
import * as D from './data.js';

export const ICON: Record<string, string> = {
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm-9 9h18M12 3c2.5 2.6 3.8 5.6 3.8 9S14.5 18.4 12 21M12 3C9.5 5.6 8.2 8.6 8.2 12s1.3 6.4 3.8 9',
  gateway: 'M4 20V9l8-5 8 5v11M8 20v-6h8v6M4 20h16',
  lb: 'M12 4v5M12 9l-6 6M12 9l6 6M12 9v6M4 18h4M10 18h4M16 18h4',
  server: 'M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01',
  db: 'M5 6c0-1.7 3.1-3 7-3s7 1.3 7 3-3.1 3-7 3-7-1.3-7-3Zm0 0v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3',
  key: 'M14 10a4 4 0 1 1-4-4 4 4 0 0 1 4 4Zm-1 3 7 7M17 17l2-2',
  target: 'M12 3v4M12 17v4M3 12h4M17 12h4M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z',
  cluster: 'M12 3l7 4v10l-7 4-7-4V7zM12 3v18M5 7l14 10M19 7 5 17',
  chart: 'M4 20V4M4 20h16M8 16v-5M12 16V8M16 16v-3',
  wide: 'M3 12h18M7 8l-4 4 4 4M17 8l4 4-4 4',
};

export function iconFor(r: Row): string {
  if (r.f.kind === 'load-balancer') return 'lb';
  return { admin: 'key', data: 'db', control: 'cluster', wide: 'wide', web: 'server', other: 'server' }[D.category(r.f)];
}
export function iconSvg(name: string, size = 16): SVGElement {
  return s('svg', { viewBox: '0 0 24 24', width: size, height: size, 'aria-hidden': 'true', class: 'ico' }, s('path', { d: ICON[name] ?? ICON.server!, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));
}

const sevColor = (sv?: Severity) => `var(--${sv ?? 'info'})`;
const worse = (a: Severity | undefined, b: Severity) => (!a || D.sevRank(b) < D.sevRank(a) ? b : a);

interface GNode { id: string; col: number; title: string; sub: string; icon: string; sev?: Severity; count: number; rows: Row[]; lane: string; verdict?: string }
interface GEdge { from: string; to: string; sev?: Severity; verdict?: string; rows: Row[] }

export interface GraphOptions {
  compact?: boolean;
  showTargets?: boolean;
  selected?: Row | undefined;
  /** Nodes whose title or ID contains this text are emphasised. */
  focus?: string;
  onSelect?: (r: Row) => void;
}

function build(rows: Row[], showTargets: boolean) {
  const nodes = new Map<string, GNode>();
  const edges = new Map<string, GEdge>();
  nodes.set('internet', { id: 'internet', col: 0, title: 'Internet', sub: D.plural(rows.length, 'exposure'), icon: 'globe', count: rows.length, rows, lane: '' });
  const edge = (from: string, to: string, r: Row, verdict?: string) => {
    const k = `${from}>${to}`;
    const e = edges.get(k) ?? { from, to, rows: [], ...(verdict ? { verdict } : {}) };
    e.rows.push(r);
    if (!verdict) e.sev = worse(e.sev, r.f.severity);
    edges.set(k, e);
  };
  for (const r of rows) {
    const lane = `${r.snap.account} / ${r.snap.region} / ${r.f.vpcId}`;
    const entryId = `${r.snap.key}|${D.entryPoint(r.f)}`;
    const isLb = r.f.kind === 'load-balancer';
    const entry = nodes.get(entryId) ?? { id: entryId, col: 1, title: isLb ? r.f.resourceName : D.entryPoint(r.f), sub: isLb ? 'Internet-facing load balancer' : 'Internet gateway', icon: isLb ? 'lb' : 'gateway', count: 0, rows: [], lane };
    entry.sev = worse(entry.sev, r.f.severity);
    entry.count += 1;
    entry.rows.push(r);
    nodes.set(entryId, entry);
    edge('internet', entryId, r);
    if (isLb) {
      if (!showTargets) continue;
      for (const t of r.f.targets ?? []) {
        const tid = `${entryId}|${t.targetId}:${t.port}`;
        if (!nodes.has(tid)) nodes.set(tid, { id: tid, col: 2, title: t.targetId, sub: `port ${t.port}, ${t.verdict}`, icon: 'target', count: 0, rows: [r], lane, verdict: t.verdict });
        edge(entryId, tid, r, t.verdict);
      }
    } else {
      const rid = `${r.snap.key}|${r.f.resourceId}`;
      const n = nodes.get(rid) ?? { id: rid, col: 2, title: D.shortName(r.f), sub: '', icon: iconFor(r), count: 0, rows: [], lane };
      n.rows.push(r);
      n.rows.sort(D.compareRows);
      n.sev = n.rows[0]!.f.severity;
      n.icon = iconFor(n.rows[0]!);
      n.count = n.rows.length;
      n.sub = n.rows.map((x) => D.service(x.f)).join(', ');
      nodes.set(rid, n);
      edge(entryId, rid, r);
    }
  }
  return { nodes, edges };
}

export function renderGraph(host: HTMLElement, rows: Row[], opts: GraphOptions = {}): { fit: () => void } {
  const compact = !!opts.compact;
  const NW = compact ? 200 : 240;
  const NH = compact ? 44 : 56;
  const GAP = compact ? 8 : 14;
  const COLX = compact ? [10, 270, 530] : [40, 390, 740];
  const { nodes, edges } = build(rows, opts.showTargets ?? true);

  const pos = new Map<string, { x: number; y: number }>();
  const right = [...nodes.values()].filter((n) => n.col === 2);
  const parent = new Map<string, string>();
  for (const e of edges.values()) if (e.from !== 'internet') parent.set(e.to, e.from);
  right.sort((a, b) => a.lane.localeCompare(b.lane) || (parent.get(a.id) ?? '').localeCompare(parent.get(b.id) ?? '') || D.sevRank(a.sev ?? 'info') - D.sevRank(b.sev ?? 'info'));
  let y = compact ? 6 : 64;
  let lane = '';
  const lanes: { name: string; y0: number; y1: number }[] = [];
  for (const n of right) {
    if (!compact && n.lane !== lane) {
      if (lanes.length) lanes[lanes.length - 1]!.y1 = y - 8;
      y += lanes.length ? 28 : 0;
      lanes.push({ name: n.lane, y0: y, y1: 0 });
      y += 30;
      lane = n.lane;
    }
    pos.set(n.id, { x: COLX[2]!, y });
    y += NH + GAP;
  }
  if (lanes.length) lanes[lanes.length - 1]!.y1 = y - 4;
  for (const n of nodes.values()) {
    if (n.col !== 1) continue;
    const kids = [...edges.values()].filter((e) => e.from === n.id).map((e) => pos.get(e.to)?.y).filter((v): v is number => v !== undefined);
    pos.set(n.id, { x: COLX[1]!, y: kids.length ? (Math.min(...kids) + Math.max(...kids)) / 2 : y });
    if (!kids.length) y += NH + GAP;
  }
  const entryYs = [...nodes.values()].filter((n) => n.col === 1).map((n) => pos.get(n.id)!.y);
  pos.set('internet', { x: COLX[0]!, y: entryYs.length ? (Math.min(...entryYs) + Math.max(...entryYs)) / 2 : 40 });
  const H = Math.max(y + 10, compact ? 120 : 300);
  const W = COLX[2]! + NW + (compact ? 10 : 60);

  const svg = s('svg', { role: 'img', 'aria-label': `Attack surface graph with ${D.plural(rows.length, 'exposure')}`, class: 'graph', ...(compact ? { viewBox: `0 0 ${W} ${H}` } : {}) });
  const g = s('g');
  svg.append(g);
  if (!compact) {
    g.append(s('text', { x: COLX[0]!, y: 32, class: 'g-col' }, 'Source'), s('text', { x: COLX[1]!, y: 32, class: 'g-col' }, 'Entry point'), s('text', { x: COLX[2]!, y: 32, class: 'g-col' }, 'Exposed resource'));
    for (const l of lanes) {
      g.append(s('rect', { x: COLX[1]! - 22, y: l.y0 - 8, width: W - COLX[1]!, height: l.y1 - l.y0 + 8, rx: 14, class: 'g-lane' }), s('text', { x: COLX[1]! - 6, y: l.y0 + 13, class: 'g-lane-t' }, l.name));
    }
  }
  const sel = opts.selected;
  const on = new Set<string>();
  if (sel) {
    for (const n of nodes.values()) if (n.rows.includes(sel)) on.add(n.id);
    on.add('internet');
  }
  const focus = opts.focus?.trim().toLowerCase();
  const focused = (n: GNode) => !!focus && (n.title.toLowerCase().includes(focus) || n.id.toLowerCase().includes(focus) || n.sub.toLowerCase().includes(focus));
  const anyFocus = focus ? [...nodes.values()].some(focused) : false;

  for (const e of edges.values()) {
    const a = pos.get(e.from);
    const b = pos.get(e.to);
    if (!a || !b) continue;
    const x1 = a.x + NW;
    const y1 = a.y + NH / 2;
    const x2 = b.x;
    const y2 = b.y + NH / 2;
    const mx = (x1 + x2) / 2;
    const color = e.verdict ? (e.verdict === 'reachable' ? 'var(--low)' : e.verdict === 'blocked' ? 'var(--critical)' : 'var(--medium)') : sevColor(e.sev);
    const lit = sel ? on.has(e.from) && on.has(e.to) : true;
    g.append(
      s('path', {
        d: `M${x1} ${y1} C${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`,
        class: `g-edge${(!sel && e.sev === 'critical' && !e.verdict) || (sel && lit) ? ' hot' : ''}${lit ? '' : ' dim'}`,
        stroke: color,
        'stroke-width': Math.min(1.6 + e.rows.length * 0.5, 5),
        ...(e.verdict === 'blocked' ? { 'stroke-dasharray': '4 5' } : {}),
      }),
    );
  }
  for (const n of nodes.values()) {
    const p = pos.get(n.id)!;
    const dim = (sel && !on.has(n.id)) || (anyFocus && !focused(n) && n.col > 0);
    const node = s('g', { class: `g-node${dim ? ' dim' : ''}${(sel && on.has(n.id) && n.col > 0) || (anyFocus && focused(n)) ? ' sel' : ''}`, transform: `translate(${p.x},${p.y})`, ...(compact ? {} : { tabindex: 0, role: 'button' }), 'aria-label': `${n.title}, ${n.sub}` });
    const ring = n.verdict ? (n.verdict === 'reachable' ? 'var(--low)' : n.verdict === 'blocked' ? 'var(--critical)' : 'var(--medium)') : n.col === 0 ? 'var(--accent)' : sevColor(n.sev);
    const r = NH / 2 - 9;
    const max = compact ? 20 : 25;
    node.append(
      s('rect', { class: 'card', width: NW, height: NH, rx: compact ? 10 : 12 }),
      s('circle', { class: 'ic', cx: NH / 2, cy: NH / 2, r }),
      s('circle', { class: 'ring', cx: NH / 2, cy: NH / 2, r, stroke: ring }),
      s('path', { d: ICON[n.icon] ?? ICON.server!, class: 'ig', transform: `translate(${NH / 2 - 12 * (r / 18)},${NH / 2 - 12 * (r / 18)}) scale(${r / 18})` }),
      s('text', { x: NH + 2, y: NH / 2 - (compact ? 2 : 3), class: 't1' }, n.title.length > max ? `${n.title.slice(0, max - 1)}…` : n.title),
      s('text', { x: NH + 2, y: NH / 2 + (compact ? 11 : 13), class: 't2' }, n.sub.length > max + 6 ? `${n.sub.slice(0, max + 5)}…` : n.sub),
    );
    if (n.col > 0 && n.count > 0 && n.sev && !compact) {
      node.append(s('rect', { x: NW - 34, y: 8, width: 24, height: 18, rx: 9, fill: sevColor(n.sev) }), s('text', { x: NW - 22, y: 21, 'text-anchor': 'middle', class: 'g-badge' }, String(n.count)));
    }
    if (opts.onSelect && n.col > 0) {
      const act = () => {
        const first = n.rows.slice().sort(D.compareRows)[0];
        if (first) opts.onSelect!(first);
      };
      node.addEventListener('click', act);
      node.addEventListener('keydown', (e) => ((e as KeyboardEvent).key === 'Enter' || (e as KeyboardEvent).key === ' ') && (e.preventDefault(), act()));
    }
    g.append(node);
  }

  if (compact) {
    host.replaceChildren(svg);
    return { fit: () => {} };
  }

  // Keep the selected path in view: centre on it when the fitted graph would leave it off screen.
  const sp = [...on].filter((id) => id !== 'internet').map((id) => pos.get(id)).filter((p): p is { x: number; y: number } => !!p);
  const box = sp.length ? { y0: Math.min(...sp.map((p) => p.y)), y1: Math.max(...sp.map((p) => p.y)) + NH } : undefined;
  return attachPanZoom(host, svg, g, W, H, 40, box);
}

/** Pan (drag), zoom (wheel and buttons) and fit-to-screen for a graph SVG. */
export function attachPanZoom(host: HTMLElement, svg: SVGElement, g: SVGElement, W: number, H: number, top = 40, keep?: { y0: number; y1: number }): { fit: () => void } {
  const view = { x: 0, y: 0, k: 1 };
  const apply = () => g.setAttribute('transform', `translate(${view.x},${view.y}) scale(${view.k})`);
  const fit = () => {
    const rect = host.getBoundingClientRect();
    view.k = Math.max(0.7, Math.min(1.8, (rect.width - 40) / W, (rect.height - 80) / H)) || 1;
    view.x = Math.max(8, (rect.width - W * view.k) / 2);
    // Centre vertically when the graph is shorter than the canvas.
    view.y = Math.max(top, (rect.height - H * view.k) / 2);
    if (keep && rect.height > 0) {
      const y0 = view.y + keep.y0 * view.k;
      const y1 = view.y + keep.y1 * view.k;
      if (y0 < top || y1 > rect.height - 16) view.y += (top + rect.height) / 2 - (y0 + y1) / 2;
    }
    apply();
  };
  fit();
  // Listeners on window must not pile up across re-renders of the same host.
  const holder = host as HTMLElement & { _ac?: AbortController };
  holder._ac?.abort();
  const ac = new AbortController();
  holder._ac = ac;
  let drag: { x: number; y: number } | undefined;
  svg.addEventListener('pointerdown', (e) => {
    if ((e.target as Element).closest('.g-node')) return;
    drag = { x: e.clientX - view.x, y: e.clientY - view.y };
    host.classList.add('panning');
  });
  window.addEventListener('pointermove', (e) => {
    if (!drag) return;
    view.x = e.clientX - drag.x;
    view.y = e.clientY - drag.y;
    apply();
  }, { signal: ac.signal });
  window.addEventListener('pointerup', () => {
    drag = undefined;
    host.classList.remove('panning');
  }, { signal: ac.signal });
  svg.addEventListener('wheel', (e) => {
    e.preventDefault();
    const rect = host.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const k = Math.min(2.5, Math.max(0.3, view.k * (e.deltaY < 0 ? 1.1 : 0.9)));
    view.x = mx - ((mx - view.x) * k) / view.k;
    view.y = my - ((my - view.y) * k) / view.k;
    view.k = k;
    apply();
  }, { passive: false });
  const zoom = (f: number) => {
    view.k = Math.min(2.5, Math.max(0.3, view.k * f));
    apply();
  };
  const z = h('div', { class: 'zoom' });
  for (const [label, act, aria] of [['+', () => zoom(1.2), 'Zoom in'], ['−', () => zoom(1 / 1.2), 'Zoom out'], ['⤢', fit, 'Fit to screen']] as const) {
    const b = h('button', { type: 'button', 'aria-label': aria }, label);
    b.addEventListener('click', act);
    z.append(b);
  }
  host.replaceChildren(svg, z);
  return { fit };
}
