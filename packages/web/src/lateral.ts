/**
 * Lateral movement graph for one snapshot: the internet, the entry points it
 * reaches, and every resource an attacker can reach from them, in columns by
 * the fewest hops it takes. Edges that give a foothold (remote administration,
 * control planes, wide ranges) are solid; edges that only reach a service are
 * thin. A selected attack chain is traced with a moving packet.
 */
import { s } from './dom.js';
import type { AttackChain, BlastReport, Severity } from './data.js';
import * as D from './data.js';
import { attachPanZoom, ICON } from './graph.js';
import { serviceLabel } from '@pinhole/engine';
import type { NetworkModel, ServiceReach } from '@pinhole/engine';

interface LNode {
  id: string;
  col: number;
  title: string;
  sub: string;
  icon: string;
  sev?: Severity;
  x: number;
  y: number;
}
interface LEdge {
  from: string;
  to: string;
  pivot: boolean;
  sev: Severity;
  label: string;
}

const NW = 196;
const NH = 50;
const GAPX = 80;
const GAPY = 16;
const colX = (c: number) => 20 + c * (NW + GAPX);
const worst = (list: Severity[]): Severity => list.reduce<Severity>((a, b) => (D.sevRank(b) < D.sevRank(a) ? b : a), 'info');
const reduced = () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

function role(svcs: ServiceReach[]): string {
  if (svcs.some((x) => x.category === 'data')) return 'db';
  if (svcs.some((x) => x.category === 'control')) return 'cluster';
  if (svcs.some((x) => x.category === 'admin')) return 'key';
  return 'server';
}

export interface LateralOptions {
  selected?: AttackChain | undefined;
  onSelectNode?: (eniId: string) => void;
  compact?: boolean;
}

export function renderLateral(host: HTMLElement, model: NetworkModel, blast: BlastReport, opts: LateralOptions = {}) {
  // Only what makes up the attack chains: every route of every chain.
  const routes = blast.chains.flatMap((c) => [c.steps, ...c.altRoutes]);
  const depth = new Map<string, number>();
  for (const r of routes) r.forEach((st, i) => depth.set(st.eniId, Math.min(depth.get(st.eniId) ?? i, i)));
  const edgeOf = new Map(blast.edges.map((e) => [`${e.from}>${e.to}`, e]));
  const impactAt = new Map<string, ServiceReach[]>();
  for (const r of routes) {
    for (let i = 1; i < r.length; i++) {
      const e = edgeOf.get(`${r[i - 1]!.eniId}>${r[i]!.eniId}`);
      const svc = e?.services.find((x) => serviceLabel(x) === r[i]!.service);
      if (svc) impactAt.set(r[i]!.eniId, [...(impactAt.get(r[i]!.eniId) ?? []), svc]);
    }
  }
  const nameOf = (id: string) => {
    const eni = model.enis.get(id);
    const inst = eni?.instanceId ? model.instances.get(eni.instanceId) : undefined;
    return inst?.name ?? id;
  };

  const nodes = new Map<string, LNode>();
  const usedEntries = blast.entries.filter((e) => depth.get(e.eniId) === 0);
  nodes.set('internet', { id: 'internet', col: 0, title: 'Internet', sub: D.plural(usedEntries.length, 'entry point'), icon: 'globe', x: 0, y: 0 });
  for (const [id, d] of depth) {
    const entry = d === 0 ? blast.entries.find((e) => e.eniId === id) : undefined;
    const svcs = impactAt.get(id) ?? [];
    nodes.set(id, {
      id,
      col: d + 1,
      title: nameOf(id),
      sub: entry ? `internet: ${entry.how.split(' from ')[0]!.split(' on ')[0]}` : `reached on ${[...new Set(svcs.map((x) => serviceLabel(x)))].join(', ')}`,
      icon: entry ? 'server' : role(svcs),
      sev: entry ? entry.severity : svcs.length ? worst(svcs.map((x) => x.severity)) : undefined,
      x: 0,
      y: 0,
    } as LNode);
  }

  const edges: LEdge[] = [];
  const seen = new Set<string>();
  for (const e of usedEntries) edges.push({ from: 'internet', to: e.eniId, pivot: true, sev: e.severity, label: e.how });
  for (const r of routes) {
    for (let i = 1; i < r.length; i++) {
      const k = `${r[i - 1]!.eniId}>${r[i]!.eniId}`;
      if (seen.has(k)) continue;
      seen.add(k);
      const e = edgeOf.get(k);
      const live = (e?.services ?? []).filter((x) => x.verdict === 'reachable');
      edges.push({ from: r[i - 1]!.eniId, to: r[i]!.eniId, pivot: !!e?.pivot, sev: worst(live.map((x) => x.severity)), label: live.map((x) => `${serviceLabel(x)}${x.name ? ` ${x.name}` : ''}`).join(', ') });
    }
  }

  // Layout: columns by depth, rows ordered by severity then name.
  const cols = new Map<number, LNode[]>();
  for (const n of nodes.values()) cols.set(n.col, [...(cols.get(n.col) ?? []), n]);
  let H = 0;
  for (const [, list] of cols) {
    list.sort((a, b) => D.sevRank(a.sev ?? 'info') - D.sevRank(b.sev ?? 'info') || a.title.localeCompare(b.title));
    H = Math.max(H, list.length * (NH + GAPY));
  }
  H = Math.max(H, 260);
  for (const [c, list] of cols) {
    const total = list.length * (NH + GAPY) - GAPY;
    list.forEach((n, i) => {
      n.x = colX(c);
      n.y = 40 + (H - total) / 2 + i * (NH + GAPY);
    });
  }
  const maxCol = Math.max(...cols.keys());
  const W = colX(maxCol) + NW + 40;
  const svgH = H + 70;

  const svg = s('svg', { class: `graph lateral${opts.compact ? ' compact' : ''}`, role: 'img', 'aria-label': 'Lateral movement graph', ...(opts.compact ? { viewBox: `0 0 ${W} ${svgH}` } : {}) });
  const g = s('g');
  svg.append(g);
  const heads = ['Internet', 'Open to the internet', ...Array.from({ length: maxCol - 1 }, (_, i) => `${i + 1} hop${i ? 's' : ''} further`)];
  heads.forEach((t, i) => g.append(s('text', { x: colX(i) + 4, y: 22, class: 'g-col' }, t)));

  // Highlighted chain: Internet -> entry -> ... -> target.
  const chainIds = opts.selected ? ['internet', ...opts.selected.steps.map((x) => x.eniId)] : [];
  const onChain = (a: string, b: string) => chainIds.some((id, i) => id === a && chainIds[i + 1] === b);
  const chainNodes = new Set(chainIds);

  const pathFor = (a: LNode, b: LNode) => {
    if (b.col > a.col) {
      const x1 = a.x + NW;
      const y1 = a.y + NH / 2;
      const x2 = b.x;
      const y2 = b.y + NH / 2;
      const mx = (x1 + x2) / 2;
      return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
    }
    // Same column or backwards: arc out into the gap on the right of the column.
    const x1 = a.x + NW;
    const y1 = a.y + NH / 2 + (b.y > a.y ? 6 : -6);
    const x2 = b.x + NW;
    const y2 = b.y + NH / 2 + (b.y > a.y ? -6 : 6);
    const bulge = Math.min(GAPX - 14, 26 + Math.abs(y2 - y1) * 0.18);
    return `M${x1},${y1} C${x1 + bulge},${y1} ${x2 + bulge},${y2} ${x2},${y2}`;
  };

  const eg = s('g');
  g.append(eg);
  const animated: SVGPathElement[] = [];
  for (const e of edges) {
    const a = nodes.get(e.from)!;
    const b = nodes.get(e.to)!;
    const hot = onChain(e.from, e.to);
    const d = pathFor(a, b);
    const path = s('path', {
      d,
      class: `g-edge${e.pivot ? ' pivot' : ' access'}${hot ? ' chain' : ''}${opts.selected && !hot ? ' dim' : ''}`,
      stroke: `var(--${e.sev})`,
      'stroke-width': hot ? 3 : e.pivot ? 1.8 : 1.1,
      'marker-end': 'url(#arrow)',
    }) as SVGPathElement;
    path.append(s('title', {}, `${a.title} → ${b.title}: ${e.label}`));
    eg.append(path);
    if (hot) animated.push(path);
  }
  const defs = s('defs');
  defs.append(s('marker', { id: 'arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' }, s('path', { d: 'M0,0 L10,5 L0,10 z', fill: 'var(--ink3)' })));
  svg.prepend(defs);

  // A packet travelling the chain, hop by hop.
  if (animated.length && !reduced() && !opts.compact) {
    const total = animated.length;
    animated.forEach((p, i) => {
      const dot = s('circle', { r: 4.5, class: 'packet' });
      const dur = 0.9;
      dot.append(s('animateMotion', { dur: `${total * dur}s`, repeatCount: 'indefinite', keyPoints: '0;0;1;1', keyTimes: `0;${(i / total).toFixed(3)};${((i + 1) / total).toFixed(3)};1`, calcMode: 'linear', path: p.getAttribute('d')! }));
      dot.append(s('animate', { attributeName: 'opacity', dur: `${total * dur}s`, repeatCount: 'indefinite', values: '0;0;1;1;0;0', keyTimes: `0;${(i / total).toFixed(3)};${(i / total + 0.001).toFixed(3)};${((i + 1) / total - 0.001).toFixed(3)};${((i + 1) / total).toFixed(3)};1` }));
      eg.append(dot);
    });
  }

  for (const n of nodes.values()) {
    const sel = chainNodes.has(n.id);
    const node = s('g', { class: `g-node${sel ? ' sel' : ''}${opts.selected && !sel ? ' dim' : ''}`, transform: `translate(${n.x},${n.y})`, tabindex: opts.compact ? -1 : 0, role: 'button', 'aria-label': `${n.title}, ${n.sub}` });
    node.append(s('rect', { class: 'card', width: NW, height: NH, rx: 6 }));
    node.append(s('circle', { class: 'ic', cx: 24, cy: NH / 2, r: 14 }));
    if (n.sev) node.append(s('circle', { class: 'ring', cx: 24, cy: NH / 2, r: 14, stroke: `var(--${n.sev})` }));
    node.append(s('path', { class: 'ig', d: ICON[n.icon] ?? ICON.server!, transform: `translate(${24 - 8},${NH / 2 - 8}) scale(0.667)` }));
    node.append(s('text', { x: 46, y: 21, class: 't1' }, n.title.length > 22 ? `${n.title.slice(0, 21)}…` : n.title));
    node.append(s('text', { x: 46, y: 37, class: 't2' }, n.sub.length > 28 ? `${n.sub.slice(0, 27)}…` : n.sub));
    if (n.id !== 'internet' && opts.onSelectNode) {
      node.addEventListener('click', () => opts.onSelectNode!(n.id));
      node.addEventListener('keydown', (e) => (e as KeyboardEvent).key === 'Enter' && opts.onSelectNode!(n.id));
    }
    g.append(node);
  }

  if (opts.compact) {
    host.replaceChildren(svg);
    return { fit: () => {} };
  }
  return attachPanZoom(host, svg, g, W, svgH, 52);
}
