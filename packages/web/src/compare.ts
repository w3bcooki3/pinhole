/**
 * Compare page: what changed between two snapshots of one account and
 * region. New exposure first, because that is what someone opening this page
 * wants to know; then what closed; then the configuration changes behind it.
 */
import { diffSnapshots } from '@pinhole/engine';
import type { ConfigChange, ExposureDelta, Severity, SnapshotDiff } from '@pinhole/engine';
import { h, on } from './dom.js';
import type { Child } from './dom.js';
import * as D from './data.js';
import type { Snap } from './data.js';
import { boxHead, empty, sevPill, short } from './ui.js';

export interface CompareState {
  all: Snap[];
  cmpOld: string;
  cmpNew: string;
}
export interface CompareCtx {
  st: CompareState;
  go: (route: string, patch?: Record<string, unknown>) => void;
}

const cache = new WeakMap<Snap, WeakMap<Snap, SnapshotDiff>>();
function diffOf(a: Snap, b: Snap): SnapshotDiff {
  let m = cache.get(a);
  if (!m) cache.set(a, (m = new WeakMap()));
  let d = m.get(b);
  if (!d) m.set(b, (d = diffSnapshots(a.model, b.model)));
  return d;
}

const when = (s: Snap) => (s.collectedAt ? D.collected(s).text.replace(/^Collected /, '') : s.name);
const ports = (d: ExposureDelta) => `${d.protocol}${d.ports ? `/${d.ports.from === d.ports.to ? d.ports.from : `${d.ports.from}-${d.ports.to}`}` : ''}`;
const sources = (xs: string[]) => xs.map((x) => x.replace(/ \(every internet address\)$/, '')).join(', ') || 'nobody';
const STATUS: Record<ExposureDelta['status'], string> = { opened: 'New', widened: 'Wider', changed: 'Changed', narrowed: 'Narrower', closed: 'Closed' };
const chainText = (steps: { name: string }[]) => steps.map((x) => short(x.name)).join(' → ');

function table(head: string[], rows: Child[][], cls = ''): HTMLElement {
  return h('div', { class: 'tscroll' }, h('table', { class: `t ${cls}` }, h('thead', {}, h('tr', {}, ...head.map((x, i) => h('th', { class: i === 0 ? 'first' : i === head.length - 1 ? 'last' : '' }, x)))), h('tbody', {}, ...rows.map((r) => h('tr', {}, ...r.map((c, i) => h('td', { class: i === 0 ? 'first' : i === r.length - 1 ? 'last' : '' }, c)))))));
}

export function comparePage(ctx: CompareCtx): HTMLElement {
  const { st } = ctx;
  const groups = new Map<string, Snap[]>();
  for (const s of st.all) {
    const k = `${s.account}/${s.region}`;
    groups.set(k, [...(groups.get(k) ?? []), s]);
  }
  for (const list of groups.values()) list.sort((a, b) => (a.collectedAt ?? '').localeCompare(b.collectedAt ?? ''));
  const pairs = [...groups.values()].filter((l) => l.length > 1);
  const header = h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Compare snapshots'), h('p', {}, 'What changed between two snapshots of the same account and region: new internet exposure and attack chains, what closed, and the rule changes behind it.')));
  if (!pairs.length) {
    return h(
      'div',
      { class: 'page' },
      header,
      h('section', { class: 'box' }, empty('Load two snapshots of one account and region', 'Collect the same region again later, for example weekly, and load both files. The newest one is used on every other page; the older ones are kept here for comparison.')),
    );
  }

  const byKey = (k: string) => st.all.find((x) => x.key === k);
  let older = byKey(st.cmpOld);
  let newer = byKey(st.cmpNew);
  if (!older || !newer || older === newer || older.account !== newer.account || older.region !== newer.region) {
    const g = pairs[0]!;
    newer = g.at(-1)!;
    older = g.at(-2)!;
  }
  const same = groups.get(`${newer.account}/${newer.region}`)!;
  const pick = (label: string, value: Snap, set: (k: string) => void) => {
    const sel = h('select', { class: 'snap-select', 'aria-label': label }, ...same.map((x) => h('option', { value: x.key }, `${when(x)}${x === same.at(-1) ? ' (latest)' : ''}`))) as HTMLSelectElement;
    sel.value = value.key;
    sel.addEventListener('change', () => set(sel.value));
    return h('label', { class: 'cmp-pick' }, h('span', {}, label), sel);
  };
  const scopeSel = pairs.length > 1
    ? (() => {
        const sel = h('select', { class: 'snap-select', 'aria-label': 'Account and region' }, ...pairs.map((g) => h('option', { value: `${g[0]!.account}/${g[0]!.region}` }, `${g[0]!.account} / ${g[0]!.region}`))) as HTMLSelectElement;
        sel.value = `${newer.account}/${newer.region}`;
        sel.addEventListener('change', () => {
          const g = groups.get(sel.value)!;
          ctx.go('compare', { cmpOld: g.at(-2)!.key, cmpNew: g.at(-1)!.key });
        });
        return h('label', { class: 'cmp-pick' }, h('span', {}, 'Account and region'), sel);
      })()
    : h('div', { class: 'cmp-pick' }, h('span', {}, 'Account and region'), h('strong', {}, `${newer.account} / ${newer.region}`));
  const [a, b] = (older.collectedAt ?? '') <= (newer.collectedAt ?? '') ? [older, newer] : [newer, older];
  const o = a;
  const n = b;
  const controls = h(
    'section',
    { class: 'box cmp-controls' },
    h('div', { class: 'pad cmp-row' }, scopeSel, pick('From', o, (k) => ctx.go('compare', { cmpOld: k, cmpNew: n.key })), h('span', { class: 'cmp-arrow', 'aria-hidden': 'true' }, '→'), pick('To', n, (k) => ctx.go('compare', { cmpOld: o.key, cmpNew: k }))),
  );
  if (o === n) return h('div', { class: 'page' }, header, controls, h('section', { class: 'box' }, empty('Pick two different snapshots', 'Choose an earlier snapshot in From and a later one in To.')));

  let d: SnapshotDiff;
  try {
    d = diffOf(o, n);
  } catch (e) {
    return h('div', { class: 'page' }, header, controls, h('section', { class: 'box' }, empty('These snapshots cannot be compared', (e as Error).message)));
  }
  const e = d.exposure;
  const worse = e.deltas.filter((x) => x.status === 'opened' || x.status === 'widened' || x.status === 'changed');
  const better = e.deltas.filter((x) => x.status === 'closed' || x.status === 'narrowed');
  const quiet = !e.deltas.length && !e.chainsOpened.length && !e.chainsClosed.length && !d.config.length;
  const verdict = quiet
    ? 'Nothing changed: the same exposure, attack chains and rules.'
    : [
        worse.length ? `${D.plural(worse.length, 'new or wider internet exposure')}` : 'No new internet exposure',
        e.chainsOpened.length ? `${D.plural(e.chainsOpened.length, 'new attack chain')}` : 'no new attack chains',
        `${better.length} closed or narrower`,
        D.plural(d.config.length, 'configuration change'),
      ].join(', ') + '.';
  const worst: Severity | undefined = [...worse.map((x) => x.severity), ...e.chainsOpened.map((c) => c.severity)].sort((x, y) => D.SEVERITY_ORDER.indexOf(x) - D.SEVERITY_ORDER.indexOf(y))[0];

  const deltaRows = (list: ExposureDelta[]) =>
    list.map((x) => [sevPill(x.severity), h('span', { class: `cmp-st ${x.status}` }, STATUS[x.status]), short(x.resourceName), h('span', { class: 'mono' }, ports(x), x.family === 'ipv6' ? ' IPv6' : ''), h('span', { class: 'mono' }, x.status === 'closed' ? '—' : sources(x.after)), h('span', { class: 'mono faint' }, x.status === 'opened' ? '—' : sources(x.before))] as Child[]);
  const configRow = (c: ConfigChange): Child[] => [h('span', { class: `cmp-st ${c.change === 'added' ? 'opened' : c.change === 'removed' ? 'closed' : 'changed'}` }, c.change[0]!.toUpperCase() + c.change.slice(1)), c.kind, h('span', { class: 'mono' }, c.id), c.where, h('span', { class: 'mono faint' }, c.before ?? '—'), h('span', { class: 'mono' }, c.after ?? '—')];

  return h(
    'div',
    { class: 'page', id: 'compare' },
    header,
    controls,
    h(
      'section',
      { class: `box cmp-verdict${worst && (worst === 'critical' || worst === 'high') ? ' bad' : quiet || !worse.length ? ' ok' : ''}`, id: 'cmp-verdict' },
      h('div', { class: 'pad' }, h('p', { class: 'lede', style: 'margin:0' }, verdict), h('p', { class: 'meta', style: 'margin:0.25rem 0 0' }, `From ${o.name} (${when(o)}) to ${n.name} (${when(n)}).`)),
    ),
    worse.length || better.length
      ? h('section', { class: 'box', style: 'margin-bottom:1rem', id: 'cmp-exposure' }, boxHead('Internet exposure', 'What the internet can open a connection to, before and after'), table(['Severity', 'Change', 'Resource', 'Service', 'Open to now', 'Open to before'], deltaRows([...worse, ...better])))
      : null,
    e.chainsOpened.length || e.chainsClosed.length || e.chainsRevealed.length
      ? h(
          'section',
          { class: 'box', style: 'margin-bottom:1rem', id: 'cmp-chains' },
          boxHead('Attack chains', 'What an attacker reaches after compromising an internet-facing server'),
          table(
            ['Severity', 'Change', 'Chain'],
            [
              ...e.chainsOpened.map((c) => [sevPill(c.severity), h('span', { class: 'cmp-st opened' }, 'New'), on(h('button', { type: 'button', class: 'link' }, chainText(c.steps)), 'click', () => ctx.go('blast', { blastKey: n.key, chain: `${n.key}#${c.id}` }))] as Child[]),
              ...e.chainsClosed.map((c) => [sevPill(c.severity), h('span', { class: 'cmp-st closed' }, 'Closed'), chainText(c.steps)] as Child[]),
              ...e.chainsRevealed.map((c) => [sevPill(c.severity), h('span', { class: 'cmp-st changed' }, 'Inside'), `${chainText(c.steps)}: hidden before because the internet reached the target directly`] as Child[]),
            ],
          ),
        )
      : null,
    d.config.length
      ? h('section', { class: 'box', style: 'margin-bottom:1rem', id: 'cmp-config' }, boxHead('Configuration changes', 'The rule, route and address changes behind it'), table(['Change', 'What', 'ID', 'Where', 'Before', 'After'], d.config.map(configRow)))
      : null,
  );
}
