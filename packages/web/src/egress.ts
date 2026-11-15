/** Outbound page: what each server can send to the internet, through which gateway, as which address. */
import { analyzeEgress, compareSeverity } from '@pinhole/engine';
import type { EgressFinding, EgressReport } from '@pinhole/engine';
import { h, on } from './dom.js';
import * as D from './data.js';
import type { Snap } from './data.js';
import { traceStepper } from './pages.js';
import { boxHead, empty, sevPill, short, stacked } from './ui.js';

const cache = new WeakMap<Snap, EgressReport>();
export function egressOf(snap: Snap): EgressReport {
  let r = cache.get(snap);
  if (!r) cache.set(snap, (r = analyzeEgress(snap.model)));
  return r;
}

const traffic = (f: EgressFinding) => (f.protocol === 'icmp' ? 'ICMP echo' : f.ports.from === 0 && f.ports.to === 65535 ? `${f.protocol.toUpperCase()} any port` : f.ports.from === f.ports.to ? `${f.protocol.toUpperCase()} ${f.ports.from}` : `${f.protocol.toUpperCase()} ${f.ports.from}-${f.ports.to}`);
const dest = (f: EgressFinding) => (f.destinations[0]?.startsWith('0.0.0.0/0 ') ? 'Any internet address' : f.destinations.slice(0, 2).join(', ') + (f.destinations.length > 2 ? ` +${f.destinations.length - 2}` : ''));

export function egressPage(ctx: { st: { snaps: Snap[] } }): HTMLElement {
  const snaps = D.latestPerScope(ctx.st.snaps);
  const all = snaps.map((snap) => ({ snap, r: egressOf(snap) }));
  // One row per server and way out: TCP, UDP and ICMP findings for it are listed together.
  const grouped = new Map<string, { snap: Snap; f: EgressFinding; all: EgressFinding[] }>();
  for (const { snap, r } of all) {
    for (const f of r.findings) {
      const k = `${snap.key}|${f.resourceId}|${f.via.gateway}|${f.via.publicIp ?? ''}|${dest(f)}`;
      const cur = grouped.get(k);
      if (!cur) grouped.set(k, { snap, f, all: [f] });
      else {
        cur.all.push(f);
        if (compareSeverity(f.severity, cur.f.severity) < 0) cur.f = f;
      }
    }
  }
  const rows = [...grouped.values()].sort((a, b) => compareSeverity(a.f.severity, b.f.severity) || a.f.resourceName.localeCompare(b.f.resourceName));
  const interfaces = all.reduce((n, x) => n + x.r.interfaces, 0);
  const open = all.reduce((n, x) => n + x.r.open, 0);
  const wide = all.reduce((n, x) => n + x.r.wide, 0);
  const exfil = new Set(rows.filter((x) => x.f.severity === 'high').map((x) => `${x.snap.key}|${x.f.resourceId}`)).size;

  const detail = h('div', { class: 'eg-detail' });
  const table = h(
    'table',
    { class: 't eg-t' },
    h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Server'), h('th', {}, 'Traffic'), h('th', { class: 'hide-sm' }, 'To'), h('th', {}, 'Leaves through'), h('th', { class: 'last hide-sm' }, 'Account and region'))),
    h(
      'tbody',
      {},
      ...rows.map(({ snap, f, all: list }) => {
        const tr = h(
          'tr',
          { class: 'click', tabindex: '0' },
          h('td', { class: 'first' }, sevPill(f.severity)),
          h('td', {}, h('strong', {}, short(f.resourceName)), f.dataStore ? h('span', { class: 'tag jewel-tag' }, 'data') : null),
          h('td', { class: 'mono' }, list.map(traffic).join(', ')),
          h('td', { class: 'hide-sm' }, dest(f)),
          h('td', {}, h('span', { class: 'mono' }, f.via.gateway), f.via.publicIp ? h('span', { class: 'faint' }, ` as ${f.via.publicIp}`) : null, f.inspectedBy?.length ? h('div', { class: 'faint' }, `inspected by ${f.inspectedBy.join(', ')}`) : null),
          h('td', { class: 'last hide-sm dim' }, `${snap.account} / ${snap.region}`),
        );
        const show = () => {
          table.querySelectorAll('tr.sel').forEach((x) => x.classList.remove('sel'));
          tr.classList.add('sel');
          detail.replaceChildren(
            h(
              'section',
              { class: 'box' },
              boxHead(`${short(f.resourceName)}: ${list.map(traffic).join(', ')} out`, f.reasons.join('; ')),
              h(
                'div',
                { class: 'pad' },
                h('dl', { class: 'kv' }, h('dt', {}, 'To'), h('dd', { class: 'mono' }, f.destinations.slice(0, 8).join(', ')), h('dt', {}, 'Leaves through'), h('dd', {}, `${f.via.gateway}${f.via.publicIp ? `, as ${f.via.publicIp}` : ''}`), h('dt', {}, 'Replies'), h('dd', {}, f.returnPath === 'all' ? 'Allowed on all of its ephemeral ports' : 'Only on some of its ephemeral ports')),
                ...(f.caveats ?? []).map((c) => h('p', { class: 'hop-caveat' }, c)),
                traceStepper({ hops: f.trace }, 'Internet'),
              ),
            ),
          );
        };
        on(tr, 'click', show);
        on(tr, 'keydown', (e) => {
          if ((e as KeyboardEvent).key === 'Enter') show();
        });
        return tr;
      }),
    ),
  );
  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Outbound'), h('p', {}, 'What each server can send to the internet, to which addresses and ports, through which gateway and as which public address.'))),
    h('p', { class: 'eg-sum' }, h('strong', {}, `${open} of ${D.plural(interfaces, 'interface')} can reach the internet`), `. ${wide} of them can send on any port to any address${exfil ? `, including ${D.plural(exfil, 'server that holds', 'servers that hold')} data` : ''}.`),
    rows.length ? h('section', { class: 'box', style: 'margin-bottom:1rem' }, boxHead('Outbound traffic', 'Select a row for the path'), h('div', { class: 'table-wrap' }, stacked(table))) : empty('Nothing can reach the internet', 'No interface in the loaded snapshots can open a connection to an internet address.'),
    detail,
  );
}
