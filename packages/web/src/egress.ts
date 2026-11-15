/** Outbound page: what each server can send to the internet, through which gateway, as which address. */
import { analyzeEgress } from '@pinhole/engine';
import type { EgressFinding, EgressReport } from '@pinhole/engine';
import { h, on } from './dom.js';
import * as D from './data.js';
import type { Snap } from './data.js';
import { traceStepper } from './pages.js';
import { boxHead, empty, sevPill, short } from './ui.js';

const cache = new WeakMap<Snap, EgressReport>();
export function egressOf(snap: Snap): EgressReport {
  let r = cache.get(snap);
  if (!r) cache.set(snap, (r = analyzeEgress(snap.model)));
  return r;
}

const traffic = (f: EgressFinding) => (f.protocol === 'icmp' ? 'ICMP echo' : f.ports.from === 0 && f.ports.to === 65535 ? `${f.protocol.toUpperCase()}, any port` : f.ports.from === f.ports.to ? `${f.protocol.toUpperCase()} ${f.ports.from}` : `${f.protocol.toUpperCase()} ${f.ports.from}-${f.ports.to}`);
const dest = (f: EgressFinding) => (f.destinations[0]?.startsWith('0.0.0.0/0 ') ? 'Any internet address' : f.destinations.slice(0, 2).join(', ') + (f.destinations.length > 2 ? ` +${f.destinations.length - 2}` : ''));

export function egressPage(ctx: { st: { snaps: Snap[] } }): HTMLElement {
  const snaps = D.latestPerScope(ctx.st.snaps);
  const all = snaps.map((snap) => ({ snap, r: egressOf(snap) }));
  const rows = all.flatMap(({ snap, r }) => r.findings.map((f) => ({ snap, f })));
  const interfaces = all.reduce((n, x) => n + x.r.interfaces, 0);
  const open = all.reduce((n, x) => n + x.r.open, 0);
  const wide = all.reduce((n, x) => n + x.r.wide, 0);
  const exfil = new Set(rows.filter((x) => x.f.severity === 'high').map((x) => `${x.snap.key}|${x.f.resourceId}`)).size;

  const stat = (n: number, label: string, note: string) => h('div', { class: 'eg-stat' }, h('div', { class: 'eg-n' }, String(n)), h('div', { class: 'eg-l' }, label), h('div', { class: 'faint' }, note));
  const detail = h('div', { class: 'eg-detail' });
  const table = h(
    'table',
    { class: 't eg-t' },
    h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Server'), h('th', {}, 'Traffic'), h('th', { class: 'hide-sm' }, 'To'), h('th', {}, 'Leaves through'), h('th', { class: 'last hide-sm' }, 'Account and region'))),
    h(
      'tbody',
      {},
      ...rows.map(({ snap, f }) => {
        const tr = h(
          'tr',
          { class: 'click', tabindex: '0' },
          h('td', { class: 'first' }, sevPill(f.severity)),
          h('td', {}, h('strong', {}, short(f.resourceName)), f.dataStore ? h('span', { class: 'tag jewel-tag' }, 'data') : null),
          h('td', { class: 'mono' }, traffic(f)),
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
              boxHead(`${short(f.resourceName)}: ${traffic(f)} out`, f.reasons.join('; ')),
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
    h('div', { class: 'eg-stats' }, stat(open, 'can reach the internet', `of ${D.plural(interfaces, 'interface')}`), stat(wide, 'on any port to any address', 'no egress filtering'), stat(exfil, 'data stores with open egress', 'exfiltration paths')),
    rows.length ? h('section', { class: 'box', style: 'margin-bottom:1rem' }, boxHead('Outbound traffic', 'Select a row for the path'), h('div', { class: 'table-wrap' }, table)) : empty('Nothing can reach the internet', 'No interface in the loaded snapshots can open a connection to an internet address.'),
    detail,
  );
}
