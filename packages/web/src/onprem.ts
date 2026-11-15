/** On-premises page: the VPN and Direct Connect links, the networks behind them, and what they reach. */
import { analyzeOnPrem, analyzeOnPremBlast } from '@pinhole/engine';
import type { BlastReport, OnPremFinding, OnPremReport } from '@pinhole/engine';
import { h, on } from './dom.js';
import * as D from './data.js';
import type { Snap } from './data.js';
import { traceStepper } from './pages.js';
import { boxHead, empty, sevPill, short } from './ui.js';

const cache = new WeakMap<Snap, OnPremReport>();
export function onPremOf(snap: Snap): OnPremReport {
  let r = cache.get(snap);
  if (!r) cache.set(snap, (r = analyzeOnPrem(snap.model)));
  return r;
}

const chainCache = new WeakMap<Snap, BlastReport>();
export function onPremChainsOf(snap: Snap): BlastReport {
  let r = chainCache.get(snap);
  if (!r) chainCache.set(snap, (r = analyzeOnPremBlast(snap.model, onPremOf(snap))));
  return r;
}

const service = (f: OnPremFinding) => (f.protocol === 'icmp' ? 'ICMP echo' : f.ports.from === 0 && f.ports.to === 65535 ? `${f.protocol.toUpperCase()}, any port` : f.ports.from === f.ports.to ? `${f.protocol.toUpperCase()} ${f.ports.from}` : `${f.protocol.toUpperCase()} ${f.ports.from}-${f.ports.to}`);
const KIND = { vpn: 'Site-to-Site VPN', 'direct-connect': 'Direct Connect', 'vpn-or-direct-connect': 'VPN or Direct Connect' } as const;

function chainsBox(snaps: Snap[]): HTMLElement {
  const chains = snaps.flatMap((s) => onPremChainsOf(s).chains);
  const box = h('section', { class: 'box op-chains', style: 'margin-top:1rem' }, boxHead('If a host on-premises is taken over', chains.length ? `${D.plural(chains.length, 'attack chain')} into AWS` : 'no attack chains'));
  box.append(
    chains.length
      ? h(
          'ol',
          { class: 'pad op-chain-list' },
          ...chains.map((c) =>
            h(
              'li',
              {},
              sevPill(c.severity),
              ' ',
              h('strong', {}, ['On-premises', ...c.steps.map((s) => short(s.name))].join(' → ')),
              h('div', { class: 'faint' }, c.why.join(' ')),
            ),
          ),
        )
      : h('p', { class: 'pad faint' }, 'No server that on-premises clients can take over reaches anything more from there.'),
  );
  return box;
}

export function onPremPage(ctx: { st: { snaps: Snap[] } }): HTMLElement {
  const snaps = D.latestPerScope(ctx.st.snaps);
  const all = snaps.map((snap) => ({ snap, r: onPremOf(snap) }));
  const links = all.flatMap(({ snap, r }) => r.links.map((l) => ({ snap, l })));
  const rows = all.flatMap(({ snap, r }) => r.findings.map((f) => ({ snap, f })));
  const head = h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'On-premises'), h('p', {}, 'What clients in your own networks can reach over Site-to-Site VPN and Direct Connect, from which addresses, and over which link.')));
  if (!links.length) return h('div', { class: 'page' }, head, h('div', { class: 'box' }, empty('No VPN or Direct Connect links', 'The loaded snapshots have no virtual private gateways, and no VPN or Direct Connect attachments on transit gateways.')));

  const linkList = h(
    'section',
    { class: 'box', style: 'margin-bottom:1rem' },
    boxHead('Links', D.plural(links.length, 'link')),
    h(
      'div',
      { class: 'table-wrap' },
      h(
        'table',
        { class: 't op-links' },
        h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Link'), h('th', {}, 'Type'), h('th', {}, 'On-premises networks'), h('th', {}, 'Tunnels'), h('th', { class: 'last hide-sm' }, 'Account and region'))),
        h(
          'tbody',
          {},
          ...links.map(({ snap, l }) =>
            h(
              'tr',
              {},
              h('td', { class: 'first mono' }, l.attachment ? `${l.id} on ${l.gateway}` : l.id),
              h('td', {}, KIND[l.kind]),
              h('td', { class: 'mono' }, l.networks.length ? l.networks.join(', ') : h('span', { class: 'faint' }, 'none routed')),
              h('td', {}, l.connections.length ? l.connections.map((c) => `${c.id}: ${c.tunnelsUp} of ${c.tunnels} up`).join('; ') : h('span', { class: 'faint' }, '—'), l.down ? h('span', { class: 'tag op-down' }, 'down') : null),
              h('td', { class: 'last hide-sm dim' }, `${snap.account} / ${snap.region}`),
            ),
          ),
        ),
      ),
    ),
  );

  const detail = h('div', { class: 'op-detail' });
  const table = h(
    'table',
    { class: 't op-t' },
    h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Server'), h('th', {}, 'Service'), h('th', {}, 'From'), h('th', { class: 'last' }, 'Over'))),
    h(
      'tbody',
      {},
      ...rows.map(({ f }) => {
        const tr = h(
          'tr',
          { class: 'click', tabindex: '0' },
          h('td', { class: 'first' }, sevPill(f.severity)),
          h('td', {}, h('strong', {}, short(f.resourceName))),
          h('td', { class: 'mono' }, service(f)),
          h('td', { class: 'mono' }, f.sources.slice(0, 2).join(', ') + (f.sources.length > 2 ? ` +${f.sources.length - 2}` : '')),
          h('td', { class: 'last mono' }, f.via, f.inspectedBy?.length ? h('div', { class: 'faint' }, `inspected by ${f.inspectedBy.join(', ')}`) : null),
        );
        const show = () => {
          table.querySelectorAll('tr.sel').forEach((x) => x.classList.remove('sel'));
          tr.classList.add('sel');
          detail.replaceChildren(
            h(
              'section',
              { class: 'box' },
              boxHead(`${short(f.resourceName)}: ${service(f)} from on-premises`, f.reasons.join('; ')),
              h(
                'div',
                { class: 'pad' },
                h('dl', { class: 'kv' }, h('dt', {}, 'From'), h('dd', { class: 'mono' }, f.sources.slice(0, 8).join(', ')), h('dt', {}, 'Over'), h('dd', {}, f.via), h('dt', {}, 'Replies'), h('dd', {}, f.returnPath === 'all' ? 'Allowed on every client port' : 'Only on some client ports')),
                traceStepper({ hops: f.trace }, short(f.resourceName)),
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
  const reach = all.reduce((n, x) => n + x.r.reachable, 0);
  const total = all.reduce((n, x) => n + x.r.interfaces, 0);
  return h(
    'div',
    { class: 'page' },
    head,
    linkList,
    rows.length
      ? h('section', { class: 'box', style: 'margin-bottom:1rem' }, boxHead('Reachable from on-premises', `${reach} of ${D.plural(total, 'interface')}; select a row for the path`), h('div', { class: 'table-wrap' }, table))
      : h('div', { class: 'box', style: 'margin-bottom:1rem' }, empty('Nothing reachable from on-premises', 'No security group, network ACL and return route together let an on-premises address connect to any interface.')),
    detail,
    chainsBox(snaps),
    h('p', { class: 'faint op-note' }, 'On-premises routers and firewalls are not visible to AWS; these paths assume they pass.'),
  );
}
