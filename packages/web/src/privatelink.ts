/** PrivateLink page: who can reach this account's services through endpoint services, and what its endpoints let through. */
import { analyzePrivateLink } from '@pinhole/engine';
import type { PrivateLinkReport, PrivateLinkService } from '@pinhole/engine';
import { h, on } from './dom.js';
import * as D from './data.js';
import type { Snap } from './data.js';
import { boxHead, empty, sevPill, stacked } from './ui.js';

const cache = new WeakMap<Snap, PrivateLinkReport>();
export function privateLinkOf(snap: Snap): PrivateLinkReport {
  let r = cache.get(snap);
  if (!r) cache.set(snap, (r = analyzePrivateLink(snap.model)));
  return r;
}

const FILTER = { 'no-security-groups': 'no security groups', 'rules-off-for-privatelink': 'security groups not applied to PrivateLink', 'security-groups': 'security groups' } as const;
const who = (s: PrivateLinkService) => (s.open ? 'Every AWS account' : s.principals ? (s.external.length ? `${D.plural(s.external.length, 'outside principal')}` : 'This account only') : 'Not collected');

function serviceDetail(s: PrivateLinkService): HTMLElement {
  return h(
    'section',
    { class: 'box' },
    boxHead(s.name, s.reasons.join('; ')),
    h(
      'div',
      { class: 'pad' },
      h(
        'dl',
        { class: 'kv' },
        h('dt', {}, 'Who may connect'),
        h('dd', {}, s.open ? 'Every AWS account' : s.principals?.length ? h('span', { class: 'mono' }, s.principals.join(', ')) : s.principals ? 'Nobody' : 'Not collected'),
        h('dt', {}, 'Approval'),
        h('dd', {}, s.acceptanceRequired ? 'Each connection needs your approval' : 'Not required: allowed principals connect at once'),
        h('dt', {}, 'Connected'),
        h('dd', {}, s.consumers.length ? s.consumers.map((c) => `${c.endpointId} (${c.owner}${c.region ? `, ${c.region}` : ''}, ${c.state})`).join('; ') : 'None'),
        ...(s.remoteRegions.length ? [h('dt', {}, 'Other Regions'), h('dd', {}, s.remoteRegions.join(', '))] : []),
      ),
      s.listeners.length
        ? h(
            'div',
            { class: 'table-wrap' },
            stacked(h(
              'table',
              { class: 't pl-listeners' },
              h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Listener'), h('th', {}, 'Consumers let in'), h('th', {}, 'Filtered by'), h('th', { class: 'last' }, 'Targets'))),
              h(
                'tbody',
                {},
                ...s.listeners.map((l) =>
                  h(
                    'tr',
                    {},
                    h('td', { class: 'first mono' }, `${l.protocol.toUpperCase()} ${l.port} on ${l.loadBalancer}`),
                    h('td', { class: 'mono' }, l.consumers.length ? l.consumers.join(', ') : 'none'),
                    h('td', {}, FILTER[l.filter]),
                    h('td', { class: 'last' }, ...(l.targets.length ? l.targets.map((t) => h('div', {}, h('span', { class: `pl-v ${t.verdict}` }, t.verdict), ` ${t.targetId}:${t.port}`, t.blockedAt ? h('span', { class: 'faint' }, ` at ${t.blockedAt.resourceId}`) : null)) : [h('span', { class: 'faint' }, 'none')])),
                  ),
                ),
              ),
            )),
          )
        : h('p', { class: 'faint' }, 'No listeners analysed (Gateway Load Balancer, or the load balancer is not in the snapshot).'),
    ),
  );
}

export function privateLinkPage(ctx: { st: { snaps: Snap[] } }): HTMLElement {
  const snaps = D.latestPerScope(ctx.st.snaps);
  const all = snaps.map((snap) => ({ snap, r: privateLinkOf(snap) }));
  const services = all.flatMap(({ snap, r }) => r.services.map((s) => ({ snap, s })));
  const endpoints = all.flatMap(({ snap, r }) => r.endpoints.map((e) => ({ snap, e })));
  const head = h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'PrivateLink'), h('p', {}, 'Who can reach your services through endpoint services, and what your own VPC endpoints let through.')));
  if (!services.length && !endpoints.length) return h('div', { class: 'page' }, head, h('div', { class: 'box' }, empty('No endpoint services or VPC endpoints', 'The loaded snapshots provide no PrivateLink services and have no interface or gateway endpoints.')));

  const detail = h('div', { class: 'pl-detail' });
  const svcTable = h(
    'table',
    { class: 't pl-services' },
    h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Service'), h('th', {}, 'Who may connect'), h('th', {}, 'Approval'), h('th', {}, 'Connected'), h('th', { class: 'last hide-sm' }, 'Account and region'))),
    h(
      'tbody',
      {},
      ...services.map(({ snap, s }) => {
        const tr = h(
          'tr',
          { class: 'click', tabindex: '0' },
          h('td', { class: 'first' }, sevPill(s.severity)),
          h('td', { class: 'mono' }, s.id),
          h('td', {}, who(s)),
          h('td', {}, s.acceptanceRequired ? 'Required' : h('strong', {}, 'Not required')),
          h('td', {}, String(s.consumers.length)),
          h('td', { class: 'last hide-sm dim' }, `${snap.account} / ${snap.region}`),
        );
        const show = () => {
          svcTable.querySelectorAll('tr.sel').forEach((x) => x.classList.remove('sel'));
          tr.classList.add('sel');
          detail.replaceChildren(serviceDetail(s));
        };
        on(tr, 'click', show);
        on(tr, 'keydown', (e) => {
          if ((e as KeyboardEvent).key === 'Enter') show();
        });
        return tr;
      }),
    ),
  );
  const epTable = h(
    'table',
    { class: 't pl-endpoints' },
    h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Endpoint'), h('th', {}, 'Service'), h('th', {}, 'Policy'), h('th', { class: 'last' }, 'Why'))),
    h(
      'tbody',
      {},
      ...endpoints.map(({ e }) =>
        h('tr', {}, h('td', { class: 'first' }, sevPill(e.severity)), h('td', { class: 'mono' }, e.id, h('div', { class: 'faint' }, e.type)), h('td', { class: 'mono' }, e.serviceName), h('td', {}, e.policy === 'full' ? 'Allows everything' : e.policy === 'restricted' ? 'Restricted' : 'Unknown'), h('td', { class: 'last' }, e.reasons.join('; '))),
      ),
    ),
  );
  return h(
    'div',
    { class: 'page' },
    head,
    services.length ? h('section', { class: 'box', style: 'margin-bottom:1rem' }, boxHead('Endpoint services you provide', 'Select a row for listeners and targets'), h('div', { class: 'table-wrap' }, stacked(svcTable))) : null,
    detail,
    endpoints.length ? h('section', { class: 'box', style: 'margin-top:1rem' }, boxHead('Your VPC endpoints', D.plural(endpoints.length, 'endpoint')), h('div', { class: 'table-wrap' }, stacked(epTable))) : null,
  );
}
