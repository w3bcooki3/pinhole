/** Savings page: network resources that cost money and serve nothing, and per-gigabyte costs worth checking. */
import { analyzeSavings, PRICES } from '@pinhole/engine';
import type { SavingsFinding, SavingsReport } from '@pinhole/engine';
import { h, on, toast } from './dom.js';
import * as D from './data.js';
import type { Snap } from './data.js';
import { egressOf } from './egress.js';
import { boxHead, empty, short, stacked } from './ui.js';

const cache = new WeakMap<Snap, SavingsReport>();
export function savingsOf(snap: Snap): SavingsReport {
  let r = cache.get(snap);
  if (!r) cache.set(snap, (r = analyzeSavings(snap.model, { exposure: D.reportOf(snap), egress: egressOf(snap) })));
  return r;
}

export const usd = (n: number) => `$${n.toLocaleString('en-US', { minimumFractionDigits: n < 100 ? 2 : 0, maximumFractionDigits: n < 100 ? 2 : 0 })}`;
const cost = (f: SavingsFinding) => (f.monthly !== undefined ? `${usd(f.monthly)} a month` : f.perGb !== undefined ? `$${f.perGb} per GB` : '');
const WHAT: Record<SavingsFinding['code'], string> = {
  'idle-elastic-ip': 'Elastic IP attached to nothing',
  'unused-public-ip': 'Public IP nothing uses',
  'unused-nat-gateway': 'NAT gateway on no route',
  'idle-load-balancer': 'Load balancer with nothing behind it',
  's3-through-nat': 'S3 through a NAT gateway',
  'nat-in-other-zone': 'NAT gateway in another zone',
};

/** Unused monthly total across the latest snapshot of each account and region. */
export function savingsTotal(snaps: Snap[]): { monthly: number; count: number } {
  const all = D.latestPerScope(snaps).map(savingsOf);
  return { monthly: all.reduce((n, r) => n + r.unusedMonthly, 0), count: all.reduce((n, r) => n + r.findings.filter((f) => f.kind === 'unused').length, 0) };
}

export function savingsPage(ctx: { st: { snaps: Snap[] } }): HTMLElement {
  const snaps = D.latestPerScope(ctx.st.snaps);
  const all = snaps.map((snap) => ({ snap, r: savingsOf(snap) }));
  const rows = all.flatMap(({ snap, r }) => r.findings.map((f) => ({ snap, f }))).sort((a, b) => (b.f.monthly ?? 0) - (a.f.monthly ?? 0) || (b.f.perGb ?? 0) - (a.f.perGb ?? 0) || a.f.resourceName.localeCompare(b.f.resourceName));
  const unused = rows.filter((x) => x.f.kind === 'unused');
  const check = rows.filter((x) => x.f.kind === 'check');
  const monthly = all.reduce((n, x) => n + x.r.unusedMonthly, 0);
  const ips = all.reduce((n, x) => n + x.r.publicIpv4.count, 0);
  const ipCost = all.reduce((n, x) => n + x.r.publicIpv4.monthly, 0);
  const noEips = all.filter((x) => !x.r.elasticIpsKnown).length;

  const detail = h('div', { class: 'eg-detail' });
  const table = (list: typeof rows, title: string, sub: string) => {
    const t = h(
      'table',
      { class: 't sv-t' },
      h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Resource'), h('th', {}, 'What'), h('th', {}, 'Cost'), h('th', { class: 'last hide-sm' }, 'Account and region'))),
      h(
        'tbody',
        {},
        ...list.map(({ snap, f }) => {
          const tr = h(
            'tr',
            { class: 'click', tabindex: '0' },
            h('td', { class: 'first' }, h('strong', {}, short(f.resourceName))),
            h('td', {}, WHAT[f.code]),
            h('td', { class: 'num' }, cost(f)),
            h('td', { class: 'last hide-sm dim' }, `${snap.account} / ${snap.region}`),
          );
          const show = () => {
            detail.parentElement?.querySelectorAll('tr.sel').forEach((x) => x.classList.remove('sel'));
            tr.classList.add('sel');
            detail.replaceChildren(
              h(
                'section',
                { class: 'box' },
                boxHead(f.title, cost(f) ? `${f.kind === 'unused' ? 'Costs' : 'Charged at'} ${cost(f)}` : ''),
                h(
                  'div',
                  { class: 'pad' },
                  h('dl', { class: 'kv' }, h('dt', {}, 'Why'), h('dd', {}, f.why), h('dt', {}, 'Fix'), h('dd', {}, f.fix), ...(f.related?.length ? [h('dt', {}, 'Covers'), h('dd', { class: 'mono' }, f.related.join(', '))] : [])),
                  f.commands?.length
                    ? h('div', { class: 'cmd' }, h('pre', {}, f.commands.join('\n')), on(h('button', { type: 'button' }, 'Copy'), 'click', async () => {
                        await D.copyText(f.commands!.join('\n'));
                        toast('Copied');
                      }))
                    : null,
                  h('p', { class: 'faint', style: 'margin:0.75rem 0 0' }, 'Nothing is changed from here: review the commands and run them yourself.'),
                ),
              ),
            );
            detail.scrollIntoView?.({ block: 'nearest' });
          };
          on(tr, 'click', show);
          on(tr, 'keydown', (e) => {
            if ((e as KeyboardEvent).key === 'Enter') show();
          });
          return tr;
        }),
      ),
    );
    return h('section', { class: 'box', style: 'margin-bottom:1rem' }, boxHead(title, sub), h('div', { class: 'table-wrap' }, stacked(t)));
  };

  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Savings'), h('p', {}, 'Network resources that cost money and serve nothing, found in the same snapshot as the security analysis. No billing access is needed.'))),
    h(
      'p',
      { class: 'eg-sum' },
      unused.length ? h('strong', {}, `${D.plural(unused.length, 'unused resource')} ${unused.length === 1 ? 'costs' : 'cost'} about ${usd(monthly)} a month (${usd(monthly * 12)} a year)`) : h('strong', {}, 'Nothing found that costs money and serves nothing'),
      `. ${D.plural(ips, 'public IPv4 address', 'public IPv4 addresses')} cost about ${usd(ipCost)} a month together.`,
    ),
    h('p', { class: 'faint', style: 'margin:-0.5rem 0 1rem' }, `Prices are AWS list prices for ${PRICES.region}; most other regions charge the same or a little more.`),
    noEips ? h('div', { class: 'warn-bar', style: 'margin:0 0 1rem' }, `${noEips === all.length ? (all.length === 1 ? 'This snapshot has' : 'These snapshots have') : `${noEips} of ${D.plural(all.length, 'snapshot')} have`} no Elastic IP list, so Elastic IPs attached to nothing are not checked there. Collect again with the current script or collector to include them.`) : null,
    unused.length ? table(unused, 'Unused', 'Nothing can use these: removing them changes nothing but the bill. Select a row for why and how.') : null,
    check.length ? table(check, 'Worth checking', 'Charged per gigabyte. The snapshot has no traffic volumes, so these give the rate and the free or cheaper alternative.') : null,
    !rows.length ? empty('Nothing to save here', 'No unused Elastic IPs, public IPs, NAT gateways or load balancers, and no per-gigabyte costs worth checking, in the loaded snapshots.') : null,
    detail,
  );
}

