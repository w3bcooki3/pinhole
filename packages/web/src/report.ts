/**
 * A report to hand to someone who will not open the console: what the internet
 * reaches, what an attacker reaches next, the changes that fix it, and what the
 * analysis could not see. Rendered as plain document markup so it prints well
 * and can be saved as one HTML file with no script.
 */
import { describeChange } from '@pinhole/engine';
import { h } from './dom.js';
import type { Child } from './dom.js';
import * as D from './data.js';
import type { Row, Severity, Snap } from './data.js';

const short = (s: string) => s.replace(/ \(.*\)$/, '');
const chainText = (steps: { name: string }[]) => steps.map((x) => short(x.name)).join(' → ');
const sev = (s: Severity) => h('span', { class: `r-sev ${s}` }, D.SEV_LABEL[s]);
const portsOf = (d: { protocol: string; ports?: { from: number; to: number } }) => `${d.protocol}${d.ports ? `/${d.ports.from === d.ports.to ? d.ports.from : `${d.ports.from}-${d.ports.to}`}` : ''}`;

function table(head: string[], rows: Child[][]): HTMLElement {
  return h('table', {}, h('thead', {}, h('tr', {}, ...head.map((x) => h('th', {}, x)))), h('tbody', {}, ...rows.map((r) => h('tr', {}, ...r.map((c) => h('td', {}, c))))));
}

export function reportDoc(snaps: Snap[], rows: Row[], now = new Date()): HTMLElement {
  const accounts = [...new Set(snaps.map((x) => x.account))].sort();
  const regions = [...new Set(snaps.map((x) => x.region))].sort();
  const count = (s: Severity) => rows.filter((r) => r.f.severity === s).length;
  const urgent = rows.filter((r) => r.f.severity === 'critical' || r.f.severity === 'high');
  const rest = rows.filter((r) => !(r.f.severity === 'critical' || r.f.severity === 'high'));
  const chains = D.chainsOf(snaps);
  const plans = snaps.map((snap) => ({ snap, plan: D.planOf(snap) }));
  const steps = plans.flatMap(({ snap, plan }) => plan.steps.map((step) => ({ snap, step })));
  const closedE = plans.reduce((n, x) => n + x.plan.before.exposures - x.plan.after.exposures, 0);
  const allE = plans.reduce((n, x) => n + x.plan.before.exposures, 0);
  const closedC = plans.reduce((n, x) => n + x.plan.before.chains - x.plan.after.chains, 0);
  const allC = plans.reduce((n, x) => n + x.plan.before.chains, 0);
  const hyg = D.hygieneRows(snaps).filter((x) => !x.h.inExposure);
  const resources = new Set(rows.map((r) => `${r.snap.key}|${r.f.resourceId}`)).size;
  const ages = snaps.map((x) => D.collected(x));
  const stale = ages.some((a) => a.days !== undefined && a.days > D.STALE_DAYS);

  const summary = [
    rows.length
      ? `${D.plural(rows.length, 'service')} on ${D.plural(resources, 'resource')} can be reached from the internet: ${count('critical')} critical, ${count('high')} high, ${count('medium')} medium and ${count('low')} low.`
      : 'Nothing in these snapshots can be reached from the internet.',
    chains.length ? ` If one of the internet-facing servers is compromised, an attacker can go on to reach ${D.plural(chains.length, 'internal resource')} (attack chains).` : '',
    steps.length ? ` ${D.plural(steps.length, 'change')} close${steps.length === 1 ? 's' : ''} ${closedE} of ${allE} critical and high exposures${allC ? ` and ${closedC} of ${allC} attack chains` : ''}; each was checked by running the analysis again.` : '',
  ].join('');

  const doc = h(
    'article',
    { class: 'report' },
    h('header', {}, h('p', { class: 'r-kicker' }, 'Pinhole network exposure report'), h('h1', {}, `${D.plural(accounts.length, 'account')}, ${D.plural(regions.length, 'region')}`), h('p', { class: 'r-meta' }, `Accounts ${accounts.join(', ')}. Regions ${regions.join(', ')}. Report generated ${now.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}.`)),
    h('section', {}, h('h2', {}, 'Summary'), h('p', { class: 'r-lede' }, summary), stale ? h('p', { class: 'r-warn' }, `At least one snapshot is more than ${D.STALE_DAYS} days old. The network may have changed since; collect fresh snapshots before acting.`) : null,
      table(['Critical', 'High', 'Medium', 'Low', 'Attack chains', 'Rule hygiene'], [[String(count('critical')), String(count('high')), String(count('medium')), String(count('low')), String(chains.length), String(hyg.length)]])),
  );

  if (steps.length) {
    doc.append(
      h(
        'section',
        {},
        h('h2', {}, 'Fix plan'),
        h('p', {}, 'The fewest changes that close every critical and high exposure and attack chain, in order. Review each command, then run it; Pinhole never changes anything in AWS.'),
        h(
          'ol',
          { class: 'r-plan' },
          ...steps.map(({ snap, step }) => {
            const said = step.changes.map((c) => { try { return describeChange(snap.model, c); } catch { return ''; } }).filter(Boolean);
            return h(
              'li',
              {},
              h('p', { class: 'r-strong' }, said.length === 1 ? said[0]! : step.title),
              said.length > 1 ? h('p', {}, said.join('. ')) : null,
              h('p', { class: 'r-dim' }, [`${snap.account} ${snap.region}.`, step.closes.length ? `Closes ${step.closes.map((d) => `${short(d.resourceName)} ${portsOf(d)}`).join(', ')}.` : '', step.chainsCut.length ? `Cuts ${step.chainsCut.map((c) => chainText(c.steps)).join('; ')}.` : '', step.collateral.length ? `Also affects ${step.collateral.map((d) => `${short(d.resourceName)} ${portsOf(d)}`).join(', ')}: check these are not wanted.` : ''].filter(Boolean).join(' ')),
              h('pre', {}, step.cli.join('\n')),
            );
          }),
        ),
        plans.some((x) => x.plan.unresolved.length) ? h('p', { class: 'r-warn' }, `No single change closes: ${plans.flatMap((x) => x.plan.unresolved).join('; ')}.`) : null,
      ),
    );
  }

  if (urgent.length) {
    doc.append(
      h(
        'section',
        {},
        h('h2', {}, 'Critical and high exposures'),
        ...urgent.map((r) => {
          const fix = D.fixesOf(r).find((x) => x.verified);
          const rules = r.f.trace.filter((x) => x.ruleIds?.length).map((x) => D.hopId(x));
          return h(
            'div',
            { class: 'r-item' },
            h('h3', {}, sev(r.f.severity), ' ', `${D.shortName(r.f)} on ${D.service(r.f)}`),
            h('p', {}, D.sentence(r.f)),
            h('p', { class: 'r-dim' }, `${D.kind(r.f)} ${r.f.resourceId} in ${r.f.vpcId}, ${r.snap.account} ${r.snap.region}.${rules.length ? ` Allowed by ${[...new Set(rules)].join(', ')}.` : ''}`),
            fix ? h('p', {}, h('b', {}, 'Fix: '), fix.steps.join('. '), '.') : h('p', {}, 'No single change closes this; see the simulator.'),
          );
        }),
      ),
    );
  }

  if (chains.length) {
    doc.append(
      h(
        'section',
        {},
        h('h2', {}, 'Attack chains'),
        h('p', {}, 'Each row assumes the first server, which the internet can reach, is compromised, and follows remote administration and control-plane access to an internal resource the internet cannot reach directly.'),
        table(
          ['Severity', 'Chain', 'Reaches', 'Account and region'],
          chains.map(({ c, snap }) => {
            const end = c.steps.at(-1)!;
            return [sev(c.severity), chainText(c.steps), `${end.serviceName ? `${end.serviceName} ` : ''}${end.service ?? ''}`, `${snap.account} ${snap.region}`];
          }),
        ),
      ),
    );
  }

  if (rest.length) {
    doc.append(h('section', {}, h('h2', {}, 'Other exposures'), table(['Severity', 'Resource', 'Service', 'Open to', 'Account and region'], rest.map((r) => [sev(r.f.severity), D.shortName(r.f), `${D.service(r.f)}${D.serviceName(r.f) ? ` ${D.serviceName(r.f)}` : ''}`, D.openTo(r.f), `${r.snap.account} ${r.snap.region}`]))));
  }

  if (hyg.length) {
    doc.append(h('section', {}, h('h2', {}, 'Rule hygiene'), h('p', {}, 'Rules that do nothing, can never match, point at something that is gone, or allow much more than they need to. None of these lets the internet in today.'), table(['Severity', 'Finding', 'Account and region'], hyg.map((x) => [sev(x.h.severity), x.h.title, `${x.snap.account} ${x.snap.region}`]))));
  }

  const notes = snaps.flatMap((s) => s.warnings.map((w) => ({ s, w })));
  doc.append(
    h(
      'section',
      {},
      h('h2', {}, 'Method and limits'),
      h('p', {}, 'Pinhole read each account with read-only Describe calls and evaluated every security group rule, network ACL entry, route table, internet gateway, public IP and load balancer listener on each path, in both directions. Results describe what the network allows at the time of collection.'),
      h('p', {}, 'It does not see host firewalls, the applications themselves, AWS WAF or Shield, or IAM. A path means the network lets the connection through, not that the service accepts it. Attack chains assume an attacker who controls one server can use any remote administration or control-plane service the network lets it reach.'),
      table(['Snapshot', 'Account and region', 'Collected', 'Coverage notes'], snaps.map((s, i) => [s.name, `${s.account} ${s.region}`, ages[i]!.text.replace(/^Collected /, ''), String(s.warnings.length)])),
      notes.length ? h('ul', {}, ...notes.map(({ s, w }) => h('li', {}, `${s.account} ${s.region}: ${w.message}`))) : null,
    ),
  );
  return doc;
}

export const REPORT_CSS = `
.report{max-width:52rem;margin:0 auto;font:400 15px/1.55 Inter,system-ui,-apple-system,"Segoe UI",sans-serif;color:#161A26}
.report header{border-bottom:2px solid #161A26;padding-bottom:1rem;margin-bottom:1.5rem}
.report .r-kicker{margin:0;color:#545B6E;font-weight:500}
.report h1{font-size:1.75rem;margin:.25rem 0 .5rem;letter-spacing:-.015em}
.report h2{font-size:1.2rem;margin:2rem 0 .75rem;padding-bottom:.375rem;border-bottom:1px solid #E2E5EB}
.report h3{font-size:1rem;margin:0 0 .375rem}
.report p{margin:0 0 .5rem}
.report .r-meta,.report .r-dim{color:#545B6E}
.report .r-lede{font-size:1.0625rem}
.report .r-strong{font-weight:600}
.report .r-warn{color:#876600;font-weight:500}
.report table{width:100%;border-collapse:collapse;margin:.75rem 0;font-size:.9rem}
.report th{text-align:left;font-weight:600;color:#545B6E;border-bottom:1px solid #C9CDD6;padding:.375rem .5rem}
.report td{border-bottom:1px solid #E2E5EB;padding:.375rem .5rem;vertical-align:top}
.report pre{background:#F3F4F7;border:1px solid #E2E5EB;border-radius:4px;padding:.5rem .625rem;font:12.5px/1.45 "Geist Mono",ui-monospace,Menlo,monospace;white-space:pre-wrap;overflow-wrap:anywhere;margin:.375rem 0 0}
.report ol.r-plan{padding-left:1.25rem}
.report ol.r-plan li{margin-bottom:1rem;break-inside:avoid}
.report .r-item{margin-bottom:1.125rem;break-inside:avoid}
.report .r-sev{font-weight:600;white-space:nowrap}
.report .r-sev.critical{color:#D7263D}.report .r-sev.high{color:#C25E00}.report .r-sev.medium{color:#876600}.report .r-sev.low{color:#23946A}.report .r-sev.info{color:#878D9E}
@media print{.report{max-width:none;font-size:11pt}.report h2{break-after:avoid}}
`;

/** The report as one HTML file: no script, nothing loaded from anywhere. */
export function reportHtml(doc: HTMLElement, title: string): string {
  const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><style>body{margin:2rem 1.25rem;background:#fff}${REPORT_CSS}</style></head>
<body>${doc.outerHTML}</body></html>
`;
}
