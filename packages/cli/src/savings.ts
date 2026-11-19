/** `pinhole savings`: network resources that cost money and serve nothing, and per-gigabyte costs worth checking. */
import { analyzeSavings, PRICES } from '@pinhole/engine';
import type { NetworkModel, SavingsFinding, SavingsReport } from '@pinhole/engine';

export function savings(model: NetworkModel): SavingsReport {
  return analyzeSavings(model);
}

const usd = (n: number) => `$${n.toFixed(2)}`;
const cost = (f: SavingsFinding) => (f.monthly !== undefined ? `${usd(f.monthly)}/month` : f.perGb !== undefined ? `$${f.perGb}/GB` : '');
const PRICE_NOTE = `Prices are AWS list prices for ${PRICES.region} (${PRICES.hoursPerMonth} hours a month); most other Regions charge the same or a little more.`;

export function savingsText(r: SavingsReport): string {
  const unused = r.findings.filter((f) => f.kind === 'unused');
  const check = r.findings.filter((f) => f.kind === 'check');
  const lines = [
    'Pinhole savings report',
    unused.length ? `${unused.length} unused ${unused.length === 1 ? 'resource costs' : 'resources cost'} about ${usd(r.unusedMonthly)} a month.` : 'Nothing found that costs money and serves nothing.',
    `${r.publicIpv4.count} public IPv4 ${r.publicIpv4.count === 1 ? 'address costs' : 'addresses cost'} about ${usd(r.publicIpv4.monthly)} a month together.`,
    PRICE_NOTE,
    '',
  ];
  if (!r.elasticIpsKnown) lines.push('This snapshot has no Elastic IP list, so idle Elastic IPs are not checked. Collect again to include them.', '');
  const show = (f: SavingsFinding) => {
    lines.push(`[${f.kind === 'unused' ? 'UNUSED' : 'CHECK'}] ${f.title}${cost(f) ? `  (${cost(f)})` : ''}`);
    lines.push(`  why:  ${f.why}`);
    lines.push(`  fix:  ${f.fix}`);
    for (const c of f.commands ?? []) lines.push(`        ${c}`);
    if (f.related?.length) lines.push(`  covers: ${f.related.join(', ')}`);
    lines.push('');
  };
  unused.forEach(show);
  if (check.length) lines.push('Worth checking (charged per gigabyte; the snapshot has no traffic volumes):', '');
  check.forEach(show);
  return `${lines.join('\n')}\n`;
}

export function savingsMarkdown(r: SavingsReport): string {
  const esc = (t: string) => t.replace(/[|\\`*_<>[\]]/g, (c) => `\\${c}`);
  return [
    `### Pinhole savings: about ${usd(r.unusedMonthly)} a month on unused network resources`,
    '',
    '| | Finding | Cost | Fix |',
    '|---|---|---|---|',
    ...r.findings.map((f) => `| ${f.kind === 'unused' ? 'Unused' : 'Check'} | ${esc(f.title)} | ${cost(f)} | ${esc(f.fix)} |`),
    '',
    PRICE_NOTE,
    '',
  ].join('\n');
}
