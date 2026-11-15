/** `pinhole onprem`: what clients on-premises can reach over VPN and Direct Connect. */
import { SEVERITY_ORDER } from '@pinhole/engine';
import type { BlastReport, OnPremFinding, OnPremReport, Severity } from '@pinhole/engine';

const ports = (f: OnPremFinding) => (f.protocol === 'icmp' ? 'icmp echo' : f.ports.from === 0 && f.ports.to === 65535 ? `${f.protocol}/any port` : f.ports.from === f.ports.to ? `${f.protocol}/${f.ports.from}` : `${f.protocol}/${f.ports.from}-${f.ports.to}`);
const at = (min: Severity) => (f: { severity: Severity }) => SEVERITY_ORDER.indexOf(f.severity) <= SEVERITY_ORDER.indexOf(min);

export function onPremText(r: OnPremReport, min: Severity, verbose: boolean, blast?: BlastReport): string {
  const lines = ['Pinhole on-premises report', ''];
  if (!r.links.length) {
    lines.push('No VPN or Direct Connect links in this snapshot: no virtual private gateways, and no VPN or Direct Connect attachments on transit gateways.');
    return `${lines.join('\n')}\n`;
  }
  lines.push('Links:');
  for (const l of r.links) {
    lines.push(`  ${l.description}${l.down ? ' [all tunnels down]' : ''}`);
    lines.push(`    on-premises networks: ${l.networks.length ? l.networks.join(', ') : 'none routed (no route in AWS leads to this link)'}`);
  }
  lines.push('', `${r.reachable} of ${r.interfaces} interfaces can be reached from on-premises.`, '');
  const shown = r.findings.filter(at(min));
  for (const f of shown) {
    lines.push(`[${f.severity.toUpperCase()}] ${ports(f)} on ${f.resourceName}`);
    lines.push(`  from:     ${f.sources.slice(0, 4).join(', ')}${f.sources.length > 4 ? ` and ${f.sources.length - 4} more` : ''}`);
    lines.push(`  over:     ${f.via}`);
    if (f.inspectedBy?.length) lines.push(`  inspected by: ${f.inspectedBy.join(', ')}`);
    lines.push(`  why:      ${f.reasons.join('; ')}`);
    if (f.returnPath !== 'all') lines.push('  replies:  only for some client ports');
    if (verbose) for (const h of f.trace) lines.push(`      ${h.stage.padEnd(18)} ${h.decision === 'pass' ? 'ok  ' : h.decision.toUpperCase().padEnd(4)} ${h.detail}`);
    lines.push('');
  }
  if (!shown.length) lines.push(`Nothing reachable from on-premises at or above ${min}.`);
  const chains = (blast?.chains ?? []).filter(at(min));
  if (blast) {
    lines.push('', `If a host on-premises is taken over: ${blast.entries.length} foothold(s) in AWS, ${blast.chains.length} attack chain(s).`);
    for (const c of chains) {
      lines.push(`[${c.severity.toUpperCase()}] on-premises --> ${c.steps.map((s, i) => (i ? `--${s.service}${s.serviceName ? ` ${s.serviceName}` : ''}--> ${s.name}` : s.name)).join(' ')}`);
      lines.push(`    ${c.why.join(' ')}`);
    }
  }
  lines.push('', 'Note: on-premises routers and firewalls are not visible to AWS; these paths assume they pass.');
  return `${lines.join('\n')}\n`;
}

export function onPremMarkdown(r: OnPremReport, min: Severity): string {
  const esc = (t: string) => t.replace(/[|\\`*_<>[\]]/g, (c) => `\\${c}`);
  return [
    `### Pinhole on-premises: ${r.reachable} of ${r.interfaces} interfaces reachable over ${r.links.length} link(s)`,
    '',
    '| Severity | Server | Service | From | Over |',
    '| --- | --- | --- | --- | --- |',
    ...r.findings.filter(at(min)).map((f) => `| ${f.severity} | ${esc(f.resourceName)} | ${ports(f)} | ${esc(f.sources.slice(0, 2).join(', '))} | ${esc(f.via)} |`),
    '',
  ].join('\n');
}

export const onPremFailsAt = (r: OnPremReport, level: Severity) => r.findings.filter(at(level)).length;
