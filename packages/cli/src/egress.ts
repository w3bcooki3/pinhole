/** `pinhole egress`: what each server can send to the internet, and how. */
import { analyzeEgress, SEVERITY_ORDER } from '@pinhole/engine';
import type { EgressFinding, EgressReport, NetworkModel, Severity } from '@pinhole/engine';

const ports = (f: EgressFinding) => (f.protocol === 'icmp' ? 'icmp echo' : f.ports.from === 0 && f.ports.to === 65535 ? `${f.protocol}/any port` : f.ports.from === f.ports.to ? `${f.protocol}/${f.ports.from}` : `${f.protocol}/${f.ports.from}-${f.ports.to}`);
const at = (min: Severity) => (f: EgressFinding) => SEVERITY_ORDER.indexOf(f.severity) <= SEVERITY_ORDER.indexOf(min);

export function egress(model: NetworkModel): EgressReport {
  return analyzeEgress(model);
}

export function egressText(r: EgressReport, min: Severity, verbose: boolean): string {
  const shown = r.findings.filter(at(min));
  const lines = [
    'Pinhole outbound report',
    `${r.open} of ${r.interfaces} interfaces can open connections to the internet; ${r.wide} on any port to any address.`,
    '',
  ];
  for (const f of shown) {
    lines.push(`[${f.severity.toUpperCase()}] ${ports(f)} out from ${f.resourceName}`);
    lines.push(`  to:       ${f.destinations.slice(0, 4).join(', ')}${f.destinations.length > 4 ? ` and ${f.destinations.length - 4} more` : ''}`);
    lines.push(`  leaves:   through ${f.via.gateway}${f.via.publicIp ? ` as ${f.via.publicIp}` : ''}`);
    if (f.inspectedBy?.length) lines.push(`  inspected by: ${f.inspectedBy.join(', ')}`);
    lines.push(`  why:      ${f.reasons.join('; ')}`);
    if (f.returnPath !== 'all') lines.push('  replies:  only for some of its ephemeral ports');
    for (const c of f.caveats ?? []) lines.push(`  note:     ${c}`);
    if (verbose) for (const h of f.trace) lines.push(`      ${h.stage.padEnd(18)} ${h.decision === 'pass' ? 'ok  ' : h.decision.toUpperCase().padEnd(4)} ${h.detail}`);
    lines.push('');
  }
  if (!shown.length) lines.push(`No outbound findings at or above ${min}.`);
  return `${lines.join('\n')}\n`;
}

export function egressMarkdown(r: EgressReport, min: Severity): string {
  const esc = (t: string) => t.replace(/[|\\`*_<>[\]]/g, (c) => `\\${c}`);
  const rows = r.findings.filter(at(min));
  return [
    `### Pinhole outbound: ${r.open} of ${r.interfaces} interfaces reach the internet, ${r.wide} on any port`,
    '',
    '| Severity | Server | Traffic | To | Through |',
    '| --- | --- | --- | --- | --- |',
    ...rows.map((f) => `| ${f.severity} | ${esc(f.resourceName)} | ${ports(f)} | ${esc(f.destinations.slice(0, 2).join(', '))} | ${esc(f.via.gateway)} |`),
    '',
  ].join('\n');
}

export const egressFailsAt = (r: EgressReport, level: Severity) => r.findings.filter(at(level)).length;
