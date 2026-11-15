/** `pinhole privatelink`: who can reach this account's services through PrivateLink, and what its endpoints let through. */
import { SEVERITY_ORDER } from '@pinhole/engine';
import type { PrivateLinkReport, Severity } from '@pinhole/engine';

const at = (min: Severity) => (x: { severity: Severity }) => SEVERITY_ORDER.indexOf(x.severity) <= SEVERITY_ORDER.indexOf(min);
const FILTER = { 'no-security-groups': 'no security groups', 'rules-off-for-privatelink': 'security groups not applied to PrivateLink', 'security-groups': 'security groups' } as const;

export function privateLinkText(r: PrivateLinkReport, min: Severity, verbose: boolean): string {
  const lines = ['Pinhole PrivateLink report', ''];
  const services = r.services.filter(at(min));
  lines.push(`Endpoint services this account provides: ${r.services.length}`);
  if (!r.services.length) lines.push('  none');
  for (const s of services) {
    lines.push('', `[${s.severity.toUpperCase()}] ${s.name} (${s.id})`);
    lines.push(`  who may connect: ${s.open ? 'every AWS account' : s.principals ? (s.principals.length ? s.principals.join(', ') : 'nobody') : 'not collected'}${s.acceptanceRequired ? ', with your approval' : ', without approval'}`);
    const conns = s.consumers.map((c) => `${c.endpointId} (${c.owner}${c.region ? `, ${c.region}` : ''}, ${c.state})`);
    lines.push(`  connected:       ${conns.length ? conns.join('; ') : 'none'}`);
    if (s.remoteRegions.length) lines.push(`  other Regions:   ${s.remoteRegions.join(', ')}`);
    for (const l of s.listeners) {
      const reach = l.targets.map((t) => `${t.targetId}:${t.port} ${t.verdict}`).join(', ') || 'no targets';
      lines.push(`  ${l.protocol}/${l.port} on ${l.loadBalancer}: consumers from ${l.consumers.length ? l.consumers.join(', ') : 'no address'} (${FILTER[l.filter]}) -> ${reach}`);
      if (verbose) for (const t of l.targets) for (const h of t.hops) lines.push(`      ${h.stage.padEnd(18)} ${h.decision === 'pass' ? 'ok  ' : h.decision.toUpperCase().padEnd(4)} ${h.detail}`);
    }
    lines.push(`  why:             ${s.reasons.join('; ')}`);
  }
  const eps = r.endpoints.filter(at(min));
  lines.push('', `VPC endpoints in this account: ${r.endpoints.length}`);
  for (const e of eps) {
    lines.push(`  [${e.severity.toUpperCase()}] ${e.id} ${e.type.toLowerCase()} ${e.serviceName} (${e.vpcId}), policy ${e.policy}`);
    if (e.inbound.length) lines.push(`      in: ${e.inbound.join('; ')}`);
    lines.push(`      ${e.reasons.join('; ')}`);
  }
  if (!services.length && !eps.length) lines.push('', `Nothing at or above ${min}.`);
  return `${lines.join('\n')}\n`;
}

export function privateLinkMarkdown(r: PrivateLinkReport, min: Severity): string {
  const esc = (t: string) => t.replace(/[|\\`*_<>[\]]/g, (c) => `\\${c}`);
  return [
    `### Pinhole PrivateLink: ${r.services.length} endpoint service(s), ${r.endpoints.length} VPC endpoint(s)`,
    '',
    '| Severity | Resource | Finding |',
    '| --- | --- | --- |',
    ...r.services.filter(at(min)).map((s) => `| ${s.severity} | ${esc(s.name)} | ${esc(s.reasons.join('; '))} |`),
    ...r.endpoints.filter(at(min)).map((e) => `| ${e.severity} | ${esc(`${e.id} (${e.serviceName})`)} | ${esc(e.reasons.join('; '))} |`),
    '',
  ].join('\n');
}

export const privateLinkFailsAt = (r: PrivateLinkReport, level: Severity) => [...r.services, ...r.endpoints].filter(at(level)).length;
