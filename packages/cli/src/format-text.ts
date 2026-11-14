/**
 * Plain-text exposure report. Designed to be read in a terminal or pasted into
 * a ticket: one block per finding, the most severe first, every block naming
 * the exact resources and rule IDs involved.
 */
import type { ExposureFinding, ExposureReport, Hop, Severity, Snapshot } from '@pinhole/engine';
import { SEVERITY_ORDER } from '@pinhole/engine';

const STAGE_LABEL: Record<string, string> = {
  'public-ip': 'public IP',
  igw: 'internet gateway',
  'dest-nacl-ingress': 'NACL in',
  'dest-sg-ingress': 'security group',
  'return-route': 'return route',
  'return-nacl': 'NACL return',
  'source-sg-egress': 'source SG out',
  'source-nacl-egress': 'NACL out',
  route: 'route',
  peering: 'peering',
  'tgw-attachment': 'TGW attachment',
  'tgw-route': 'TGW route',
  'tgw-nacl': 'TGW subnet NACL',
  'dest-vpc-route': 'route (dest VPC)',
  scope: 'note',
  resolve: 'resolve',
};

function portText(f: ExposureFinding): string {
  if (f.protocol === 'icmp') return 'icmp echo';
  if (f.protocol !== 'tcp' && f.protocol !== 'udp') return f.protocol;
  return f.ports.from === f.ports.to ? `${f.protocol}/${f.ports.from}` : `${f.protocol}/${f.ports.from}-${f.ports.to}`;
}

function hopLine(h: Hop): string {
  const label = (STAGE_LABEL[h.stage] ?? h.stage).padEnd(16);
  const decision = h.decision === 'pass' ? 'ok  ' : h.decision === 'info' ? '    ' : h.decision.toUpperCase().padEnd(4);
  return `      ${label} ${decision} ${h.detail}`;
}

function returnText(f: ExposureFinding): string {
  if (f.returnPath === 'all') return 'return traffic allowed for all client port ranges';
  const parts = (f.returnProfiles ?? []).map((p) => `${p.profile}: ${p.coverage}`);
  return `return traffic only partly allowed (${parts.join('; ')})`;
}

function findingBlock(f: ExposureFinding, verbose: boolean): string[] {
  const lines: string[] = [];
  const why = f.reasons.length ? ` (${f.reasons.join('; ')})` : '';
  lines.push(`[${f.severity.toUpperCase()}] ${portText(f)}${f.family === 'ipv6' ? ' over IPv6' : ''}${why}`);
  lines.push(`  resource: ${f.resourceName}`);
  if (f.kind === 'load-balancer') lines.push(`  arn:      ${f.resourceId}`);
  lines.push(`  public:   ${f.publicIps.join(', ') || '(none)'}`);
  lines.push(`  allowed:  ${f.sources.join(', ')}`);
  if (verbose || f.sourceRanges.length <= 4) {
    lines.push(`  sources:  ${f.sourceRanges.join(', ')}`);
  } else {
    lines.push(`  sources:  ${f.sourceRanges.slice(0, 4).join(', ')} and ${f.sourceRanges.length - 4} more (use --verbose)`);
  }
  lines.push(`  return:   ${returnText(f)}`);
  const sample = f.trace.find((h) => h.stage === 'dest-nacl-ingress')?.detail.match(/from (\S+)$/)?.[1];
  lines.push(`  path${sample ? ` (sample client ${sample})` : ''}:`);
  for (const h of f.trace) lines.push(hopLine(h));
  for (const t of f.targets ?? []) {
    const nodes = t.nodesTotal > 1 ? ` (${t.nodesReachable}/${t.nodesTotal} load balancer nodes)` : '';
    const where = t.blockedAt ? ` at ${STAGE_LABEL[t.blockedAt.stage] ?? t.blockedAt.stage}: ${t.blockedAt.detail}` : '';
    lines.push(`  target ${t.targetId}${t.ip && t.ip !== t.targetId ? ` (${t.ip})` : ''} port ${t.port}: ${t.verdict}${nodes}${where}`);
    for (const n of t.notes) lines.push(`    note: ${n}`);
    if (verbose) for (const h of t.hops) lines.push(`  ${hopLine(h)}`);
  }
  return lines;
}

export function formatExposureText(report: ExposureReport, snapshot: Snapshot, opts: { verbose?: boolean; minSeverity?: Severity } = {}): string {
  const min = SEVERITY_ORDER.indexOf(opts.minSeverity ?? 'info');
  const shown = report.findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= min);
  const counts = SEVERITY_ORDER.map((s) => `${report.findings.filter((f) => f.severity === s).length} ${s}`).join(', ');
  const out: string[] = [];
  out.push('Pinhole internet exposure report');
  out.push(`Snapshot: account ${snapshot.accountId ?? 'unknown'}, region ${snapshot.region ?? 'unknown'}, collected ${snapshot.collectedAt ?? 'unknown'} (${snapshot.source ?? 'unknown source'})`);
  out.push(
    `Analysed ${report.stats.interfacesAnalysed} interfaces with public IPs and ${report.stats.loadBalancersAnalysed} internet-facing load balancers.`,
  );
  out.push(`Findings: ${report.findings.length} (${counts}).${shown.length < report.findings.length ? ` Showing ${shown.length} at or above ${opts.minSeverity}.` : ''}`);
  out.push('');
  if (shown.length === 0) out.push('Nothing reachable from the internet at this severity.', '');
  for (const f of shown) out.push(...findingBlock(f, opts.verbose ?? false), '');
  if (report.warnings.length) {
    out.push(`Warnings (${report.warnings.length}): results may be incomplete where these apply.`);
    for (const w of report.warnings) out.push(`  - [${w.code}] ${w.message}${w.docUrl ? ` (${w.docUrl})` : ''}`);
    out.push('');
  }
  return out.join('\n');
}
