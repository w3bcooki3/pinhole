/**
 * Exposure report as SARIF 2.1.0 (for GitHub code scanning and other SARIF
 * viewers) and as Markdown (for tickets and pull request comments).
 */
import { createHash } from 'node:crypto';
import { categorize, serviceName, SEVERITY_ORDER } from '@pinhole/engine';
import type { ExposureFinding, ExposureReport, ServiceCategory, Severity, Snapshot } from '@pinhole/engine';

const HOME = 'https://github.com/w3bcooki3/pinhole';

const RULES: Record<ServiceCategory, { name: string; short: string; help: string }> = {
  admin: { name: 'RemoteAdministrationExposed', short: 'Remote administration reachable from the internet', help: 'SSH, RDP, VNC, WinRM, SMB and similar services give direct control of a server. Allow them only from known addresses, or use AWS Systems Manager Session Manager instead of opening a port.' },
  data: { name: 'DataStoreExposed', short: 'Database or cache reachable from the internet', help: 'Databases and caches should be reached only by the applications that use them. Remove the rule that lets the internet in, or limit it to the application security group.' },
  control: { name: 'ControlPlaneExposed', short: 'Cluster control plane reachable from the internet', help: 'Kubernetes, Docker and similar control planes can run code on the cluster. Limit them to administrator addresses or a private network.' },
  wide: { name: 'WidePortRangeExposed', short: 'Wide port range reachable from the internet', help: 'A rule that opens many ports exposes every service that listens on them, including ones added later. Open only the ports the service needs.' },
  other: { name: 'ServiceExposed', short: 'Service reachable from the internet', help: 'Check that this service is meant to be public, and limit the sources if not.' },
  web: { name: 'WebServiceExposed', short: 'Web service reachable from the internet', help: 'HTTP and HTTPS are usually meant to be public. Check that the service behind it is the one intended.' },
};
const ORDER: ServiceCategory[] = ['admin', 'data', 'control', 'wide', 'other', 'web'];
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

const portText = (f: ExposureFinding) => (f.protocol === 'icmp' || f.protocol === 'all' ? f.protocol : `${f.protocol}/${f.ports.from === f.ports.to ? f.ports.from : `${f.ports.from}-${f.ports.to}`}`);
const allInternet = (f: ExposureFinding) => /^(0\.0\.0\.0\/0|::\/0) \(/.test(f.sourceRanges[0] ?? '');
const rulesOf = (f: ExposureFinding) => [...new Set(f.trace.flatMap((h) => (h.stage === 'dest-sg-ingress' || h.stage === 'dest-nacl-ingress' ? (h.ruleIds ?? []).map((r) => r.replace(/^(.+)#(?:ingress|egress)#(\d+)$/, '$1 #$2')) : [])))];

function sentence(f: ExposureFinding): string {
  const who = allInternet(f) ? `Anyone on the internet${f.family === 'ipv6' ? ' over IPv6' : ''}` : `Clients in ${f.sources.join(', ')}`;
  const svc = serviceName(f.protocol, f.ports);
  const where = f.kind === 'load-balancer' ? `load balancer ${f.resourceName}${f.listener ? ` (listener ${f.listener.protocol}:${f.listener.port})` : ''}` : f.resourceName;
  const ip = f.publicIps.length ? ` at ${f.family === 'ipv6' ? 'IPv6 address ' : ''}${f.publicIps.join(', ')}` : '';
  const rules = rulesOf(f);
  return `${who} can open ${svc ? `${svc} (${portText(f)})` : portText(f)} on ${where}${ip}.${rules.length ? ` Allowed by ${rules.join(', ')}.` : ''}`;
}

export function exposureSarif(report: ExposureReport, snap: Snapshot, file: string, version: string, minSeverity: Severity = 'info'): string {
  const min = SEVERITY_ORDER.indexOf(minSeverity);
  const findings = report.findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= min);
  const uri = file.replace(/\\/g, '/');
  const results = findings.map((f) => {
    const cat = categorize(f.protocol, f.ports);
    const key = [snap.accountId ?? '', snap.region ?? '', f.resourceId, f.protocol, f.ports.from, f.ports.to, f.listener?.port ?? '', ...(f.family ? [f.family] : [])].join('|');
    return {
      ruleId: `pinhole/${cat}`,
      ruleIndex: ORDER.indexOf(cat),
      level: LEVEL[f.severity],
      message: { text: sentence(f) },
      locations: [
        {
          physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } },
          logicalLocations: [{ name: f.resourceId, fullyQualifiedName: [snap.accountId, snap.region, f.vpcId, f.resourceId].filter(Boolean).join('/'), kind: 'resource' }],
        },
      ],
      // Stable across runs, so code scanning tracks one alert per exposed service.
      partialFingerprints: { 'pinholeExposure/v1': createHash('sha256').update(key).digest('hex') },
      properties: { severity: f.severity, 'security-severity': SECURITY_SEVERITY[f.severity], resource: f.resourceName, resourceId: f.resourceId, vpcId: f.vpcId, protocol: f.protocol, ports: f.ports, sources: f.sources, publicIps: f.publicIps, rules: rulesOf(f) },
    };
  });
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Pinhole',
            version,
            semanticVersion: version,
            informationUri: HOME,
            rules: ORDER.map((c) => ({
              id: `pinhole/${c}`,
              name: RULES[c].name,
              shortDescription: { text: RULES[c].short },
              fullDescription: { text: `${RULES[c].short}. ${RULES[c].help}` },
              help: { text: RULES[c].help, markdown: `${RULES[c].help}\n\nSee [how Pinhole decides](${HOME}/blob/main/docs/model.md).` },
              helpUri: `${HOME}#what-it-reports`,
              defaultConfiguration: { level: c === 'web' ? 'note' : c === 'other' ? 'warning' : 'error' },
              properties: { tags: ['security', 'network', 'aws'], precision: 'very-high', 'security-severity': c === 'web' ? '3.0' : c === 'other' ? '5.5' : '9.5' },
            })),
          },
        },
        automationDetails: { id: `pinhole/exposure/${snap.accountId ?? 'unknown'}/${snap.region ?? 'unknown'}/` },
        ...(snap.collectedAt ? { properties: { collectedAt: snap.collectedAt } } : {}),
        results,
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

/** Markdown summary of an exposure report. Cell text is escaped. */
export function exposureMarkdown(report: ExposureReport, snap: Snapshot, minSeverity: Severity = 'info'): string {
  const cell = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[<>]/g, (c) => (c === '<' ? '&lt;' : '&gt;')).replace(/[\r\n]+/g, ' ');
  const min = SEVERITY_ORDER.indexOf(minSeverity);
  const findings = report.findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= min);
  const count = (s: Severity) => report.findings.filter((f) => f.severity === s).length;
  const out: string[] = [];
  out.push(`### Pinhole: internet exposure in ${cell(snap.accountId ?? 'unknown account')} ${cell(snap.region ?? '')}`);
  out.push('');
  out.push(report.findings.length ? `**${report.findings.length} service${report.findings.length === 1 ? '' : 's'} reachable from the internet:** ${SEVERITY_ORDER.filter((s) => s !== 'info').map((s) => `${count(s)} ${s}`).join(', ')}.` : '**Nothing is reachable from the internet.**');
  if (snap.collectedAt) out.push(`Snapshot collected ${cell(snap.collectedAt)}.`);
  out.push('');
  if (findings.length) {
    out.push('| Severity | Resource | Service | Open to | Allowed by |');
    out.push('|---|---|---|---|---|');
    for (const f of findings) {
      const svc = serviceName(f.protocol, f.ports);
      out.push(`| ${f.severity} | ${cell(f.resourceName)} | ${cell(`${portText(f)}${svc ? ` ${svc}` : ''}`)} | ${cell(allInternet(f) ? 'any address' : f.sources.join(', '))} | ${cell(rulesOf(f).join(', '))} |`);
    }
    out.push('');
  }
  if (report.warnings.length) out.push(`_${report.warnings.length} coverage note${report.warnings.length === 1 ? '' : 's'}: parts of the network were not analysed. Run \`pinhole validate\` for details._\n`);
  return `${out.join('\n')}\n`;
}
