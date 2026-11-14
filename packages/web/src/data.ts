/**
 * Data and text helpers for the web console: analysing snapshots, demo data,
 * labels, remediation text, rule impact and resource grouping. No DOM here
 * except the small file helpers.
 */
import { analyzeBlastRadius, analyzeExposure, analyzeHygiene, findChokepoints, findFixes, normalize, planFixes, assertSnapshot, SEVERITY_ORDER } from '@pinhole/engine';
import type { AttackChain, BlastReport, Chokepoint, ExposureFinding, ExposureReport, FixCandidate, FixPlan, HygieneFinding, Hop, NetworkModel, Severity, Snapshot, Warning } from '@pinhole/engine';

declare const __DEMO__: { name: string; snapshot: unknown }[];
declare const __SCRIPT__: string;
declare const __POLICY__: string;
declare const __VERSION__: string;

export const SCRIPT = __SCRIPT__;
export const POLICY = __POLICY__;
export const VERSION = __VERSION__;
export { SEVERITY_ORDER };
export type { AttackChain, BlastReport, Chokepoint, ExposureFinding, FixCandidate, FixPlan, HygieneFinding, Hop, Severity, Warning };

export interface Snap {
  key: string;
  name: string;
  account: string;
  region: string;
  collectedAt?: string;
  model: NetworkModel;
  findings: ExposureFinding[];
  warnings: Warning[];
  stats: { interfacesWithPublicIp: number; interfacesAnalysed: number; loadBalancersAnalysed: number; cellsEvaluated: number };
}
export interface Row {
  id: string;
  f: ExposureFinding;
  snap: Snap;
}

export function analyse(value: unknown, name: string): Snap {
  assertSnapshot(value);
  const snap = value as Snapshot;
  const model = normalize(snap);
  const report = analyzeExposure(model);
  return {
    key: `${snap.accountId ?? '?'}/${snap.region ?? '?'}/${snap.collectedAt ?? name}`,
    name,
    account: snap.accountId ?? 'unknown',
    region: snap.region ?? 'unknown',
    ...(snap.collectedAt ? { collectedAt: snap.collectedAt } : {}),
    model,
    findings: report.findings,
    warnings: report.warnings,
    stats: report.stats,
  };
}

// ---------------------------------------------------------------- deeper analyses
// Blast radius and hygiene are computed on first use and kept per snapshot.

const blastCache = new WeakMap<Snap, BlastReport>();
const hygieneCache = new WeakMap<Snap, HygieneFinding[]>();
export function blastOf(snap: Snap): BlastReport {
  let b = blastCache.get(snap);
  if (!b) {
    b = analyzeBlastRadius(snap.model, reportOf(snap));
    blastCache.set(snap, b);
  }
  return b;
}
export function hygieneOf(snap: Snap): HygieneFinding[] {
  let x = hygieneCache.get(snap);
  if (!x) {
    x = analyzeHygiene(snap.model, reportOf(snap));
    hygieneCache.set(snap, x);
  }
  return x;
}

export const reportOf = (snap: Snap): ExposureReport => ({ findings: snap.findings, warnings: snap.warnings, stats: snap.stats });

const chokeCache = new WeakMap<Snap, Chokepoint[]>();
/** Rules whose removal cuts the most attack chains, proved by re-analysis. */
export function chokepointsOf(snap: Snap): Chokepoint[] {
  let c = chokeCache.get(snap);
  if (!c) {
    c = blastOf(snap).chains.length ? findChokepoints(snap.model, reportOf(snap), blastOf(snap), 12) : [];
    chokeCache.set(snap, c);
  }
  return c;
}

const planCache = new WeakMap<Snap, FixPlan>();
/** The fewest verified changes that close the critical and high exposures and chains in a snapshot. */
export function planOf(snap: Snap): FixPlan {
  let p = planCache.get(snap);
  if (!p) {
    p = planFixes(snap.model, reportOf(snap), blastOf(snap));
    planCache.set(snap, p);
  }
  return p;
}

const fixCache = new WeakMap<ExposureFinding, FixCandidate[]>();
export function fixesOf(row: Row): FixCandidate[] {
  let f = fixCache.get(row.f);
  if (!f) {
    f = findFixes(row.snap.model, row.f);
    fixCache.set(row.f, f);
  }
  return f;
}

export interface ChainRow {
  id: string;
  c: AttackChain;
  snap: Snap;
}
export const chainsOf = (snaps: Snap[]): ChainRow[] =>
  snaps
    .flatMap((snap) => blastOf(snap).chains.map((c) => ({ id: `${snap.key}#${c.id}`, c, snap })))
    .sort((a, b) => b.c.score - a.c.score || a.c.steps.length - b.c.steps.length);

export interface HygieneRow {
  id: string;
  h: HygieneFinding;
  snap: Snap;
}
export const hygieneRows = (snaps: Snap[]): HygieneRow[] =>
  snaps.flatMap((snap) => hygieneOf(snap).map((h, i) => ({ id: `${snap.key}#h${i}`, h, snap }))).sort((a, b) => sevRank(a.h.severity) - sevRank(b.h.severity));

export function parseFile(text: string, name: string): Snap {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${name} is not JSON. Load the pinhole-snapshot-….json file the collector writes.`);
  }
  return analyse(value, name);
}

export const demoSnaps = (): Snap[] => __DEMO__.map((d) => analyse(d.snapshot, d.name));
export const rowsOf = (snaps: Snap[]): Row[] =>
  snaps.flatMap((s) => s.findings.map((f, i) => ({ id: `${s.key}#${i}`, f, snap: s }))).sort(compareRows);

export const sevRank = (s: Severity) => SEVERITY_ORDER.indexOf(s);
export function compareRows(a: Row, b: Row): number {
  return sevRank(a.f.severity) - sevRank(b.f.severity) || a.f.resourceName.localeCompare(b.f.resourceName) || a.f.ports.from - b.f.ports.from;
}

export const SEV_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function service(f: ExposureFinding): string {
  if (f.protocol === 'icmp') return 'ICMP echo';
  if (f.protocol !== 'tcp' && f.protocol !== 'udp') return f.protocol;
  if (f.ports.from === 0 && f.ports.to === 65535) return `${f.protocol}/all`;
  return f.ports.from === f.ports.to ? `${f.protocol}/${f.ports.from}` : `${f.protocol}/${f.ports.from}-${f.ports.to}`;
}
export const serviceName = (f: ExposureFinding) =>
  f.ports.to - f.ports.from >= 1000 ? `${f.ports.to - f.ports.from + 1} ports` : (f.reasons.find((r) => !r.startsWith('wide'))?.replace(/ \([\d-]+\)$/, '') ?? '');
/** Risk reasons, capped so an all-ports finding stays readable. */
export const riskList = (f: ExposureFinding, max = 4) => (f.reasons.length > max ? [...f.reasons.slice(0, max), `and ${f.reasons.length - max} more`] : f.reasons);
export const riskText = (f: ExposureFinding) => riskList(f).join('; ');
export const kind = (f: ExposureFinding) => (f.kind === 'load-balancer' ? (f.resourceName.startsWith('NLB') ? 'Network Load Balancer' : 'Application Load Balancer') : 'EC2 network interface');
export const shortKind = (f: ExposureFinding) => (f.kind === 'load-balancer' ? (f.resourceName.startsWith('NLB') ? 'NLB' : 'ALB') : 'ENI');
export const openTo = (f: ExposureFinding) => (f.sourceRanges[0]?.startsWith('0.0.0.0/0') ? '0.0.0.0/0' : f.sources.join(', '));
export const isWorld = (f: ExposureFinding) => !!f.sourceRanges[0]?.startsWith('0.0.0.0/0');
export const entryPoint = (f: ExposureFinding) => (f.kind === 'load-balancer' ? f.resourceName : f.trace.find((h) => h.stage === 'igw')?.resourceId ?? 'internet gateway');

export const STAGE: Record<string, string> = {
  'public-ip': 'Public IP', igw: 'Internet gateway', 'dest-nacl-ingress': 'Network ACL (inbound)', 'dest-sg-ingress': 'Security group',
  'return-route': 'Return route', 'return-nacl': 'Network ACL (outbound)', 'source-sg-egress': 'Security group (outbound)', 'source-nacl-egress': 'Network ACL (outbound)',
  route: 'Route', peering: 'Peering', 'tgw-attachment': 'TGW attachment', 'tgw-route': 'TGW route', 'tgw-nacl': 'TGW subnet ACL',
  'dest-vpc-route': 'Route in VPC', scope: 'Note', resolve: 'Lookup',
};
export const SHORT_STAGE: Record<string, string> = {
  'public-ip': 'public ip', igw: 'igw', 'dest-nacl-ingress': 'nacl in', 'dest-sg-ingress': 'sg', 'return-route': 'route back', 'return-nacl': 'nacl out',
};

export function hopId(h: Hop): string {
  if (h.ruleIds?.length) {
    return h.ruleIds
      .map((r) => {
        const m = /^(acl-[^#]+)#(ingress|egress)#(.+)$/.exec(r);
        return m ? `${m[1]} #${m[3]}` : r;
      })
      .join(', ');
  }
  return h.resourceId;
}

export function hopDetail(h: Hop): string {
  const d = h.detail;
  let m: RegExpExecArray | null;
  switch (h.stage) {
    case 'public-ip':
      return d.replace(/^public IP /, '').replace(/^Elastic IP /, 'Elastic IP ').replace(' -> ', ' → ');
    case 'igw':
      return (m = / attached to (\S+)/.exec(d)) ? `attached to ${m[1]}` : d;
    case 'dest-nacl-ingress':
    case 'tgw-nacl':
      return (m = / (allows|denies) (\S+)/.exec(d)) ? `${m[1]} ${m[2]}` : d;
    case 'dest-sg-ingress':
      return h.decision === 'pass' && (m = /^inbound (\S+)/.exec(d)) ? `allows ${m[1]}` : d;
    case 'return-route':
      return (m = /^[^:]+: (.*)$/.exec(d)) ? m[1]!.replace(' -> ', ' → ') : d;
    case 'return-nacl':
      return (m = /ports (.+?) of /.exec(d)) ? `client ports ${m[1]}` : d;
    default:
      return d;
  }
}

/** The hops worth showing on a path (drops informational notes). */
export const pathHops = (f: ExposureFinding) => f.trace.filter((h) => h.stage !== 'scope');

export function remediation(f: ExposureFinding, model: NetworkModel): string[] {
  const out: string[] = [];
  const sg = f.trace.find((x) => x.stage === 'dest-sg-ingress');
  const rules = (sg?.ruleIds ?? []).map((id) => {
    for (const g of model.securityGroups.values()) if (g.ingress.some((r) => r.id === id)) return `${id} in ${g.id}${g.name !== g.id ? ` (${g.name})` : ''}`;
    return id;
  });
  if (rules.length) out.push(`Allowed by ${rules.join(', ')}. ${isWorld(f) ? 'Restrict the source to the addresses that need access, or remove the rule.' : 'Confirm every address in the source range still needs access.'}`);
  else if (sg) out.push('No security group filters this listener. Attach a security group to the load balancer.');
  if (f.reasons.some((r) => /SSH|RDP|WinRM|VNC|Telnet/.test(r))) out.push('Use Systems Manager Session Manager or a VPN for administrative access instead of an open port.');
  if (f.reasons.some((r) => /SQL|Postgre|MySQL|Oracle|Mongo|Redis|Memcached|Elastic|Cassandra|CouchDB|Influx/.test(r))) out.push('Data stores rarely need a public address. Remove the public IP or move the resource to a private subnet.');
  if (f.returnPath === 'partial') out.push('The network ACL returns traffic only on some client port ranges, so some clients time out.');
  const blocked = (f.targets ?? []).filter((t) => t.verdict === 'blocked');
  if (blocked.length) out.push(`${plural(blocked.length, 'target')} behind this listener cannot be reached from the load balancer.`);
  return out;
}

// ---------------------------------------------------------------- files out (no network)

export function saveFile(name: string, text: string, type: string) {
  const a = document.createElement('a');
  a.download = name;
  a.href = URL.createObjectURL(new Blob([text], { type }));
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

export async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

export function csv(rows: Row[]): string {
  const cell = (v: string | number) => {
    const t = String(v);
    return `"${(/^[=+\-@\t\r]/.test(t) ? `'${t}` : t).replace(/"/g, '""')}"`;
  };
  const head = ['severity', 'account', 'region', 'kind', 'resource_id', 'resource_name', 'vpc', 'protocol', 'port_from', 'port_to', 'allowed_by', 'responses'];
  return [head.join(','), ...rows.map(({ f, snap }) => [f.severity, snap.account, snap.region, f.kind, f.resourceId, f.resourceName, f.vpcId, f.protocol, f.ports.from, f.ports.to, f.sources.join(' '), f.returnPath].map(cell).join(','))].join('\n') + '\n';
}

// ---------------------------------------------------------------- onboarding commands

export const heredoc = () => `cat > cloudshell-collect.sh <<'PINHOLE_EOF'\n${SCRIPT.replace(/\n$/, '')}\nPINHOLE_EOF\nchmod +x cloudshell-collect.sh\n`;
export const scriptLines = () => SCRIPT.split('\n').length;
export function regionList(text: string): string[] {
  return text.split(/[\s,]+/).map((x) => x.trim()).filter((x) => /^[a-z]{2}(-[a-z]+)+-\d$/.test(x));
}
export function runCommand(regions: string[]): string {
  const r = regions.length ? regions : ['us-east-1'];
  return r.length > 1 ? `for r in ${r.join(' ')}; do bash cloudshell-collect.sh "$r"; done` : `bash cloudshell-collect.sh ${r[0]}`;
}
export const cloudShellUrl = (region: string) => `https://${region}.console.aws.amazon.com/cloudshell/home?region=${region}`;
export const LIST_CMD = 'ls -1 ~/pinhole-snapshot-*.json';
export const CLEAN_CMD = 'rm -f ~/pinhole-snapshot-*.json ~/cloudshell-collect.sh';

/** The six onboarding steps, as data, so every prototype says the same thing. */
export const STEPS = [
  { title: 'Open CloudShell', body: 'Sign in to the AWS console in the account to check and open CloudShell. It already has the AWS CLI and jq and is signed in as you.' },
  { title: 'Add the collector', body: 'Paste this into the CloudShell terminal. It writes cloudshell-collect.sh to your home folder. If CloudShell asks about a multi-line paste, choose Paste.' },
  { title: 'Run it', body: 'Read-only describe calls; one JSON file per region. Nothing in the account changes.' },
  { title: 'Download the snapshot', body: 'Actions, then Download file. Paste the path the script printed. Repeat per region.' },
  { title: 'Load it here', body: 'Drop the files on this page. They are analysed in this tab and never uploaded.' },
  { title: 'Clean up (optional)', body: 'Remove the snapshots and the script from CloudShell.' },
];

/** Larger files would freeze the tab while parsing; the CLI has no such limit. */
export const MAX_SNAPSHOT_BYTES = 200_000_000;

/** More files than this in one drop is almost certainly a mistake. */
export const MAX_FILES = 200;

export function readFiles(files: FileList | File[], done: (snaps: Snap[], errors: string[]) => void) {
  const all = [...files];
  const list = all.slice(0, MAX_FILES);
  const snaps: Snap[] = [];
  const errors: string[] = all.length > MAX_FILES ? [`Only the first ${MAX_FILES} of ${all.length} files were read.`] : [];
  let left = list.length;
  if (!left) return done(snaps, errors);
  for (const file of list) {
    if (file.size > MAX_SNAPSHOT_BYTES) {
      errors.push(`${file.name} is ${Math.round(file.size / 1e6)} MB; the limit is ${MAX_SNAPSHOT_BYTES / 1e6} MB. Use the CLI for very large snapshots.`);
      if (--left === 0) done(snaps, errors);
      continue;
    }
    const r = new FileReader();
    r.onload = () => {
      try {
        snaps.push(parseFile(String(r.result), file.name));
      } catch (e) {
        const msg = (e as Error).message;
        errors.push(msg.includes(file.name) ? msg : `${file.name}: ${msg}`);
      }
      if (--left === 0) done(snaps, errors);
    };
    r.onerror = () => {
      errors.push(`Could not read ${file.name}.`);
      if (--left === 0) done(snaps, errors);
    };
    r.readAsText(file);
  }
}

// ---------------------------------------------------------------- categories

export type Category = 'admin' | 'data' | 'control' | 'web' | 'wide' | 'other';
export const CATEGORY_LABEL: Record<Category, string> = {
  admin: 'Remote administration',
  data: 'Databases and caches',
  control: 'Cluster control planes',
  web: 'Web',
  wide: 'Wide port ranges',
  other: 'Other services',
};
export function category(f: ExposureFinding): Category {
  if (f.ports.to - f.ports.from >= 1000) return 'wide';
  const why = f.reasons.join(' ');
  if (/SSH|RDP|WinRM|VNC|Telnet|MS RPC|NetBIOS|SMB/.test(why)) return 'admin';
  if (/SQL|Postgre|MySQL|Oracle|Mongo|Redis|Memcached|Elastic|Cassandra|Couch|Influx/.test(why)) return 'data';
  if (/Kubernetes|etcd|kubelet|Docker/.test(why)) return 'control';
  if (f.severity === 'low') return 'web';
  return 'other';
}

// ---------------------------------------------------------------- rule impact

export interface RuleImpact {
  key: string;
  ruleId: string;
  groupId: string;
  groupName: string;
  source: string;
  ports: string;
  snap: Snap;
  rows: Row[];
  /** Findings where this is the only security group rule letting traffic in. */
  sole: number;
  worst: Severity;
}

/**
 * Groups findings by the security group rule that admits them. Narrowing or
 * removing a rule only closes a finding when no other rule also admits it,
 * so `sole` counts those separately.
 */
export function ruleImpact(rows: Row[]): RuleImpact[] {
  const map = new Map<string, RuleImpact>();
  for (const r of rows) {
    const ids = r.f.trace.find((x) => x.stage === 'dest-sg-ingress')?.ruleIds ?? [];
    for (const id of ids) {
      const key = `${r.snap.key}|${id}`;
      let it = map.get(key);
      if (!it) {
        let groupId = '';
        let groupName = '';
        let source = '';
        let ports = '';
        for (const g of r.snap.model.securityGroups.values()) {
          const rule = g.ingress.find((x) => x.id === id);
          if (!rule) continue;
          groupId = g.id;
          groupName = g.name;
          source = rule.cidr?.text ?? rule.prefixListId ?? rule.referencedGroupId ?? '';
          const proto = rule.protocol === '-1' ? 'all' : rule.protocol === '6' ? 'tcp' : rule.protocol === '17' ? 'udp' : rule.protocol === '1' ? 'icmp' : rule.protocol;
          ports = rule.protocol === '-1' || rule.fromPort === undefined || rule.fromPort === -1 ? proto : rule.fromPort === rule.toPort ? `${proto}/${rule.fromPort}` : `${proto}/${rule.fromPort}-${rule.toPort}`;
        }
        it = { key, ruleId: id, groupId, groupName, source, ports, snap: r.snap, rows: [], sole: 0, worst: r.f.severity };
        map.set(key, it);
      }
      it.rows.push(r);
      if (ids.length === 1) it.sole += 1;
      if (sevRank(r.f.severity) < sevRank(it.worst)) it.worst = r.f.severity;
    }
  }
  return [...map.values()].sort((a, b) => sevRank(a.worst) - sevRank(b.worst) || b.sole - a.sole || b.rows.length - a.rows.length);
}

// ---------------------------------------------------------------- resources

export interface ResourceRow {
  key: string;
  name: string;
  id: string;
  kind: string;
  snap: Snap;
  vpc: string;
  publicIps: string[];
  rows: Row[];
  worst: Severity;
}
export function resources(rows: Row[]): ResourceRow[] {
  const map = new Map<string, ResourceRow>();
  for (const r of rows) {
    const key = `${r.snap.key}|${r.f.resourceId}`;
    const it = map.get(key) ?? { key, name: r.f.resourceName, id: r.f.resourceId, kind: kind(r.f), snap: r.snap, vpc: r.f.vpcId, publicIps: r.f.publicIps, rows: [], worst: r.f.severity };
    it.rows.push(r);
    if (sevRank(r.f.severity) < sevRank(it.worst)) it.worst = r.f.severity;
    map.set(key, it);
  }
  return [...map.values()].sort((a, b) => sevRank(a.worst) - sevRank(b.worst) || b.rows.length - a.rows.length || a.name.localeCompare(b.name));
}

export const shortName = (f: ExposureFinding) => f.resourceName.replace(/ \(.*\)$/, '');

/** "Collected 12 Nov 2026, 2 days ago", or a plain note when the snapshot has no time. */
export function collected(snap: Snap, now = Date.now()): { text: string; days: number | undefined } {
  if (!snap.collectedAt) return { text: 'Collection time not recorded in this snapshot', days: undefined };
  const t = Date.parse(snap.collectedAt);
  if (Number.isNaN(t)) return { text: `Collected ${snap.collectedAt}`, days: undefined };
  const days = Math.max(0, Math.floor((now - t) / 86_400_000));
  const date = new Date(t).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  return { text: `Collected ${date}, ${days === 0 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`}`, days };
}
/** Snapshots older than this are flagged: the network may have changed since. */
export const STALE_DAYS = 7;

/** One plain sentence: who can open what, where. */
export function sentence(f: ExposureFinding): string {
  const who = isWorld(f) ? 'Anyone on the internet' : `Clients in ${f.sources.join(', ')}`;
  const what = serviceName(f) ? `${serviceName(f)} (${service(f)})` : service(f);
  const where = f.kind === 'load-balancer' ? `the ${kind(f).toLowerCase()} ${shortName(f)}` : shortName(f);
  const ip = f.publicIps.length ? ` at ${f.publicIps.join(', ')}` : '';
  const back = f.returnPath === 'partial' ? ' Responses get back for some client port ranges only.' : '';
  return `${who} can open ${what} on ${where}${ip}.${back}`;
}
