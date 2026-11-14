/**
 * Drift: what changed between two snapshots of the same account and region.
 *
 * Two views, because they answer different questions:
 * - exposure: what the internet, and an attacker inside, can reach now that
 *   it could not before (and the reverse). This is the one to alert on.
 * - config: the rule, route and address changes that explain it, so a
 *   reviewer can find the change and the person who made it.
 */
import { analyzeBlastRadius } from './blast.js';
import { analyzeExposure } from './exposure.js';
import { hasPorts, protocolName } from './packet.js';
import type { NetworkModel, NaclEntry, Route } from './types.js';
import { diffExposure, ruleText } from './whatif.js';
import type { ExposureDiff } from './whatif.js';

export type ConfigKind = 'security group' | 'security group rule' | 'network ACL entry' | 'network ACL association' | 'route' | 'public IP' | 'interface security groups' | 'internet gateway' | 'load balancer' | 'listener';

export interface ConfigChange {
  kind: ConfigKind;
  change: 'added' | 'removed' | 'changed';
  /** The resource that changed, e.g. a rule ID or "acl-1 inbound #100". */
  id: string;
  /** Where it lives, in words: "sg-web (web)", "rtb-public". */
  where: string;
  before?: string;
  after?: string;
}

export interface SnapshotDiff {
  accountId?: string;
  region?: string;
  exposure: ExposureDiff;
  config: ConfigChange[];
}

export class DriftError extends Error {}

/**
 * Compare two models of the same account and region. Throws DriftError when
 * they are not, because IDs would not line up and every resource would look
 * both removed and added.
 */
export function diffSnapshots(before: NetworkModel, after: NetworkModel): SnapshotDiff {
  if (before.accountId && after.accountId && before.accountId !== after.accountId) throw new DriftError(`The snapshots are of different accounts (${before.accountId} and ${after.accountId}).`);
  if (before.region && after.region && before.region !== after.region) throw new DriftError(`The snapshots are of different regions (${before.region} and ${after.region}).`);
  const eb = analyzeExposure(before);
  const ea = analyzeExposure(after);
  const exposure = diffExposure(eb, ea, { before: analyzeBlastRadius(before, eb), after: analyzeBlastRadius(after, ea) });
  return { accountId: after.accountId ?? before.accountId, region: after.region ?? before.region, exposure, config: configChanges(before, after) };
}

function compare<T>(out: ConfigChange[], kind: ConfigKind, a: Map<string, T>, b: Map<string, T>, text: (x: T) => string, where: (x: T) => string, label: (key: string) => string = (k) => k): void {
  for (const [k, x] of a) {
    const y = b.get(k);
    if (!y) out.push({ kind, change: 'removed', id: label(k), where: where(x), before: text(x) });
    else if (text(x) !== text(y)) out.push({ kind, change: 'changed', id: label(k), where: where(y), before: text(x), after: text(y) });
  }
  for (const [k, y] of b) if (!a.has(k)) out.push({ kind, change: 'added', id: label(k), where: where(y), after: text(y) });
}

const groupLabel = (m: NetworkModel, id: string) => {
  const g = m.securityGroups.get(id);
  return g && g.name && g.name !== id ? `${id} (${g.name})` : id;
};
const eniLabel = (m: NetworkModel, id: string) => {
  const e = m.enis.get(id);
  const inst = e?.instanceId ? m.instances.get(e.instanceId) : undefined;
  return inst?.name ? `${id} (${inst.name})` : e?.instanceId ? `${id} (${e.instanceId})` : id;
};
const naclText = (e: NaclEntry) => {
  const proto = protocolName(e.protocol);
  const ports = hasPorts(e.protocol) && e.portRange ? (e.portRange.from === e.portRange.to ? `/${e.portRange.from}` : `/${e.portRange.from}-${e.portRange.to}`) : '';
  return `${e.action} ${proto === 'all' ? 'all traffic' : proto}${ports} ${e.egress ? 'to' : 'from'} ${e.cidr?.text ?? e.ipv6CidrText ?? '?'}`;
};
const routeKey = (r: Route) => r.destination?.text ?? r.destinationPrefixListId ?? '?';
const routeText = (r: Route) => `${routeKey(r)} -> ${r.target.id}${r.state === 'blackhole' ? ' (blackhole)' : ''}`;

function configChanges(a: NetworkModel, b: NetworkModel): ConfigChange[] {
  const out: ConfigChange[] = [];
  compare(out, 'security group', a.securityGroups, b.securityGroups, (g) => g.name, (g) => g.vpcId);

  const rules = (m: NetworkModel) => {
    const r = new Map<string, { text: string; where: string }>();
    for (const g of m.securityGroups.values()) for (const x of [...g.ingress, ...g.egress]) r.set(x.id, { text: ruleText(x), where: groupLabel(m, g.id) });
    return r;
  };
  compare(out, 'security group rule', rules(a), rules(b), (x) => x.text, (x) => x.where);

  const nacl = (m: NetworkModel) => {
    const r = new Map<string, { text: string; where: string }>();
    for (const n of m.nacls.values()) for (const e of n.entries) if (e.ruleNumber < 32767) r.set(`${n.id} ${e.egress ? 'outbound' : 'inbound'} #${e.ruleNumber}`, { text: naclText(e), where: n.id });
    return r;
  };
  compare(out, 'network ACL entry', nacl(a), nacl(b), (x) => x.text, (x) => x.where);

  const assoc = (m: NetworkModel) => new Map([...m.nacls.values()].map((n) => [n.id, { text: [...n.subnetIds].sort().join(', ') || 'no subnets', where: n.vpcId }]));
  compare(out, 'network ACL association', assoc(a), assoc(b), (x) => x.text, (x) => x.where);

  const routes = (m: NetworkModel) => {
    const r = new Map<string, { text: string; where: string }>();
    for (const t of m.routeTables.values()) for (const x of t.routes) if (x.origin !== 'local') r.set(`${t.id} ${routeKey(x)}`, { text: routeText(x), where: t.id });
    return r;
  };
  compare(out, 'route', routes(a), routes(b), (x) => x.text, (x) => x.where);

  const ips = (m: NetworkModel) => {
    const r = new Map<string, { text: string; where: string }>();
    for (const e of m.enis.values()) for (const p of e.publicAddresses) r.set(`${e.id} ${p.publicIp}`, { text: `${p.publicIp} -> ${p.privateIp}${p.elastic ? ' (Elastic IP)' : ''}`, where: eniLabel(m, e.id) });
    return r;
  };
  compare(out, 'public IP', ips(a), ips(b), (x) => x.text, (x) => x.where, (k) => k.split(' ')[1]!);

  const sgs = (m: NetworkModel) => new Map([...m.enis.values()].map((e) => [e.id, { text: [...e.groupIds].sort().join(', '), where: eniLabel(m, e.id) }]));
  const ea = sgs(a);
  const eb = sgs(b);
  for (const [k, x] of ea) {
    const y = eb.get(k);
    if (y && y.text !== x.text) out.push({ kind: 'interface security groups', change: 'changed', id: k, where: y.where, before: x.text, after: y.text });
  }

  compare(out, 'internet gateway', a.internetGateways, b.internetGateways, (g) => (g.vpcId ? `attached to ${g.vpcId}` : 'detached'), (g) => g.vpcId ?? '');
  compare(out, 'load balancer', a.loadBalancers, b.loadBalancers, (l) => `${l.type} ${l.scheme}`, (l) => l.name, (k) => b.loadBalancers.get(k)?.name ?? a.loadBalancers.get(k)?.name ?? k);
  const lbName = (arn: string) => b.loadBalancers.get(arn)?.name ?? a.loadBalancers.get(arn)?.name ?? arn;
  const listeners = (m: NetworkModel) => new Map(m.listeners.map((l) => [`${lbName(l.loadBalancerArn)} :${l.port}`, l]));
  compare(out, 'listener', listeners(a), listeners(b), (l) => `${l.protocol}:${l.port}`, (l) => lbName(l.loadBalancerArn));

  const order: Record<ConfigChange['change'], number> = { added: 0, changed: 1, removed: 2 };
  return out.sort((x, y) => order[x.change] - order[y.change] || x.kind.localeCompare(y.kind) || x.id.localeCompare(y.id));
}
