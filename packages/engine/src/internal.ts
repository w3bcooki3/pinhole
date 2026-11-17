/**
 * Internal traffic: what interfaces inside the estate can open to each other,
 * and what a change would cut.
 *
 * A fix that closes an internet exposure can also cut traffic that something
 * inside the network relies on: a load balancer reaching its targets, a health
 * check, an application server reaching its database through a rule that
 * names its security group, a bastion reaching a host through a wide rule.
 * This module measures that exactly. For every pair of interfaces a change can
 * affect, it runs the same service reachability as attack chains (reach.ts)
 * before and after, and reports every protocol and port range that is lost.
 *
 * Each lost range carries the evidence that it is wanted:
 *  - load-balancer: a load balancer node reaching a registered target on its
 *    traffic port;
 *  - health-check: the same, on a separate health check port;
 *  - group-reference: a rule that names the source's security group, which
 *    someone wrote on purpose;
 *  - network: allowed by an address range only. It may or may not be used;
 *    the snapshot cannot tell.
 */
import { parseIpv4 } from './ipv4.js';
import { reachServices, serviceLabel } from './reach.js';
import { reachBetween } from './blast.js';
import type { PairReach } from './reach.js';
import { displayName, eniByPrivateIp, isElbNode, naclForSubnet, routeTableForSubnet } from './topology.js';
import type { Change } from './whatif.js';
import type { Eni, NetworkModel, PortRange, SgRule } from './types.js';

export type Evidence = 'load-balancer' | 'health-check' | 'group-reference' | 'network';

export interface InternalFlow {
  from: string;
  fromName: string;
  to: string;
  toName: string;
  protocol: string;
  ports?: PortRange;
  evidence: Evidence;
  /** Why the flow is believed to be wanted, in words. */
  note: string;
}

export interface Breakage {
  flow: InternalFlow;
  /** Port ranges of the flow that no longer get through (the whole flow when `closed`). */
  lost: PortRange[];
  closed: boolean;
}

/** Evidence that is strong enough to call a lost flow a break, not just a cut. */
export const isWanted = (b: Breakage | InternalFlow) => ('flow' in b ? b.flow : b).evidence !== 'network';

/** Interfaces that never start connections of their own. */
const NOT_A_SOURCE = new Set(['nat_gateway', 'vpc_endpoint', 'transit_gateway', 'gateway_load_balancer_endpoint']);
/** Interfaces that never take new inbound connections worth reporting (load balancer nodes do). */
const NOT_A_DEST = new Set(['nat_gateway', 'vpc_endpoint', 'transit_gateway', 'gateway_load_balancer_endpoint', 'lambda', 'global_accelerator_managed']);

export const canSend = (e: Eni) => !NOT_A_SOURCE.has(e.interfaceType) && e.privateIps.length > 0;
export const canTake = (e: Eni) => !NOT_A_DEST.has(e.interfaceType) || isElbNode(e);

// Pair results depend only on the model, and fixes are tried many times on the same one.
const cache = new WeakMap<NetworkModel, Map<string, PairReach>>();
export function pairReach(model: NetworkModel, from: string, to: string): PairReach {
  let m = cache.get(model);
  if (!m) cache.set(model, (m = new Map()));
  const k = `${from}>${to}`;
  let r = m.get(k);
  if (!r) m.set(k, (r = reachServices(model, from, to)));
  return r;
}

function ruleIndex(model: NetworkModel): Map<string, SgRule> {
  const idx = new Map<string, SgRule>();
  for (const g of model.securityGroups.values()) for (const r of g.ingress) idx.set(r.id, r);
  return idx;
}

/** The target ports a load balancer node sends to on `dst`: traffic ports and health check ports. */
function lbPorts(model: NetworkModel, node: Eni, dst: Eni): { lb: string; port: number; protocol: string; health: boolean }[] {
  const out: { lb: string; port: number; protocol: string; health: boolean }[] = [];
  for (const lb of model.loadBalancers.values()) {
    if (!lb.nodeEniIds.includes(node.id)) continue;
    const tgs = new Set(model.listeners.filter((l) => l.loadBalancerArn === lb.arn).flatMap((l) => l.targetGroupArns));
    for (const arn of tgs) {
      const tg = model.targetGroups.get(arn);
      if (!tg) continue;
      const p = (tg.protocol ?? 'TCP').toUpperCase();
      const protos = p === 'UDP' ? ['udp'] : p === 'TCP_UDP' ? ['tcp', 'udp'] : ['tcp'];
      for (const t of tg.targets) {
        const eni =
          tg.targetType === 'instance' ? model.enis.get(model.instances.get(t.id)?.primaryEniId ?? '') : tg.targetType === 'ip' ? safeEni(model, t.id) : undefined;
        if (eni?.id !== dst.id) continue;
        const port = t.port ?? tg.port;
        if (port === undefined) continue;
        for (const protocol of protos) out.push({ lb: lb.name, port, protocol, health: false });
        const hc = tg.healthCheckPort && tg.healthCheckPort !== 'traffic-port' ? Number(tg.healthCheckPort) : undefined;
        // Health checks are TCP (or HTTP/HTTPS over TCP) even for UDP target groups.
        if (hc !== undefined && Number.isFinite(hc) && hc !== port) out.push({ lb: lb.name, port: hc, protocol: 'tcp', health: true });
      }
    }
  }
  return out;
}

function safeEni(model: NetworkModel, ip: string): Eni | undefined {
  try {
    return eniByPrivateIp(model, parseIpv4(ip));
  } catch {
    return undefined;
  }
}

const inRange = (port: number, r?: PortRange) => !r || (port >= r.from && port <= r.to);

/** The flows from one pair, with evidence. */
function flowsOf(model: NetworkModel, reach: PairReach, rules: Map<string, SgRule>): InternalFlow[] {
  const src = model.enis.get(reach.from)!;
  const dst = model.enis.get(reach.to)!;
  const base = { from: src.id, fromName: displayName(model, src), to: dst.id, toName: displayName(model, dst) };
  const lb = isElbNode(src) ? lbPorts(model, src, dst) : [];
  const out: InternalFlow[] = [];
  for (const s of reach.services) {
    for (const p of lb) {
      if (p.protocol !== s.protocol || !inRange(p.port, s.ports)) continue;
      out.push({ ...base, protocol: s.protocol, ports: { from: p.port, to: p.port }, evidence: p.health ? 'health-check' : 'load-balancer', note: p.health ? `${p.lb} health checks on ${p.port}` : `${p.lb} sends traffic to this target on ${p.port}` });
    }
    const ids = s.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? [];
    const ref = ids.map((id) => rules.get(id)).find((r) => r?.referencedGroupId && src.groupIds.includes(r.referencedGroupId));
    out.push({
      ...base,
      protocol: s.protocol,
      ...(s.ports ? { ports: { ...s.ports } } : {}),
      evidence: ref ? 'group-reference' : 'network',
      note: ref ? `${ref.id} allows ${ref.referencedGroupId}, a group of ${base.fromName}` : ids.length ? `allowed by ${ids.join(', ')}` : 'no security group on the destination',
    });
  }
  return out;
}

/** Changes that act only on the interfaces they touch: a pair between untouched interfaces is unchanged. */
const LOCAL_KINDS = new Set(['revoke-sg-rule', 'edit-sg-rule', 'add-sg-rule', 'add-nacl-entry', 'remove-nacl-entry', 'associate-nacl', 'attach-sg', 'detach-sg', 'remove-public-ip', 'add-public-ip', 'create-sg', 'add-listener', 'remove-listener']);

/**
 * Seeds the pair cache of a model made by `applyChanges` with the results of
 * the model it came from, for every pair the changes cannot affect. A pair's
 * result depends only on the two interfaces' security groups, subnets,
 * network ACLs and routes; security group and network ACL changes reach only
 * the interfaces that use them. Route and gateway changes can affect paths
 * between any two interfaces, so nothing is inherited for those.
 */
export function inheritPairs(before: NetworkModel, after: NetworkModel, changes: Change[]): void {
  const from = cache.get(before);
  if (!from?.size || !changes.every((c) => LOCAL_KINDS.has(c.kind))) return;
  const touched = touchedInterfaces(before, changes);
  for (const id of touchedInterfaces(after, changes)) touched.add(id);
  const to = new Map<string, PairReach>();
  for (const [k, v] of from) if (!touched.has(v.from) && !touched.has(v.to)) to.set(k, v);
  cache.set(after, to);
}

/** Interfaces whose inbound or outbound traffic a change can affect. */
export function touchedInterfaces(model: NetworkModel, changes: Change[]): Set<string> {
  const groups = new Set<string>();
  const subnets = new Set<string>();
  const enis = new Set<string>();
  const tables = new Set<string>();
  const ruleGroup = new Map<string, string>();
  for (const g of model.securityGroups.values()) for (const r of [...g.ingress, ...g.egress]) ruleGroup.set(r.id, g.id);
  for (const c of changes) {
    switch (c.kind) {
      case 'revoke-sg-rule':
      case 'edit-sg-rule': {
        const g = ruleGroup.get(c.ruleId);
        if (g) groups.add(g);
        break;
      }
      case 'add-sg-rule':
        groups.add(c.groupId);
        break;
      case 'attach-sg':
      case 'detach-sg':
        enis.add(c.eniId);
        break;
      case 'add-nacl-entry':
      case 'remove-nacl-entry':
        for (const s of model.subnets.values()) if (naclForSubnet(model, s)?.id === c.naclId) subnets.add(s.id);
        break;
      case 'associate-nacl':
      case 'associate-route-table':
        subnets.add(c.subnetId);
        break;
      case 'add-route':
      case 'remove-route':
      case 'set-main-route-table':
        tables.add(c.routeTableId);
        break;
      default:
        // Public IPs, internet gateways and listeners do not carry traffic between private addresses.
        break;
    }
  }
  if (tables.size) for (const s of model.subnets.values()) if (tables.has(routeTableForSubnet(model, s)?.id ?? '')) subnets.add(s.id);
  for (const c of changes) {
    if (c.kind !== 'set-main-route-table') continue;
    const explicit = new Set([...model.routeTables.values()].flatMap((t) => t.subnetIds));
    for (const s of model.subnets.values()) if (s.vpcId === c.vpcId && !explicit.has(s.id)) subnets.add(s.id);
  }
  for (const e of model.enis.values()) if (subnets.has(e.subnetId) || e.groupIds.some((g) => groups.has(g))) enis.add(e.id);
  return enis;
}

/** Every pair a change to `touched` can affect: anything into a touched interface, and anything out of one. */
function pairs(model: NetworkModel, touched: Set<string>): [string, string][] {
  const all = [...model.enis.values()];
  const out = new Map<string, [string, string]>();
  for (const id of touched) {
    const t = model.enis.get(id);
    if (!t) continue;
    if (canTake(t)) for (const s of all) if (s.id !== t.id && canSend(s)) out.set(`${s.id}>${t.id}`, [s.id, t.id]);
    if (canSend(t)) for (const d of all) if (d.id !== t.id && canTake(d)) out.set(`${t.id}>${d.id}`, [t.id, d.id]);
  }
  return [...out.values()];
}

/** Internal flows into or out of the given interfaces. */
export function internalFlows(model: NetworkModel, touched: Set<string>): InternalFlow[] {
  const rules = ruleIndex(model);
  return pairs(model, touched).flatMap(([a, b]) => flowsOf(model, pairReach(model, a, b), rules));
}

function subtract(range: PortRange, keep: PortRange[]): PortRange[] {
  let left: PortRange[] = [{ ...range }];
  for (const k of keep) {
    const next: PortRange[] = [];
    for (const r of left) {
      if (k.to < r.from || k.from > r.to) next.push(r);
      else {
        if (k.from > r.from) next.push({ from: r.from, to: k.from - 1 });
        if (k.to < r.to) next.push({ from: k.to + 1, to: r.to });
      }
    }
    left = next;
  }
  return left;
}

/**
 * Internal traffic that `changes` would cut, measured exactly: every flow into
 * or out of an interface the changes touch, before and after.
 */
export function internalBreaks(before: NetworkModel, after: NetworkModel, changes: Change[]): Breakage[] {
  const touched = touchedInterfaces(before, changes);
  for (const id of touchedInterfaces(after, changes)) touched.add(id);
  if (!touched.size) return [];
  const rules = ruleIndex(before);
  const out: Breakage[] = [];
  for (const [a, b] of pairs(before, touched)) {
    const r0 = reachBetween(before, a, b);
    if (!r0.services.length) continue;
    const r1 = after.enis.has(a) && after.enis.has(b) ? reachBetween(after, a, b) : { services: [] as PairReach['services'] };
    for (const flow of flowsOf(before, r0, rules)) {
      const still = r1.services.filter((s) => s.protocol === flow.protocol);
      if (!flow.ports) {
        if (!still.length) out.push({ flow, lost: [], closed: true });
        continue;
      }
      const lost = subtract(flow.ports, still.map((s) => s.ports ?? { from: 0, to: 65535 }));
      if (lost.length) out.push({ flow, lost, closed: lost.length === 1 && lost[0]!.from === flow.ports.from && lost[0]!.to === flow.ports.to });
    }
  }
  return out;
}

/** "web-1 → db-1 tcp/5432 (app-sg rule)" */
export function describeBreak(b: Breakage): string {
  const ports = b.closed || !b.flow.ports ? serviceLabel(b.flow) : b.lost.map((p) => serviceLabel({ protocol: b.flow.protocol, ports: p })).join(', ');
  return `${b.flow.fromName} → ${b.flow.toName} ${ports}: ${b.flow.note}`;
}

/** Wanted breaks first, then network cuts; at most one line per pair and protocol. */
export function summarizeBreaks(list: Breakage[]): { wanted: Breakage[]; network: Breakage[]; pairs: number } {
  const wanted = list.filter(isWanted);
  const network = list.filter((b) => !isWanted(b));
  return { wanted, network, pairs: new Set(list.map((b) => `${b.flow.from}>${b.flow.to}`)).size };
}
