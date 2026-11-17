/**
 * Fix finder: candidate changes that close an exposure finding, each one
 * proved by applying it to a copy of the model and re-running the analysis.
 *
 * Candidates, from narrowest to broadest:
 *  - narrow the rule's source to exactly what uses it inside the network
 *    (the security groups, or addresses, of the interfaces that reach the
 *    resource through that rule today);
 *  - cut the finding's ports out of a wider security group rule;
 *  - remove the security group rule(s) that let the traffic in;
 *  - add a network ACL deny for the ports, ahead of the rule that allows them;
 *  - remove the public IP.
 *
 * A fix is "verified" only if the re-analysis no longer finds any internet
 * path to the finding's resource, protocol and ports. Everything else the
 * change closes or narrows is reported too: closing another critical path is
 * a bonus; closing a web or low-severity path is collateral, because it is
 * probably traffic someone wants.
 *
 * Every candidate is also checked for the internal traffic it cuts
 * (internal.ts): a load balancer losing its targets or health checks, or a
 * connection allowed by a rule that names the source's group, is a break; a
 * connection allowed only by an address range is a cut that may or may not
 * matter. A verified fix that opens nothing and breaks nothing wanted is
 * marked safe; address-range cuts are still listed with it.
 */
import { analyzeExposure } from './exposure.js';
import type { ExposureFinding, ExposureReport } from './exposure.js';
import { hasPorts, normalizeProtocol, protocolName } from './packet.js';
import { compareSeverity } from './risk.js';
import { serviceLabel } from './reach.js';
import { INTERNET6, RangeSet6 } from './ipv6.js';
import { INTERNET, RangeSet } from './ipv4.js';
import { analyzeBlastRadius, findingKey } from './blast.js';
import type { AttackChain, BlastReport } from './blast.js';
import { naclForSubnet } from './topology.js';
import { canSend, internalBreaks, isWanted, pairReach } from './internal.js';
import type { Breakage } from './internal.js';
import { applyChanges, cliFor, describeChange, diffExposure, ruleText } from './whatif.js';
import type { Change, ExposureDelta } from './whatif.js';
import type { Eni, NetworkModel, PortRange, SgRule } from './types.js';

export interface FixCandidate {
  id: string;
  title: string;
  rationale: string;
  changes: Change[];
  steps: string[];
  cli: string[];
  /** The finding is fully closed after the change. */
  verified: boolean;
  /** Changes on the finding itself. */
  closes: ExposureDelta[];
  /** Other critical or high paths the same change closes or narrows. */
  bonus: ExposureDelta[];
  /** Other, probably wanted, paths the change also closes or narrows. */
  collateral: ExposureDelta[];
  /** Paths the change would open (should be empty). */
  opened: ExposureDelta[];
  /**
   * For a change that keeps access from inside the network: attack chains that
   * still reach this resource from another internet-facing server afterwards.
   */
  stillReachable: AttackChain[];
  /** Internal traffic the change cuts, with the evidence that it is wanted. */
  breaks: Breakage[];
  /** Verified, opens nothing, and breaks no internal traffic with evidence that it is wanted. */
  safe: boolean;
  score: number;
}

function findRule(model: NetworkModel, id: string): SgRule | undefined {
  for (const g of model.securityGroups.values()) {
    const r = g.ingress.find((x) => x.id === id);
    if (r) return r;
  }
  return undefined;
}

/** Interfaces and load balancers a change can affect, so re-analysis can be limited to them. */
function affected(model: NetworkModel, changes: Change[], finding: ExposureFinding): Set<string> {
  const ids = new Set<string>([finding.resourceId]);
  const groups = new Set<string>();
  const subnets = new Set<string>();
  for (const c of changes) {
    if (c.kind === 'revoke-sg-rule' || c.kind === 'edit-sg-rule') {
      for (const g of model.securityGroups.values()) if (g.ingress.some((r) => r.id === c.ruleId) || g.egress.some((r) => r.id === c.ruleId)) groups.add(g.id);
    }
    if (c.kind === 'add-sg-rule') groups.add(c.groupId);
    if (c.kind === 'add-nacl-entry' || c.kind === 'remove-nacl-entry') for (const s of model.nacls.get(c.naclId)?.subnetIds ?? []) subnets.add(s);
    if (c.kind === 'remove-public-ip' || c.kind === 'detach-sg') ids.add(c.eniId);
  }
  for (const e of model.enis.values()) if (subnets.has(e.subnetId) || e.groupIds.some((g) => groups.has(g))) ids.add(e.id);
  for (const lb of model.loadBalancers.values()) if (lb.securityGroupIds.some((g) => groups.has(g)) || lb.subnetIds.some((s) => subnets.has(s))) ids.add(lb.arn);
  return ids;
}

/**
 * Every interface and load balancer whose exposure a list of changes can
 * alter, or undefined when a change is of a kind that could affect anything
 * (routes, gateways), so a full analysis is needed.
 */
function exposureScope(model: NetworkModel, changes: Change[]): Set<string> | undefined {
  const ids = new Set<string>();
  const groups = new Set<string>();
  const subnets = new Set<string>();
  for (const c of changes) {
    if (c.kind === 'revoke-sg-rule' || c.kind === 'edit-sg-rule') {
      for (const g of model.securityGroups.values()) if (g.ingress.some((r) => r.id === c.ruleId) || g.egress.some((r) => r.id === c.ruleId)) groups.add(g.id);
    } else if (c.kind === 'add-sg-rule') groups.add(c.groupId);
    else if (c.kind === 'add-nacl-entry' || c.kind === 'remove-nacl-entry') {
      for (const sub of model.subnets.values()) if (naclForSubnet(model, sub)?.id === c.naclId) subnets.add(sub.id);
    } else if (c.kind === 'remove-public-ip' || c.kind === 'detach-sg' || c.kind === 'attach-sg') ids.add(c.eniId);
    else return undefined;
  }
  const enis = new Set<string>();
  for (const e of model.enis.values()) if (ids.has(e.id) || subnets.has(e.subnetId) || e.groupIds.some((g) => groups.has(g))) enis.add(e.id);
  enis.forEach((id) => ids.add(id));
  // A load balancer's finding depends on its own groups and subnets, its nodes, and its targets.
  for (const lb of model.loadBalancers.values()) {
    if (lb.securityGroupIds.some((g) => groups.has(g)) || lb.subnetIds.some((x) => subnets.has(x)) || lb.nodeEniIds.some((id) => enis.has(id))) {
      ids.add(lb.arn);
      continue;
    }
    for (const l of model.listeners) {
      if (l.loadBalancerArn !== lb.arn) continue;
      for (const tg of l.targetGroupArns.map((a) => model.targetGroups.get(a))) {
        for (const t of tg?.targets ?? []) {
          const eni = tg!.targetType === 'instance' ? model.instances.get(t.id)?.primaryEniId : [...model.enis.values()].find((e) => e.privateIps.includes(t.id))?.id;
          if (eni && enis.has(eni)) ids.add(lb.arn);
        }
      }
    }
  }
  return ids;
}

/** Exposure after `changes`, re-analysing only what they can affect and keeping every other finding. */
function exposureAfter(before: NetworkModel, after: NetworkModel, e0: ExposureReport, changes: Change[]): ExposureReport {
  const scope = exposureScope(before, changes);
  if (!scope) return analyzeExposure(after);
  const part = analyzeExposure(after, { only: scope });
  return { findings: [...e0.findings.filter((f) => !scope.has(f.resourceId)), ...part.findings], warnings: e0.warnings, stats: e0.stats };
}

const overlaps = (d: ExposureDelta, f: ExposureFinding) =>
  d.resourceId === f.resourceId && d.protocol === f.protocol && (!d.ports || (d.ports.from <= f.ports.to && d.ports.to >= f.ports.from)) && (f.listener ? d.listenerPort === f.listener.port : d.listenerPort === undefined);

/**
 * Every inbound rule on the resource's security groups that admits some
 * internet address on the finding's protocol and ports. The trace names the
 * rules for one representative packet; this finds the rest, so a fix can
 * cover all of them.
 */
export function allowingRules(model: NetworkModel, f: ExposureFinding): string[] {
  const groups = f.kind === 'interface' ? model.enis.get(f.resourceId)?.groupIds ?? [] : model.loadBalancers.get(f.resourceId)?.securityGroupIds ?? [];
  const proto = normalizeProtocol(f.protocol);
  const out: string[] = [];
  for (const gid of groups) {
    for (const r of model.securityGroups.get(gid)?.ingress ?? []) {
      if (r.protocol !== '-1' && r.protocol !== proto) continue;
      if (hasPorts(proto) && r.protocol !== '-1' && r.fromPort !== undefined && r.fromPort !== -1 && ((r.toPort ?? r.fromPort) < f.ports.from || r.fromPort > f.ports.to)) continue;
      if (f.family === 'ipv6') {
        // IPv6 findings come only from IPv6 rules that admit some internet address.
        if (r.ipv6CidrText && !INTERNET6.intersect(RangeSet6.fromCidrs([r.ipv6CidrText])).isEmpty()) out.push(r.id);
        continue;
      }
      const sources = r.cidr ? [r.cidr] : r.prefixListId ? model.prefixLists.get(r.prefixListId)?.entries ?? [] : [];
      if (sources.some((c) => !INTERNET.intersect(RangeSet.of([c])).isEmpty())) out.push(r.id);
    }
  }
  // Fall back to the trace when groups are not in the snapshot.
  return out.length ? out : (f.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? []).filter((id) => findRule(model, id));
}

/**
 * The interfaces that reach the finding's resource through `rule` and through
 * nothing else, on some protocol and port: removing the rule would cut them.
 */
function usersOf(model: NetworkModel, f: ExposureFinding | string[], rule: SgRule): Eni[] {
  const dsts = Array.isArray(f) ? f : f.kind === 'interface' ? [f.resourceId] : model.loadBalancers.get(f.resourceId)?.nodeEniIds ?? [];
  const out: Eni[] = [];
  for (const src of model.enis.values()) {
    if (!canSend(src) || dsts.includes(src.id)) continue;
    const uses = dsts.some((d) =>
      pairReach(model, src.id, d).services.some((s) => {
        const ids = s.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? [];
        return ids.length === 1 && ids[0] === rule.id;
      }),
    );
    if (uses) out.push(src);
  }
  return out;
}

/**
 * The fewest sources that keep every user of `rule`: security groups where
 * the users are in the same VPC (greedy set cover, preferring groups with no
 * members beyond the users), single addresses for the rest.
 */
function narrowSources(model: NetworkModel, users: Eni[], vpcId: string, exclude: Set<string> = new Set()): { groups: string[]; cidrs: string[] } {
  const vpcOf = (e: Eni) => model.subnets.get(e.subnetId)?.vpcId;
  const left = new Set(users.filter((u) => vpcOf(u) === vpcId && u.groupIds.length).map((u) => u.id));
  const ids = new Set(users.map((u) => u.id));
  const groups: string[] = [];
  const members = (g: string) => [...model.enis.values()].filter((e) => e.groupIds.includes(g));
  while (left.size) {
    let best: { g: string; covers: number; extra: number } | undefined;
    for (const g of new Set(users.filter((u) => left.has(u.id)).flatMap((u) => u.groupIds))) {
      const m = members(g);
      // A group with an excluded member would let it back in.
      if (m.some((e) => exclude.has(e.id))) continue;
      const covers = m.filter((e) => left.has(e.id)).length;
      const extra = m.filter((e) => !ids.has(e.id)).length;
      if (!best || covers - extra * 0.5 > best.covers - best.extra * 0.5) best = { g, covers, extra };
    }
    if (!best) break;
    groups.push(best.g);
    for (const e of members(best.g)) left.delete(e.id);
  }
  const covered = new Set(groups.flatMap((g) => members(g).map((e) => e.id)));
  const cidrs = users.filter((u) => !covered.has(u.id)).map((u) => `${u.privateIps[0]}/32`);
  return { groups, cidrs };
}

/**
 * A rule on an attack chain hop, rewritten to keep every interface that uses
 * it except the one the attacker comes from: the chain is cut and the rest of
 * the traffic keeps working.
 */
function narrowHop(model: NetworkModel, r: SgRule, dst: string, foothold: string): { title: string; rationale: string; changes: Change[] } | undefined {
  if (!r.cidr) return undefined;
  const footEni = model.enis.get(foothold);
  const users = usersOf(model, [dst], r).filter((u) => u.id !== foothold);
  if (!users.length || !footEni) return undefined;
  const { groups, cidrs } = narrowSources(model, users, model.securityGroups.get(r.groupId)?.vpcId ?? footEni.vpcId, new Set([foothold]));
  if (groups.length + cidrs.length > 8 || cidrs.some((c) => footEni.privateIps.some((ip) => `${ip}/32` === c))) return undefined;
  const ports = r.fromPort === undefined || r.fromPort === -1 ? {} : { fromPort: r.fromPort, toPort: r.toPort ?? r.fromPort };
  const proto = protocolName(r.protocol);
  return {
    title: `Allow ${r.id} only from what uses it, not ${foothold}`,
    rationale: `${r.id} allows ${ruleText(r)}. Replacing ${r.cidr.text} with ${[...groups, ...cidrs].join(', ')} keeps the ${users.length} other interface${users.length === 1 ? '' : 's'} that reach ${dst} through it and drops ${foothold}.`,
    changes: [
      { kind: 'revoke-sg-rule', ruleId: r.id },
      ...groups.map((g): Change => ({ kind: 'add-sg-rule', groupId: r.groupId, egress: false, protocol: proto, ...ports, referencedGroupId: g, ...(r.description ? { description: r.description } : {}) })),
      ...cidrs.map((c): Change => ({ kind: 'add-sg-rule', groupId: r.groupId, egress: false, protocol: proto, ...ports, cidr: c, ...(r.description ? { description: r.description } : {}) })),
    ],
  };
}

type Candidate = { title: string; rationale: string; changes: Change[]; narrow?: boolean };

function candidates(model: NetworkModel, f: ExposureFinding): Candidate[] {
  const out: Candidate[] = [];
  const ruleIds = allowingRules(model, f);
  const proto = normalizeProtocol(f.protocol);
  const label = serviceLabel(f);

  for (const id of ruleIds) {
    const r = findRule(model, id)!;
    // Least privilege: keep exactly the internal traffic that uses this rule.
    if (r.cidr && f.family !== 'ipv6') {
      const users = usersOf(model, f, r);
      const groupVpc = model.securityGroups.get(r.groupId)?.vpcId ?? f.vpcId;
      const { groups, cidrs } = users.length ? narrowSources(model, users, groupVpc) : { groups: [], cidrs: [] };
      if (users.length && groups.length + cidrs.length <= 8) {
        const ports = r.fromPort === undefined || r.fromPort === -1 ? {} : { fromPort: r.fromPort, toPort: r.toPort ?? r.fromPort };
        const proto = protocolName(r.protocol);
        const named = [...groups.map((g) => `${g}${model.securityGroups.get(g)?.name ? ` (${model.securityGroups.get(g)!.name})` : ''}`), ...cidrs];
        out.push({
          title: `Allow ${id} only from what uses it`,
          rationale: `${id} allows ${ruleText(r)}. Inside the network, ${users.length} interface${users.length === 1 ? '' : 's'} reach ${f.resourceName} through it and nothing else: ${users.slice(0, 4).map((u) => u.id).join(', ')}${users.length > 4 ? ', ...' : ''}. Replacing ${r.cidr.text} with ${named.join(', ')} keeps that traffic and closes the rule to the internet and to everything else.`,
          narrow: true,
          changes: [
            { kind: 'revoke-sg-rule', ruleId: id },
            ...groups.map((g): Change => ({ kind: 'add-sg-rule', groupId: r.groupId, egress: false, protocol: proto, ...ports, referencedGroupId: g, ...(r.description ? { description: r.description } : {}) })),
            ...cidrs.map((c): Change => ({ kind: 'add-sg-rule', groupId: r.groupId, egress: false, protocol: proto, ...ports, cidr: c, ...(r.description ? { description: r.description } : {}) })),
          ],
        });
      }
    }
    const from = r.fromPort ?? -1;
    const to = r.toPort ?? from;
    const wider = hasPorts(proto) && r.protocol === proto && from !== -1 && (from < f.ports.from || to > f.ports.to);
    if (wider) {
      const changes: Change[] = [];
      if (from < f.ports.from) changes.push({ kind: 'edit-sg-rule', ruleId: id, fromPort: from, toPort: f.ports.from - 1 });
      if (to > f.ports.to) {
        if (changes.length) changes.push({ kind: 'add-sg-rule', groupId: r.groupId, egress: false, protocol: f.protocol, fromPort: f.ports.to + 1, toPort: to, ...(r.cidr ? { cidr: r.cidr.text } : {}), ...(r.referencedGroupId ? { referencedGroupId: r.referencedGroupId } : {}), ...(r.description ? { description: r.description } : {}) });
        else changes.push({ kind: 'edit-sg-rule', ruleId: id, fromPort: f.ports.to + 1, toPort: to });
      }
      out.push({ title: `Cut ${label} out of ${id}`, rationale: `${id} allows ${ruleText(r)}. Keeping the rest of its range and dropping ${label} closes this path without touching anything else the rule allows.`, changes });
    }
    // Keep access from inside the VPC, close it to everyone else.
    const vpc = model.vpcs.get(f.vpcId);
    const inside = r.cidr && vpc?.cidrs.length && !vpc.cidrs.some((c) => c.start <= r.cidr!.start && c.end >= r.cidr!.end);
    if (inside && vpc) {
      const [first, ...rest] = vpc.cidrs;
      const ports = r.fromPort === undefined || r.fromPort === -1 ? {} : { fromPort: r.fromPort, toPort: r.toPort ?? r.fromPort };
      out.push({
        title: `Allow ${label} on ${id} only from inside ${vpc.id}`,
        rationale: `Changes the source of ${id} from ${r.cidr!.text} to ${vpc.cidrs.map((c) => c.text).join(' and ')}. Servers in the VPC keep access; the internet loses it.`,
        changes: [
          { kind: 'edit-sg-rule', ruleId: id, cidr: first!.text },
          ...rest.map((c): Change => ({ kind: 'add-sg-rule', groupId: r.groupId, egress: false, protocol: protocolName(r.protocol), ...ports, cidr: c.text, ...(r.description ? { description: r.description } : {}) })),
        ],
      });
    }
    out.push({ title: `Remove ${id}`, rationale: `${id} (${ruleText(r)}) is ${ruleIds.length > 1 ? 'one of the rules' : 'the rule'} letting this traffic in.`, changes: [{ kind: 'revoke-sg-rule', ruleId: id }] });
  }
  if (ruleIds.length > 1) {
    out.push({ title: `Remove all ${ruleIds.length} rules that allow ${label}`, rationale: `${ruleIds.join(', ')} each allow this traffic from the internet, so each must go.`, changes: ruleIds.map((ruleId) => ({ kind: 'revoke-sg-rule', ruleId })) });
    const vpc = model.vpcs.get(f.vpcId);
    if (vpc?.cidrs.length === 1 && ruleIds.every((id) => findRule(model, id)?.cidr)) {
      out.push({
        title: `Allow ${label} only from inside ${vpc.id}, on all ${ruleIds.length} rules`,
        rationale: `${ruleIds.join(', ')} each allow this traffic from the internet. Changing each source to ${vpc.cidrs[0]!.text} keeps access for servers in the VPC.`,
        changes: ruleIds.map((ruleId): Change => ({ kind: 'edit-sg-rule', ruleId, cidr: vpc.cidrs[0]!.text })),
      });
    }
  }

  // Network ACL deny, numbered just ahead of the entry that currently allows it.
  if (f.kind === 'interface' && hasPorts(proto)) {
    const eni = model.enis.get(f.resourceId);
    const subnet = eni ? model.subnets.get(eni.subnetId) : undefined;
    const acl = subnet ? naclForSubnet(model, subnet) : undefined;
    const naclHop = f.trace.find((h) => h.stage === 'dest-nacl-ingress');
    const allowing = Number(naclHop?.ruleIds?.[0]?.split('#')[2]);
    if (acl && Number.isFinite(allowing)) {
      const taken = new Set(acl.entries.filter((e) => !e.egress).map((e) => e.ruleNumber));
      let n = allowing - 1;
      while (n >= 1 && taken.has(n)) n -= 1;
      if (n >= 1) {
        out.push({
          title: `Deny ${label} in ${acl.id}`,
          rationale: `An inbound deny numbered ${n}, ahead of rule ${allowing}, blocks ${label} for every address and every interface in ${acl.subnetIds.join(', ')}, including traffic from inside the VPC.`,
          changes: [{ kind: 'add-nacl-entry', naclId: acl.id, egress: false, ruleNumber: n, action: 'deny', protocol: f.protocol, cidr: '0.0.0.0/0', fromPort: f.ports.from, toPort: f.ports.to }],
        });
      }
    }
  }

  if (f.kind === 'interface') {
    for (const ip of f.publicIps) {
      out.push({ title: `Remove public IP ${ip}`, rationale: `Without a public address nothing on the internet can start a connection to ${f.resourceName}. Reach it through a load balancer, Session Manager or a VPN instead.`, changes: [{ kind: 'remove-public-ip', eniId: f.resourceId, publicIp: ip }] });
    }
  }
  return out;
}

const SEV_WEIGHT = { critical: 8, high: 5, medium: 2, low: 1, info: 0 } as const;

/** Verified fixes for one finding, best first. */
export function findFixes(model: NetworkModel, finding: ExposureFinding): FixCandidate[] {
  const fixes: FixCandidate[] = [];
  for (const c of candidates(model, finding)) {
    let after: NetworkModel;
    try {
      after = applyChanges(model, c.changes);
    } catch {
      continue;
    }
    const only = affected(model, c.changes, finding);
    const before: ExposureReport = analyzeExposure(model, { only });
    const next: ExposureReport = analyzeExposure(after, { only });
    const diff = diffExposure(before, next);
    const verified = !next.findings.some((g) => g.resourceId === finding.resourceId && g.protocol === finding.protocol && g.ports.from <= finding.ports.to && g.ports.to >= finding.ports.from && (finding.listener ? g.listener?.port === finding.listener.port : !g.listener));
    const lost = diff.deltas.filter((d) => d.status === 'closed' || d.status === 'narrowed');
    const closes = lost.filter((d) => overlaps(d, finding));
    const others = lost.filter((d) => !overlaps(d, finding));
    const bonus = others.filter((d) => compareSeverity(d.severity, 'high') <= 0);
    const collateral = others.filter((d) => compareSeverity(d.severity, 'high') > 0);
    const opened = diff.deltas.filter((d) => d.status === 'opened' || d.status === 'widened');
    // A network ACL deny hits every interface in the subnet, and removing a public
    // IP cuts everything on the interface: prefer the targeted rule change.
    const breadth = c.changes.some((x) => x.kind === 'add-nacl-entry') ? 15 : c.changes.some((x) => x.kind === 'remove-public-ip') ? 12 : 0;
    const keepsAccess = !!c.narrow || c.changes.every((x) => x.kind === 'edit-sg-rule' || x.kind === 'add-sg-rule');
    const breaks = internalBreaks(model, after, c.changes);
    const wanted = breaks.filter(isWanted).length;
    const cutPairs = new Set(breaks.filter((x) => !isWanted(x)).map((x) => `${x.flow.from}>${x.flow.to}`)).size;
    const safe = verified && !opened.length && !wanted;
    // Restricting a rule to the VPC keeps internal access, which is the point, but
    // a compromised internet-facing server inside the VPC may then still reach it.
    let stillReachable: AttackChain[] = [];
    if (keepsAccess && verified && finding.kind !== 'load-balancer') {
      const full = analyzeExposure(after);
      stillReachable = analyzeBlastRadius(after, full).chains.filter((x) => x.targetId === finding.resourceId);
    }
    const score =
      (keepsAccess ? 3 : 0) +
      (c.narrow ? 2 : 0) +
      (safe ? 4 : 0) -
      25 * wanted -
      0.5 * Math.min(cutPairs, 6) +
      (verified ? 100 : 0) + bonus.reduce((n, d) => n + SEV_WEIGHT[d.severity], 0) - collateral.reduce((n, d) => n + 12 + SEV_WEIGHT[d.severity], 0) - 50 * opened.length - 2 * c.changes.length - breadth - 5 * stillReachable.length;
    fixes.push({
      id: c.changes.map((x) => JSON.stringify(x)).join('|'),
      title: c.title,
      rationale: c.rationale,
      changes: c.changes,
      steps: c.changes.map((x) => describeChange(model, x)),
      cli: c.changes.flatMap((x) => cliFor(model, x)),
      verified,
      closes,
      bonus,
      collateral,
      opened,
      stillReachable,
      breaks,
      safe,
      score,
    });
  }
  return fixes.sort((a, b) => b.score - a.score);
}

// ------------------------------------------------------------------ chokepoints

export interface Chokepoint {
  ruleId: string;
  groupId: string;
  text: string;
  /** Chains (by ID) that no longer exist once this rule is removed. */
  chainsClosed: string[];
  /** Internet exposure ranges closed or narrowed. */
  exposureClosed: ExposureDelta[];
  /** Of those, the ones that are probably wanted (medium and below). */
  collateral: ExposureDelta[];
  cli: string[];
}

/**
 * The security group rules that sit on attack chains, ranked by how many
 * chains removing each one would cut. Each rule is removed on a copy of the
 * model and both analyses are run again, so the counts are exact.
 * Candidates are the rules that let traffic in on every chain step, plus the
 * rules on the entry points' internet exposure; at most `limit` of the most
 * frequent are checked.
 */
export function findChokepoints(model: NetworkModel, exposure: ExposureReport, blast: BlastReport, limit = 20): Chokepoint[] {
  const freq = new Map<string, number>();
  const bump = (id: string) => freq.set(id, (freq.get(id) ?? 0) + 1);
  const edgeOf = new Map(blast.edges.map((e) => [`${e.from}>${e.to}`, e]));
  for (const c of blast.chains) {
    for (let i = 1; i < c.steps.length; i++) {
      const e = edgeOf.get(`${c.steps[i - 1]!.eniId}>${c.steps[i]!.eniId}`);
      const svc = e?.services.find((s) => serviceLabel(s) === c.steps[i]!.service);
      for (const id of svc?.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? []) bump(id);
    }
    const keys = new Set(c.entries.flatMap((e) => e.findingKeys));
    for (const f of exposure.findings) {
      if (!keys.has(findingKey(f))) continue;
      for (const id of f.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? []) bump(id);
    }
  }
  const before = new Set(blast.chains.map((c) => c.id));
  const out: Chokepoint[] = [];
  for (const [ruleId] of [...freq].sort((a, b) => b[1] - a[1]).slice(0, limit)) {
    const rule = findRule(model, ruleId);
    if (!rule) continue;
    const change: Change = { kind: 'revoke-sg-rule', ruleId };
    const after = applyChanges(model, [change]);
    const e1 = analyzeExposure(after);
    const b1 = analyzeBlastRadius(after, e1);
    const still = new Set(b1.chains.map((c) => c.id));
    const diff = diffExposure(exposure, e1);
    const lost = diff.deltas.filter((d) => d.status === 'closed' || d.status === 'narrowed');
    out.push({
      ruleId,
      groupId: rule.groupId,
      text: ruleText(rule),
      chainsClosed: [...before].filter((id) => !still.has(id)),
      exposureClosed: lost,
      collateral: lost.filter((d) => compareSeverity(d.severity, 'high') > 0),
      cli: cliFor(model, change),
    });
  }
  return out
    .filter((c) => c.chainsClosed.length || c.exposureClosed.length)
    .sort((a, b) => b.chainsClosed.length - a.chainsClosed.length || a.collateral.length - b.collateral.length || b.exposureClosed.length - a.exposureClosed.length);
}

// ------------------------------------------------------------------ remediation plan

export interface PlanStep {
  title: string;
  rationale: string;
  changes: Change[];
  cli: string[];
  /** Critical and high exposures this step closes or narrows. */
  closes: ExposureDelta[];
  /** Attack chains this step cuts. */
  chainsCut: AttackChain[];
  /** Other paths it closes or narrows, probably wanted. */
  collateral: ExposureDelta[];
  /** Internal traffic this step cuts. */
  breaks: Breakage[];
}

export interface FixPlan {
  steps: PlanStep[];
  before: { exposures: number; chains: number };
  after: { exposures: number; chains: number };
  /** Goals no single verified change could close. */
  unresolved: string[];
  /** How the plan was found: candidate changes tried, full re-analyses run, redundant steps dropped. */
  stats: { candidates: number; evaluations: number; pruned: number };
  /** Set when the time limit ended the search: more steps may be needed for the goals still open. */
  stoppedEarly?: boolean;
  /**
   * How close the plan is to the fewest steps possible, among the candidate
   * changes considered. `optimal`: no smaller set of them closes as much
   * without breaking more, proved by search. `bounded`: the search ran out of
   * budget; at least `lowerBound` steps are needed. `lowerBound` is the
   * minimum number of candidates that touch every closed goal at all, which
   * any plan must reach.
   */
  optimality: { status: 'optimal' | 'bounded'; lowerBound: number; searched: number; improvedFrom?: number };
}

export interface PlanOptions {
  /** Most steps to plan (default 10). */
  maxSteps?: number;
  /** Which exposures and chains the plan must close (default: critical and high). */
  goals?: { finding?: (f: ExposureFinding) => boolean; chain?: (c: AttackChain) => boolean };
  /**
   * Traffic that must keep working, such as a policy's require rules: returns
   * how many required connections are broken in a model. A step that breaks
   * more than the snapshot already does is never taken.
   */
  protect?: (model: NetworkModel) => number;
  /** Most re-analyses to spend proving or improving the plan's size (default 500; 0 skips the proof). */
  proofBudget?: number;
  /** Most time in milliseconds to spend on that proof (default 3000): on large networks each re-analysis is slow, and the plan stands without it. */
  proofTimeMs?: number;
  /**
   * Stop adding steps after this many milliseconds (default: no limit). The
   * steps found so far are kept, verified as usual, and `stoppedEarly` is set.
   */
  timeMs?: number;
}

// ------------------------------------------------------------------ plan size proof

/**
 * What a goal's traffic depends on: one item per connection it needs. A
 * finding needs the internet to reach its resource on its protocol and ports;
 * a chain needs its entries' findings and every hop of every route found.
 * `protocol: '*'` means any change near that interface counts (used where the
 * dependency is not one connection, such as targets behind a load balancer).
 */
type Need = { dst: string; src?: string; protocol: string; ports?: PortRange };

function needsOf(model: NetworkModel, exposure: ExposureReport, goal: { f?: ExposureFinding; c?: AttackChain }): Need[] {
  const out: Need[] = [];
  const ofFinding = (f: ExposureFinding) => {
    out.push({ dst: f.resourceId, protocol: f.protocol, ports: f.ports });
    if (f.kind === 'load-balancer') for (const id of behind(model, f.resourceId)) out.push({ dst: id, protocol: '*' });
  };
  if (goal.f) ofFinding(goal.f);
  if (goal.c) {
    const keys = new Set(goal.c.entries.flatMap((e) => e.findingKeys));
    for (const f of exposure.findings) if (keys.has(findingKey(f))) ofFinding(f);
    // Entries reached through a load balancer: the listener findings in front of them.
    const entryIds = new Set(goal.c.entries.map((e) => e.eniId));
    for (const f of exposure.findings) if (f.kind === 'load-balancer' && behind(model, f.resourceId).some((id) => entryIds.has(id))) ofFinding(f);
    for (const route of [goal.c.steps, ...goal.c.altRoutes]) {
      for (let i = 1; i < route.length; i++) {
        const m = /^([a-z0-9]+)(?:\/(\d+)(?:-(\d+))?)?$/.exec(route[i]!.service ?? '');
        const ports = m?.[2] ? { from: Number(m[2]), to: Number(m[3] ?? m[2]) } : undefined;
        out.push({ src: route[i - 1]!.eniId, dst: route[i]!.eniId, protocol: m?.[1] ?? '*', ...(ports ? { ports } : {}) });
      }
    }
  }
  return out;
}

/** A load balancer's nodes and target interfaces. */
function behind(model: NetworkModel, arn: string): string[] {
  const lb = model.loadBalancers.get(arn);
  if (!lb) return [];
  const ids = [...lb.nodeEniIds];
  for (const l of model.listeners.filter((x) => x.loadBalancerArn === arn))
    for (const tg of l.targetGroupArns.map((a) => model.targetGroups.get(a)))
      for (const t of tg?.targets ?? []) {
        const eni = tg!.targetType === 'instance' ? model.instances.get(t.id)?.primaryEniId : [...model.enis.values()].find((e) => e.privateIps.includes(t.id))?.id;
        if (eni) ids.push(eni);
      }
  return ids;
}

/**
 * Whether a change could close a need. Sound for the changes the planner
 * uses: taking away or narrowing a rule that never matches the need's
 * traffic, or adding a rule, cannot close it. Anything not understood here
 * counts as touching it.
 */
function canClose(model: NetworkModel, c: Change, n: Need): boolean {
  const groupsOf = (id: string | undefined) => (id ? model.enis.get(id)?.groupIds ?? model.loadBalancers.get(id)?.securityGroupIds ?? [] : []);
  const subnetsOf = (id: string | undefined) => (id ? (model.enis.get(id) ? [model.enis.get(id)!.subnetId] : model.loadBalancers.get(id)?.subnetIds ?? []) : []);
  const ports = (r: { protocol: string; fromPort?: number; toPort?: number }) => {
    if (n.protocol === '*') return true;
    const p = normalizeProtocol(n.protocol);
    if (r.protocol !== '-1' && r.protocol !== p) return false;
    if (!n.ports || r.fromPort === undefined || r.fromPort === -1 || !hasPorts(p)) return true;
    return r.fromPort <= n.ports.to && (r.toPort ?? r.fromPort) >= n.ports.from;
  };
  switch (c.kind) {
    case 'revoke-sg-rule':
    case 'edit-sg-rule': {
      for (const g of model.securityGroups.values()) {
        const r = g.ingress.find((x) => x.id === c.ruleId) ?? g.egress.find((x) => x.id === c.ruleId);
        if (!r) continue;
        const side = g.ingress.includes(r) ? groupsOf(n.dst) : groupsOf(n.src);
        return side.includes(g.id) && ports(r);
      }
      return false;
    }
    case 'add-sg-rule':
      return false;
    case 'add-nacl-entry':
    case 'remove-nacl-entry': {
      // A new allow entry only adds; a new deny only blocks its own protocol and ports.
      if (c.kind === 'add-nacl-entry' && (c.action === 'allow' || !ports({ protocol: normalizeProtocol(c.protocol), ...(c.fromPort !== undefined ? { fromPort: c.fromPort, toPort: c.toPort ?? c.fromPort } : {}) }))) return false;
      const acl = model.nacls.get(c.naclId);
      return [...subnetsOf(n.dst), ...subnetsOf(n.src)].some((sid) => {
        const sub = model.subnets.get(sid);
        return !!sub && naclForSubnet(model, sub)?.id === acl?.id;
      });
    }
    case 'remove-public-ip':
    case 'detach-sg':
    case 'attach-sg':
      return c.eniId === n.dst || c.eniId === n.src;
    default:
      return true;
  }
}

/** Minimum hitting set size, exactly, by branch and bound (sets are small). */
function minHittingSet(sets: number[][], cap = 200000): { size: number; exact: boolean } {
  let best = Infinity;
  let nodes = 0;
  const go = (chosen: Set<number>, depth: number) => {
    if (++nodes > cap || depth >= best) return;
    const open = sets.filter((s) => !s.some((x) => chosen.has(x)));
    if (!open.length) {
      best = depth;
      return;
    }
    // Disjoint open sets each need their own element: a quick bound.
    const used = new Set<number>();
    let disjoint = 0;
    for (const s of [...open].sort((a, b) => a.length - b.length)) if (!s.some((x) => used.has(x))) {
      disjoint += 1;
      s.forEach((x) => used.add(x));
    }
    if (depth + disjoint >= best) return;
    const pick = open.reduce((a, b) => (b.length < a.length ? b : a));
    for (const x of pick) {
      chosen.add(x);
      go(chosen, depth + 1);
      chosen.delete(x);
    }
  };
  go(new Set(), 0);
  return { size: best === Infinity ? 0 : best, exact: nodes <= cap };
}

const W = { critical: 10, high: 6, medium: 0, low: 0, info: 0 } as const;
const isSevere = (s: { severity: keyof typeof W }) => s.severity === 'critical' || s.severity === 'high';

type Cand = { title: string; rationale: string; changes: Change[] };
type Eval = { m: NetworkModel; e: ExposureReport; b: BlastReport; diff: ReturnType<typeof diffExposure> };

/**
 * A short list of changes that, applied in order, closes every critical and
 * high exposure and attack chain it can. Nothing is guessed: every number
 * comes from applying the change to a copy of the model and re-running both
 * analyses.
 *
 * 1. Candidates: the verified fixes for the worst few open exposures, and the
 *    removal of each rule on the worst few open attack chains (every route).
 * 2. Lazy greedy selection (Minoux): each candidate keeps its last measured
 *    gain as an upper bound, because closing goals only ever lowers what is
 *    left for the others. Candidates are re-measured in bound order and the
 *    search stops as soon as no bound can beat the best fresh gain, so most
 *    candidates are not re-analysed at every step. Candidates for the goals
 *    being worked on are always re-measured, since two rules that only matter
 *    together break the bound.
 * 3. Pruning: once the plan is built, each step is taken out in turn and the
 *    rest re-applied; a step whose removal leaves every goal as closed as
 *    before is redundant (a later, broader step covered it) and is dropped.
 */
export function planFixes(model: NetworkModel, exposure: ExposureReport, blast: BlastReport, maxStepsOrOpts: number | PlanOptions = 10): FixPlan {
  const opts: PlanOptions = typeof maxStepsOrOpts === 'number' ? { maxSteps: maxStepsOrOpts } : maxStepsOrOpts;
  const maxSteps = opts.maxSteps ?? 10;
  const isGoalF = (f: ExposureFinding) => isSevere(f) && (opts.goals?.finding ? opts.goals.finding(f) : !opts.goals);
  const isGoalC = (c: AttackChain) => isSevere(c) && (opts.goals?.chain ? opts.goals.chain(c) : !opts.goals);
  const weight = (e: ExposureReport, b: BlastReport) => e.findings.filter(isGoalF).reduce((n, f) => n + W[f.severity], 0) + b.chains.filter(isGoalC).reduce((n, c) => n + W[c.severity], 0);
  const stats = { candidates: 0, evaluations: 0, pruned: 0 };

  const evaluate = (m0: NetworkModel, e0: ExposureReport, b0: BlastReport, changes: Change[]): Eval | undefined => {
    let m1: NetworkModel;
    try {
      m1 = applyChanges(m0, changes);
    } catch {
      return undefined;
    }
    stats.evaluations += 1;
    const e1 = exposureAfter(m0, m1, e0, changes);
    const b1 = analyzeBlastRadius(m1, e1);
    return { m: m1, e: e1, b: b1, diff: diffExposure(e0, e1, { before: b0, after: b1 }) };
  };
  const protectBase = opts.protect ? opts.protect(model) : 0;
  const breaksProtected = (m1: NetworkModel) => !!opts.protect && opts.protect(m1) > protectBase;
  const collateralOf = (d: ReturnType<typeof diffExposure>) => d.deltas.filter((x) => (x.status === 'closed' || x.status === 'narrowed') && compareSeverity(x.severity, 'high') > 0);

  let m = model;
  let e = exposure;
  let b = blast;
  const chosen: Cand[] = [];
  const skipped = new Set<string>();
  const unresolved: string[] = [];
  const pool = new Map<string, Cand & { bound: number }>();
  const keyOf = (c: Cand) => c.changes.map((x) => JSON.stringify(x)).join('|');
  const byGoal = new Map<string, Set<string>>();

  const deadline = opts.timeMs === undefined ? Infinity : performance.now() + opts.timeMs;
  let stoppedEarly = false;
  for (let i = 0; i < maxSteps; i++) {
    if (performance.now() > deadline) {
      stoppedEarly = true;
      break;
    }
    const goalF = e.findings.filter((f) => isGoalF(f) && !skipped.has(findingKey(f)));
    const goalC = b.chains.filter((c) => isGoalC(c) && !skipped.has(c.id));
    if (!goalF.length && !goalC.length) break;

    // Candidates are generated once per goal (the worst few open ones) and kept in the pool.
    // Those for the single worst goal are always re-measured; the rest use their bound.
    const forced = new Set<string>();
    const add = (c: Cand, goal: string) => {
      const k = keyOf(c);
      if (!pool.has(k)) {
        stats.candidates += 1;
        pool.set(k, { ...c, bound: Infinity });
      }
      (byGoal.get(goal) ?? byGoal.set(goal, new Set()).get(goal)!).add(k);
    };
    for (const f of goalF.slice(0, 3)) {
      const g = `f:${findingKey(f)}`;
      if (byGoal.has(g)) continue;
      byGoal.set(g, new Set());
      for (const x of findFixes(m, f).filter((x) => x.verified && !x.opened.length).slice(0, 3)) add(x, g);
    }
    const edgeOf = new Map(b.edges.map((x) => [`${x.from}>${x.to}`, x]));
    for (const c0 of goalC.slice(0, 2)) {
      const g = `c:${c0.id}`;
      if (byGoal.has(g)) continue;
      byGoal.set(g, new Set());
      // Cutting the chain where it starts: the internet exposure of its entry points.
      // One change there can break every chain from that entry at once.
      const entryKeys = new Set(c0.entries.flatMap((x) => x.findingKeys));
      for (const f of e.findings.filter((x) => entryKeys.has(findingKey(x))).slice(0, 2)) {
        for (const x of findFixes(m, f).filter((x) => x.verified && !x.opened.length).slice(0, 2)) add(x, g);
      }
      for (const route of [c0.steps, ...c0.altRoutes]) {
        for (let k = 1; k < route.length; k++) {
          const svc = edgeOf.get(`${route[k - 1]!.eniId}>${route[k]!.eniId}`)?.services.find((s) => serviceLabel(s) === route[k]!.service);
          for (const id of svc?.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? []) {
            const r = findRule(m, id);
            if (!r) continue;
            const routeText = route.map((s) => s.name.replace(/ \(.*\)$/, '')).join(' → ');
            add({ title: `Remove ${id}`, rationale: `${id} (${ruleText(r)}) is a step on ${routeText}.`, changes: [{ kind: 'revoke-sg-rule', ruleId: id }] }, g);
            // Or keep the rule for everyone who uses it except the attacker's foothold.
            const narrowed = narrowHop(m, r, route[k]!.eniId, route[k - 1]!.eniId);
            if (narrowed) add({ ...narrowed, rationale: `${narrowed.rationale} It cuts ${routeText}.` }, g);
          }
        }
      }
    }
    for (const g of [goalF[0] ? `f:${findingKey(goalF[0])}` : '', goalC[0] ? `c:${goalC[0].id}` : '']) for (const k of byGoal.get(g) ?? []) forced.add(k);

    const w0 = weight(e, b);
    let best: { key: string; c: Cand; ev: Eval; gain: number } | undefined;
    for (const [key, c] of [...pool].sort((x, y) => y[1].bound - x[1].bound)) {
      if (best && c.bound - c.changes.length <= best.gain && !forced.has(key)) continue;
      // Out of time: take the best step measured so far.
      if (best && performance.now() > deadline) {
        stoppedEarly = true;
        break;
      }
      const ev = evaluate(m, e, b, c.changes);
      if (!ev || ev.diff.opened || ev.diff.chainsOpened.length || breaksProtected(ev.m)) {
        pool.delete(key);
        continue;
      }
      // Breaking traffic someone probably wants costs more than leaving one risk open:
      // a step with collateral only wins if nothing cleaner closes as much.
      // So does cutting internal traffic: a load balancer, a health check or a
      // group-to-group connection is a break; address-range traffic is a smaller cost.
      const closure = w0 - weight(ev.e, ev.b);
      // The bound is on what a step closes; penalties only ever lower it further.
      c.bound = closure;
      const before = closure - 15 * collateralOf(ev.diff).length - c.changes.length;
      // Breaks only lower the gain: skip measuring them when the step cannot win anyway.
      if (closure <= 0 || (best && before <= best.gain)) continue;
      const br = internalBreaks(m, ev.m, c.changes);
      const brPairs = new Set(br.filter((x) => !isWanted(x)).map((x) => `${x.flow.from}>${x.flow.to}`)).size;
      const gain = before - 15 * br.filter(isWanted).length - 0.5 * Math.min(brPairs, 6);
      // A step that closes something is taken even at a cost, when nothing cleaner
      // closes as much; its breaks are reported with it.
      if (closure > 0 && (!best || gain > best.gain)) best = { key, c, ev, gain };
    }
    if (!best) {
      // Nothing closes the worst goal on its own: leave it to a person.
      const f0 = goalF[0];
      const c0 = goalC[0];
      if (f0) {
        skipped.add(findingKey(f0));
        unresolved.push(`${f0.resourceName}: ${serviceLabel(f0)} from ${f0.sources.join(', ')}`);
      } else if (c0) {
        skipped.add(c0.id);
        unresolved.push(`attack chain ${c0.steps.map((s) => s.name).join(' → ')}`);
      }
      continue;
    }
    chosen.push(best.c);
    pool.delete(best.key);
    m = best.ev.m;
    e = best.ev.e;
    b = best.ev.b;
  }

  // Pruning: drop any step the rest of the plan already covers.
  const finalWeight = weight(e, b);
  const replay = (list: Cand[]) => {
    let mm = model;
    for (const c of list) mm = applyChanges(mm, c.changes);
    const ee = exposureAfter(model, mm, exposure, list.flatMap((c) => c.changes));
    stats.evaluations += 1;
    return { e: ee, b: analyzeBlastRadius(mm, ee) };
  };
  let plan = chosen;
  if (plan.length > 1 && performance.now() <= deadline) {
    for (let i = plan.length - 1; i >= 0; i--) {
      const trial = plan.filter((_, j) => j !== i);
      let r: { e: ExposureReport; b: BlastReport };
      try {
        r = replay(trial);
      } catch {
        continue;
      }
      if (weight(r.e, r.b) <= finalWeight) {
        plan = trial;
        stats.pruned += 1;
      }
    }
  }

  // Proof: is there a smaller plan among the candidates? Every closed goal
  // must be touched by some step, which gives a lower bound; then every set of
  // candidates smaller than the plan that touches every closed goal is tried.
  const optimality: FixPlan['optimality'] = stoppedEarly ? { status: 'bounded', lowerBound: Math.min(1, plan.length), searched: 0 } : { status: 'optimal', lowerBound: plan.length, searched: 0 };
  const budget = opts.proofBudget ?? 500;
  const proofDeadline = performance.now() + (opts.proofTimeMs ?? 3000);
  if (plan.length > 1 && budget > 0 && !stoppedEarly) {
    const all = [...new Map([...plan, ...pool.values()].map((c) => [keyOf(c), c])).values()];
    const openKeys = new Set([...e.findings.filter(isGoalF).map((f) => `f:${findingKey(f)}`), ...b.chains.filter(isGoalC).map((c) => `c:${c.id}`)]);
    const closedGoals = [
      ...exposure.findings.filter((f) => isGoalF(f) && !openKeys.has(`f:${findingKey(f)}`)).map((f) => ({ key: `f:${findingKey(f)}`, needs: needsOf(model, exposure, { f }) })),
      ...blast.chains.filter((c) => isGoalC(c) && !openKeys.has(`c:${c.id}`)).map((c) => ({ key: `c:${c.id}`, needs: needsOf(model, exposure, { c }) })),
    ];
    const closedNeeds = closedGoals.map((g) => g.needs);
    // A goal closes only if some step can close one of the connections it needs.
    const sets = closedNeeds.map((needs) => all.map((_, i) => i).filter((i) => all[i]!.changes.some((x) => needs.some((nd) => canClose(model, x, nd)))));
    const lb = minHittingSet(sets);
    optimality.lowerBound = lb.exact ? lb.size : 1;
    const wantedOf = (list: Cand[]) => {
      let mm = model;
      let n = 0;
      for (const c of list) {
        const next = applyChanges(mm, c.changes);
        n += internalBreaks(mm, next, c.changes).filter(isWanted).length;
        mm = next;
      }
      return n;
    };
    let planWanted = -1;
    // Every set of k relevant candidates that touches every closed goal, for k
    // from the lower bound up to one less than the plan. All of them, not just
    // minimal ones: two candidates on the same goal can matter together.
    // Candidates that touch the most goals come first.
    const rel = [...new Set(sets.flat())].sort((x, y) => sets.filter((st) => st.includes(y)).length - sets.filter((st) => st.includes(x)).length);
    const ruleSets = all.map((c) => new Set(c.changes.flatMap((x) => ('ruleId' in x ? [x.ruleId] : 'naclId' in x && 'ruleNumber' in x ? [`${x.naclId}:${x.egress}:${x.ruleNumber}`] : 'eniId' in x && 'publicIp' in x ? [`${x.eniId}:${x.publicIp}`] : []))));
    const rulesOf = (i: number) => ruleSets[i]!;
    const hitting = function* (k: number): Generator<number[]> {
      const go = function* (start: number, chosen: number[]): Generator<number[]> {
        if (chosen.length === k) {
          if (sets.every((st) => st.some((x) => chosen.includes(x)))) yield chosen;
          return;
        }
        // Not enough left to fill the set, or a goal no remaining candidate can touch.
        if (rel.length - start < k - chosen.length) return;
        const rest = new Set(rel.slice(start));
        if (sets.some((st) => !st.some((x) => chosen.includes(x) || rest.has(x)))) return;
        for (let i = start; i < rel.length; i++) {
          // Two changes to the same rule cannot both be applied.
          if (chosen.some((x) => [...rulesOf(x)].some((r) => rulesOf(rel[i]!).has(r)))) continue;
          yield* go(i + 1, [...chosen, rel[i]!]);
        }
      };
      yield* go(0, []);
    };
    const openParts: bigint[][] = [];
    let exhausted = true;
    search: for (let k = optimality.lowerBound; k < plan.length; k++) {
      for (const idx of hitting(k)) {
        if (optimality.searched >= budget || performance.now() > proofDeadline) {
          exhausted = false;
          break search;
        }
        // Whether a goal closes depends only on the candidates that can touch it,
        // and every candidate only takes access away, so if some candidates
        // leave a goal open, any subset of them does too. A set whose part for
        // some goal is inside a part already seen to fail is ruled out for free.
        const parts = sets.map((st) => idx.filter((i) => st.includes(i)).reduce((m, i) => m | (1n << BigInt(i)), 0n));
        if (parts.some((p, gi) => (openParts[gi] ?? []).some((q) => (p & q) === p))) continue;
        optimality.searched += 1;
        const trial = idx.map((i) => all[i]!);
        let r: { e: ExposureReport; b: BlastReport };
        try {
          r = replay(trial);
        } catch {
          continue;
        }
        const stillOpen = new Set([...r.e.findings.map((f) => `f:${findingKey(f)}`), ...r.b.chains.map((c) => `c:${c.id}`)]);
        closedGoals.forEach((g, gi) => {
          if (stillOpen.has(g.key)) (openParts[gi] ??= []).push(parts[gi]!);
        });
        if (closedGoals.some((g) => stillOpen.has(g.key))) continue;
        if (weight(r.e, r.b) > finalWeight) continue;
        if (r.e.findings.length > exposure.findings.length || diffExposure(exposure, r.e).opened) continue;
        if (opts.protect && breaksProtected(trial.reduce((mm, c) => applyChanges(mm, c.changes), model))) continue;
        if (planWanted < 0) planWanted = wantedOf(plan);
        if (wantedOf(trial) > planWanted) continue;
        optimality.improvedFrom = plan.length;
        plan = trial;
        break search;
      }
    }
    // Sizes are searched smallest first, so a plan found is the smallest there is.
    if (!exhausted && !optimality.improvedFrom) optimality.status = 'bounded';
    // Every smaller size was searched in full: the plan's size is the minimum.
    if (exhausted) optimality.lowerBound = plan.length;
    if (optimality.improvedFrom) optimality.lowerBound = plan.length;
  }
  if (plan.length <= 1) optimality.lowerBound = plan.length;

  // Describe the final steps against the model as it is when each one runs.
  const steps: PlanStep[] = [];
  let mm = model;
  let ee = exposure;
  let bb = blast;
  for (const c of plan) {
    const ev = evaluate(mm, ee, bb, c.changes);
    if (!ev) break;
    const lost = ev.diff.deltas.filter((d) => d.status === 'closed' || d.status === 'narrowed');
    steps.push({
      title: c.title,
      rationale: c.rationale,
      changes: c.changes,
      cli: c.changes.flatMap((x) => cliFor(mm, x)),
      closes: lost.filter((d) => compareSeverity(d.severity, 'high') <= 0),
      chainsCut: ev.diff.chainsClosed.filter(isGoalC),
      collateral: lost.filter((d) => compareSeverity(d.severity, 'high') > 0),
      breaks: internalBreaks(mm, ev.m, c.changes),
    });
    mm = ev.m;
    ee = ev.e;
    bb = ev.b;
  }
  return {
    steps,
    before: { exposures: exposure.findings.filter(isGoalF).length, chains: blast.chains.filter(isGoalC).length },
    after: { exposures: ee.findings.filter(isGoalF).length, chains: bb.chains.filter(isGoalC).length },
    unresolved,
    stats,
    optimality,
    ...(stoppedEarly ? { stoppedEarly } : {}),
  };
}
