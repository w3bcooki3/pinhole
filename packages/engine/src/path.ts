/**
 * Answers "can traffic from A reach B on protocol/port?" for one concrete
 * packet, and explains the answer hop by hop.
 *
 * Order of evaluation follows the packet:
 *   source SG (outbound) -> source NACL (outbound) -> routing (VPC, peering,
 *   TGW incl. attachment-subnet NACLs) -> destination NACL (inbound) ->
 *   destination SG (inbound) -> return routing -> return NACLs.
 *
 * Security groups are stateful, so the return direction never consults them
 * (https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html).
 * NACLs are stateless, so return traffic is checked on the client's
 * ephemeral ports (https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html).
 *
 * The verdict is three-valued. "unknown" means the snapshot does not contain
 * what the answer depends on (another account, a shared TGW route table,
 * an inspection appliance), never that we guessed.
 */
import { DOCS } from './docs.js';
import { formatIpv4, INTERNET, parseIpv4 } from './ipv4.js';
import { evaluateNacl, evaluateNaclPortRange } from './nacl.js';
import { describePacket, hasPorts, normalizeProtocol } from './packet.js';
import type { PeerRelation, SgPeer } from './sg.js';
import { evaluateSg } from './sg.js';
import { attachedIgw, eniByPrivateIp, isElbNode, naclForSubnet, primaryIp } from './topology.js';
import { PROTO_ICMP } from './types.js';
import type { Eni, NetworkModel, Packet, PortRange, SecurityGroup, Subnet } from './types.js';
import type { ApplianceCheckpoint, Hop, NaclCheckpoint, Stage, Walk, WalkStep } from './walk.js';
import { applianceOf, walkFromTgwAttachment, walkRoute } from './walk.js';
import { ONPREM_CAVEAT, describeLink, linkOf } from './onprem.js';
import type { OnPremLink } from './onprem.js';
import { evaluateFirewall } from './firewall.js';
import { lookupRoute } from './routes.js';

export type Endpoint =
  | { eni: string; ip?: string }
  | { instance: string }
  /** A client on the internet with this public address. */
  | { internet: string }
  /** Any address; resolved to an interface if one in the snapshot owns it. */
  | { ip: string };

export interface PathQuery {
  from: Endpoint;
  to: Endpoint;
  /** "tcp", "udp", "icmp", or an IP protocol number. */
  protocol: string;
  /** Destination port (TCP/UDP) or ICMP type (ICMP; default 8, echo request). */
  port?: number;
}

/** Ephemeral port range a client OS chooses its source port from. */
export interface EphemeralProfile {
  name: string;
  range: PortRange;
}

/**
 * Ranges from the AWS NACL documentation ("Ephemeral ports"):
 * https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html
 */
export const CLIENT_PROFILES: EphemeralProfile[] = [
  { name: 'Linux kernels (incl. Amazon Linux)', range: { from: 32768, to: 61000 } },
  { name: 'Windows Server 2008 and later', range: { from: 49152, to: 65535 } },
];
export const ELB_PROFILES: EphemeralProfile[] = [{ name: 'Elastic Load Balancing', range: { from: 1024, to: 65535 } }];

export type ReturnCoverage = 'all' | 'partial' | 'none';

export interface ReturnProfileResult {
  profile: string;
  range: PortRange;
  allowed: PortRange[];
  coverage: ReturnCoverage;
}

export interface PathResult {
  verdict: 'reachable' | 'blocked' | 'unknown';
  summary: string;
  hops: Hop[];
  blockedAt?: { stage: Stage; resourceId: string; detail: string; docUrl?: string };
  /** For reachable paths: how much of the clients' ephemeral range can get back. */
  returnPath?: ReturnCoverage;
  returnProfiles?: ReturnProfileResult[];
  /** For outbound paths: the gateway the traffic leaves through, and the public address it leaves as. */
  via?: { gateway: string; publicIp?: string };
  warnings: string[];
}

// ------------------------------------------------------------------ endpoints

type Resolved =
  | { kind: 'eni'; eni: Eni; ip: number; subnet: Subnet }
  | { kind: 'internet'; ip: number }
  | { kind: 'outside'; ip: number };

class ResolveError extends Error {}

function resolve(model: NetworkModel, ep: Endpoint): Resolved {
  const fromEni = (eni: Eni | undefined, ipText?: string): Resolved => {
    if (!eni) throw new ResolveError('Interface not found in snapshot.');
    const subnet = model.subnets.get(eni.subnetId);
    if (!subnet) throw new ResolveError(`Subnet ${eni.subnetId} of ${eni.id} is not in the snapshot.`);
    const ip = ipText ? parseIpv4(ipText) : primaryIp(eni);
    if (ip === undefined) throw new ResolveError(`${eni.id} has no private IPv4 address.`);
    if (ipText && !eni.privateIps.includes(ipText)) throw new ResolveError(`${ipText} is not a private IP of ${eni.id}.`);
    return { kind: 'eni', eni, ip, subnet };
  };
  if ('eni' in ep) {
    const eni = model.enis.get(ep.eni);
    if (!eni) throw new ResolveError(`Interface ${ep.eni} is not in the snapshot.`);
    return fromEni(eni, ep.ip);
  }
  if ('instance' in ep) {
    const inst = model.instances.get(ep.instance);
    const eniId = inst?.primaryEniId;
    if (!eniId) throw new ResolveError(`Instance ${ep.instance} (or its primary interface) is not in the snapshot.`);
    return fromEni(model.enis.get(eniId));
  }
  if ('internet' in ep) {
    const ip = parseIpv4(ep.internet);
    if (!INTERNET.containsIp(ip)) throw new ResolveError(`${ep.internet} is not a public internet address.`);
    return { kind: 'internet', ip };
  }
  const ip = parseIpv4(ep.ip);
  const eni = eniByPrivateIp(model, ip);
  if (eni) return fromEni(eni, ep.ip);
  return { kind: 'outside', ip };
}

function packetFor(protocol: string, port: number | undefined): Packet {
  const p = normalizeProtocol(protocol);
  if (p === '-1') throw new ResolveError('A query needs a concrete protocol, not "all".');
  if (hasPorts(p)) {
    if (port === undefined || port < 0 || port > 65535) throw new ResolveError(`Protocol ${protocol} needs a port between 0 and 65535.`);
    return { protocol: p, port };
  }
  if (p === PROTO_ICMP) return { protocol: p, icmpType: port ?? 8, icmpCode: 0 };
  return { protocol: p };
}

// ------------------------------------------------------------------ helpers

function groupsOf(model: NetworkModel, eni: Eni): SecurityGroup[] {
  return eni.groupIds.map((id) => model.securityGroups.get(id)).filter((g): g is SecurityGroup => !!g);
}

function naclHop(model: NetworkModel, check: NaclCheckpoint, pkt: Packet): Hop {
  const subnet = model.subnets.get(check.subnetId);
  const acl = subnet ? naclForSubnet(model, subnet) : undefined;
  if (!acl) {
    return { stage: check.stage, decision: 'unknown', resourceId: check.subnetId, detail: `No network ACL found for ${check.subnetId}.` };
  }
  const d = evaluateNacl(acl, check.egress, check.peerIp, pkt);
  const dir = check.egress ? 'outbound' : 'inbound';
  const rule = d.entry.ruleNumber === 32767 ? '*' : String(d.entry.ruleNumber);
  return {
    stage: check.stage,
    decision: d.action === 'allow' ? 'pass' : 'block',
    resourceId: acl.id,
    detail: `${acl.id} ${dir} rule ${rule} ${d.action === 'deny' ? 'denies' : 'allows'} ${describePacket(pkt)} ${check.egress ? 'to' : 'from'} ${formatIpv4(check.peerIp)}`,
    ruleIds: [`${acl.id}#${check.egress ? 'egress' : 'ingress'}#${rule}`],
    docUrl: DOCS.naclCustom,
  };
}

function sgHop(
  model: NetworkModel,
  stage: Stage,
  eni: Eni,
  direction: 'ingress' | 'egress',
  peer: SgPeer,
  pkt: Packet,
): { hop: Hop; warnings: string[] } {
  const groups = groupsOf(model, eni);
  if (eni.groupIds.length === 0) {
    const nlb = eni.interfaceType === 'network_load_balancer';
    return {
      hop: {
        stage,
        decision: 'pass',
        resourceId: eni.id,
        detail: nlb
          ? `${eni.id} belongs to a Network Load Balancer without security groups: all client traffic reaches its listeners.`
          : `${eni.id} has no security groups (${eni.interfaceType}); no security group filtering applies.`,
        ...(nlb ? { docUrl: DOCS.nlbSecurityGroups } : {}),
      },
      warnings: [],
    };
  }
  const missing = eni.groupIds.filter((id) => !model.securityGroups.has(id));
  const d = evaluateSg(groups, direction, peer, pkt, model.prefixLists);
  const warnings: string[] = [];
  if (missing.length) warnings.push(`Security groups ${missing.join(', ')} of ${eni.id} are not in the snapshot.`);
  if (d.unknownPrefixLists.length) warnings.push(`Prefix lists ${d.unknownPrefixLists.join(', ')} have no entries in the snapshot.`);
  const dir = direction === 'ingress' ? 'inbound' : 'outbound';
  const peerText = formatIpv4(peer.ip);
  const unknown = !d.allowed && (missing.length > 0 || d.unknownPrefixLists.length > 0);
  return {
    hop: {
      stage,
      decision: d.allowed ? 'pass' : unknown ? 'unknown' : 'block',
      resourceId: eni.groupIds.join(','),
      detail: d.allowed
        ? `${dir} ${describePacket(pkt)} ${direction === 'ingress' ? 'from' : 'to'} ${peerText} allowed by ${d.matched.map((r) => `${r.id} (${r.groupId})`).join(', ')}`
        : `no ${dir} rule in ${eni.groupIds.join(', ')} allows ${describePacket(pkt)} ${direction === 'ingress' ? 'from' : 'to'} ${peerText}`,
      ruleIds: d.matched.map((r) => r.id),
      docUrl: DOCS.sgRules,
    },
    warnings,
  };
}

/** Intersection of two sorted lists of port ranges. */
function intersectRanges(a: PortRange[], b: PortRange[]): PortRange[] {
  const out: PortRange[] = [];
  for (const x of a) {
    for (const y of b) {
      const from = Math.max(x.from, y.from);
      const to = Math.min(x.to, y.to);
      if (from <= to) out.push({ from, to });
    }
  }
  return out.sort((p, q) => p.from - q.from);
}

function coverage(allowed: PortRange[], range: PortRange): ReturnCoverage {
  const covered = intersectRanges(allowed, [range]).reduce((n, r) => n + (r.to - r.from + 1), 0);
  if (covered === 0) return 'none';
  return covered === range.to - range.from + 1 ? 'all' : 'partial';
}

/**
 * Evaluates the return direction's NACL checkpoints.
 * TCP/UDP: the response goes to the client's ephemeral port; we compute, per
 * client profile, which part of its range every checkpoint allows.
 * ICMP: an echo request (type 8) is answered by an echo reply (type 0).
 * Other protocols: the same protocol with no ports.
 */
function evaluateReturnNacls(
  model: NetworkModel,
  checks: NaclCheckpoint[],
  pkt: Packet,
  profiles: EphemeralProfile[],
  /** Client ports a firewall on the path lets through, when there is one. */
  limit?: PortRange[],
): { hops: Hop[]; profiles?: ReturnProfileResult[]; coverage: ReturnCoverage; blockingHop?: Hop } {
  const hops: Hop[] = [];
  if (!hasPorts(pkt.protocol)) {
    const reply: Packet = pkt.protocol === PROTO_ICMP ? { protocol: PROTO_ICMP, icmpType: pkt.icmpType === 8 ? 0 : pkt.icmpType ?? 0, icmpCode: 0 } : { protocol: pkt.protocol };
    for (const c of checks) {
      const h = naclHop(model, { ...c, stage: 'return-nacl' }, reply);
      hops.push(h);
      if (h.decision !== 'pass') return { hops, coverage: 'none', blockingHop: h };
    }
    return { hops, coverage: 'all' };
  }

  const span: PortRange = {
    from: Math.min(...profiles.map((p) => p.range.from)),
    to: Math.max(...profiles.map((p) => p.range.to)),
  };
  let allowed: PortRange[] = limit ? intersectRanges([span], limit) : [span];
  let firstBlocking: Hop | undefined;
  for (const c of checks) {
    const subnet = model.subnets.get(c.subnetId);
    const acl = subnet ? naclForSubnet(model, subnet) : undefined;
    if (!acl) {
      const h: Hop = { stage: 'return-nacl', decision: 'unknown', resourceId: c.subnetId, detail: `No network ACL found for ${c.subnetId}.` };
      hops.push(h);
      return { hops, coverage: 'none', blockingHop: h };
    }
    const segs = evaluateNaclPortRange(acl, c.egress, c.peerIp, pkt.protocol, span);
    const ok = segs.filter((s) => s.action === 'allow').map((s) => s.range);
    allowed = intersectRanges(allowed, ok);
    const dir = c.egress ? 'outbound' : 'inbound';
    const rules = [...new Set(segs.map((s) => (s.entry.ruleNumber === 32767 ? '*' : String(s.entry.ruleNumber))))];
    const fmt = (rs: PortRange[]) => (rs.length ? rs.map((r) => (r.from === r.to ? `${r.from}` : `${r.from}-${r.to}`)).join(', ') : 'none');
    const h: Hop = {
      stage: 'return-nacl',
      decision: ok.length === 0 ? 'block' : 'pass',
      resourceId: acl.id,
      detail: `${acl.id} ${dir} ${c.egress ? 'to' : 'from'} ${formatIpv4(c.peerIp)}: ports ${fmt(ok)} of ${span.from}-${span.to} allowed (rules ${rules.join(', ')})`,
      ruleIds: rules.map((r) => `${acl.id}#${c.egress ? 'egress' : 'ingress'}#${r}`),
      docUrl: DOCS.naclCustom,
    };
    hops.push(h);
    if (ok.length === 0 && !firstBlocking) firstBlocking = h;
  }
  const results: ReturnProfileResult[] = profiles.map((p) => ({ profile: p.name, range: p.range, allowed: intersectRanges(allowed, [p.range]), coverage: coverage(allowed, p.range) }));
  const all = results.every((r) => r.coverage === 'all');
  const none = results.every((r) => r.coverage === 'none');
  const cov: ReturnCoverage = all ? 'all' : none ? 'none' : 'partial';
  const blocking = cov === 'none' ? firstBlocking ?? hops[hops.length - 1] : undefined;
  return { hops, profiles: results, coverage: cov, ...(blocking ? { blockingHop: blocking } : {}) };
}

/**
 * What an appliance in the path does to the connection. A Network Firewall
 * is evaluated exactly, for every client source port in `span`; where its
 * answer depends on the traffic itself, or the appliance is a third party's,
 * the path goes on with a caveat rather than stopping, so an exposure is
 * never hidden by a device whose rules cannot be seen.
 */
function applianceHop(model: NetworkModel, c: ApplianceCheckpoint, pkt: Packet, span: PortRange): { hop: Hop; allowed?: PortRange[] } {
  if (c.firewallArn) {
    const fw = model.firewalls.get(c.firewallArn)!;
    const r = evaluateFirewall(model, fw, c.srcIp, c.dstIp, Number(pkt.protocol), hasPorts(pkt.protocol) ? pkt.port : undefined, span);
    const base = { stage: 'firewall' as const, resourceId: fw.name, relatedIds: [fw.arn, c.endpointId], ruleIds: r.ruleIds, docUrl: DOCS.networkFirewall };
    if (r.verdict === 'block') return { hop: { ...base, decision: 'block', detail: r.detail } };
    const allowed = [...r.allowed, ...r.unknownPorts];
    const caveat = r.verdict === 'unknown' || r.unknownPorts.length ? `${fw.name} decides this by the traffic itself (content, host name or application), which a configuration snapshot cannot show.` : undefined;
    return { hop: { ...base, decision: 'pass', detail: r.detail, ...(caveat ? { caveat } : {}) }, ...(hasPorts(pkt.protocol) ? { allowed } : {}) };
  }
  const svc = c.serviceName ?? 'an endpoint service';
  return {
    hop: {
      stage: 'appliance',
      decision: 'pass',
      resourceId: c.endpointId,
      detail: `${c.endpointId} sends the traffic to a third-party appliance (${svc}) and back.`,
      caveat: `The appliance behind ${c.endpointId} (${svc}) may block this, but its rules are not visible to AWS APIs; the path assumes it passes.`,
      docUrl: DOCS.gwlbRouting,
    },
  };
}

function walkHops(model: NetworkModel, walk: Walk | WalkStep[], pkt: Packet, span: PortRange = { from: 1024, to: 65535 }): { hops: Hop[]; blocking?: Hop; limit?: PortRange[]; appliances: string[] } {
  const hops: Hop[] = [];
  let limit: PortRange[] | undefined;
  const appliances: string[] = [];
  for (const s of Array.isArray(walk) ? walk : walk.steps) {
    let h: Hop;
    if (s.kind === 'hop') h = s.hop;
    else if (s.kind === 'nacl') h = naclHop(model, s.check, pkt);
    else {
      const a = applianceHop(model, s.check, pkt, span);
      h = a.hop;
      appliances.push(s.check.firewallArn ?? s.check.endpointId);
      if (a.allowed) limit = limit ? intersectRanges(limit, a.allowed) : a.allowed;
      if (h.decision === 'pass' && a.allowed && !a.allowed.length) h = { ...h, decision: 'block', detail: `${h.detail} (no client port gets through)` };
    }
    hops.push(h);
    if (h.decision === 'block' || h.decision === 'unknown') return { hops, blocking: h, ...(limit ? { limit } : {}), appliances };
  }
  return { hops, ...(limit ? { limit } : {}), appliances };
}

/**
 * A packet arriving from outside through a gateway (an internet gateway, or a
 * virtual private gateway), to `privateIp` in `dstSubnet`. A gateway route table
 * (ingress routing) may send it through a firewall or appliance first
 * (https://docs.aws.amazon.com/vpc/latest/userguide/gateway-route-tables.html).
 * Returns the hops decided so far, the steps still to evaluate (ending with the
 * destination subnet's network ACL), or the hop that stops it.
 */
function ingressFromGateway(model: NetworkModel, gatewayId: string, clientIp: number, dstPrivate: number, privateText: string, dstSubnet: Subnet, pkt: Packet, span: PortRange): { hops: Hop[]; steps: WalkStep[]; fail?: Hop } {
  const hops: Hop[] = [];
  let steps: WalkStep[] = [{ kind: 'nacl', check: { subnetId: dstSubnet.id, egress: false, peerIp: clientIp, stage: 'dest-nacl-ingress' } }];
  const edge = [...model.routeTables.values()].find((rt) => rt.gatewayIds.includes(gatewayId));
  if (!edge) return { hops, steps };
  const m = lookupRoute(edge, dstPrivate, model.prefixLists);
  const target = m?.route.target;
  const fail = (h: Hop) => {
    hops.push(h);
    return { hops, steps, fail: h };
  };
  // A gateway route table always holds the VPC's local route, even when a snapshot leaves it out.
  if (m && m.route.state !== 'active') {
    return fail({ stage: 'ingress-route', decision: 'block', resourceId: edge.id, detail: `${edge.id} (the route table of ${gatewayId}) sends ${privateText} to a blackhole route.`, docUrl: DOCS.gatewayRouteTables });
  }
  if (m && target?.type === 'vpce' && applianceOf(model, target.id)) {
    hops.push({ stage: 'ingress-route', decision: 'pass', resourceId: edge.id, relatedIds: [target.id], detail: `${edge.id} (the route table of ${gatewayId}): ${m.matchedCidr.text} -> ${target.id}`, docUrl: DOCS.gatewayRouteTables });
    const app = applianceOf(model, target.id)!;
    const epSubnet = app.subnetId ? model.subnets.get(app.subnetId) : undefined;
    if (!epSubnet) return fail({ stage: 'appliance', decision: 'unknown', resourceId: target.id, detail: `The subnet of endpoint ${target.id} is not in the snapshot.`, docUrl: DOCS.gwlbRouting });
    const on = walkRoute(model, epSubnet, clientIp, dstPrivate, 1);
    steps = [
      { kind: 'nacl', check: { subnetId: epSubnet.id, egress: false, peerIp: clientIp, stage: 'appliance-nacl' } },
      { kind: 'appliance', check: { endpointId: target.id, ...(app.firewallArn ? { firewallArn: app.firewallArn } : {}), ...(app.serviceName ? { serviceName: app.serviceName } : {}), subnetId: epSubnet.id, srcIp: clientIp, dstIp: dstPrivate } },
      ...on.steps,
    ];
    if (on.end.kind !== 'delivered' || on.end.subnet.id !== dstSubnet.id) {
      const r = walkHops(model, steps, pkt, span);
      hops.push(...r.hops);
      if (r.blocking) return { hops, steps, fail: r.blocking };
      return fail(
        on.end.kind === 'blocked' || on.end.kind === 'unknown'
          ? { stage: on.end.stage, decision: on.end.kind === 'blocked' ? 'block' : 'unknown', resourceId: on.end.resourceId, detail: on.end.detail }
          : { stage: 'route', decision: 'block', resourceId: epSubnet.id, detail: `After ${target.id}, ${privateText} is routed ${on.end.kind === 'egress' ? `to ${on.end.target.id}` : `to ${on.end.subnet.id}`}, not to ${dstSubnet.id}.`, docUrl: DOCS.gwlbRouting },
      );
    }
    return { hops, steps };
  }
  if (m && target?.type !== 'local') {
    return fail({ stage: 'ingress-route', decision: 'unknown', resourceId: edge.id, relatedIds: target ? [target.id] : [], detail: `${edge.id} (the route table of ${gatewayId}) sends ${privateText} to ${target?.id}, which is not an inspection endpoint Pinhole follows.`, docUrl: DOCS.gatewayRouteTables });
  }
  hops.push({ stage: 'ingress-route', decision: 'pass', resourceId: edge.id, detail: `${edge.id} (the route table of ${gatewayId}): ${m ? m.matchedCidr.text : 'the VPC CIDR'} -> local`, docUrl: DOCS.gatewayRouteTables });
  return { hops, steps };
}

/** Firewalls (by ARN) and appliances (by endpoint) a walk passes. */
const appliancesOn = (walk: Walk): string[] => walk.steps.filter((s): s is { kind: 'appliance'; check: ApplianceCheckpoint } => s.kind === 'appliance').map((s) => s.check.firewallArn ?? s.check.endpointId);

/**
 * A stateful firewall must see both directions of a connection
 * (https://docs.aws.amazon.com/network-firewall/latest/developerguide/arch-igw-ngw.html).
 * A Network Firewall on one direction only is a break; a third-party
 * appliance on one direction only is a caveat.
 */
function symmetryHop(model: NetworkModel, forward: string[], back: string[]): Hop | undefined {
  const one = [...forward.filter((x) => !back.includes(x)), ...back.filter((x) => !forward.includes(x))];
  if (!one.length) return undefined;
  const fw = one.map((x) => model.firewalls.get(x)).find((f) => f);
  if (fw) {
    return { stage: 'firewall', decision: 'block', resourceId: fw.name, relatedIds: [fw.arn], detail: `Only one direction of the connection passes ${fw.name}; its stateful engine drops traffic it did not see start (asymmetric routing). Route both directions through the same firewall endpoint.`, docUrl: DOCS.networkFirewall };
  }
  return { stage: 'appliance', decision: 'pass', resourceId: one[0]!, detail: `Only one direction of the connection passes ${one[0]}.`, caveat: `Only one direction passes the appliance behind ${one[0]}; a stateful appliance drops such connections.`, docUrl: DOCS.gwlbRouting };
}

// ------------------------------------------------------------------ evaluation

/**
 * Target side of a Network Load Balancer with client IP preservation on.
 * The target sees the client's address, so its subnet NACL (inbound), its
 * security groups, and its subnet NACL (outbound, to the client's ephemeral
 * port) are evaluated against the client. A rule referencing the NLB's
 * security group still matches
 * (https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html).
 * Routing back to the client is handled by the load balancer and not checked.
 */
export function evaluateClientPreservedTarget(
  model: NetworkModel,
  clientIp: string,
  target: { eniId: string; ip: string },
  protocol: string,
  port: number,
  nlbGroupIds: string[],
): PathResult {
  const hops: Hop[] = [];
  const warnings: string[] = [];
  const eni = model.enis.get(target.eniId);
  const subnet = eni ? model.subnets.get(eni.subnetId) : undefined;
  const pkt = packetFor(protocol, port);
  const src = parseIpv4(clientIp);
  const done = (verdict: PathResult['verdict'], at?: Hop, extra: Partial<PathResult> = {}): PathResult => ({
    verdict,
    summary: `${describePacket(pkt)} from client ${clientIp} via NLB to ${target.ip}: ${verdict}${at ? ` at ${at.stage}` : ''}`,
    hops,
    ...(at ? { blockedAt: { stage: at.stage, resourceId: at.resourceId, detail: at.detail, ...(at.docUrl ? { docUrl: at.docUrl } : {}) } } : {}),
    warnings,
    ...extra,
  });
  if (!eni || !subnet) return done('unknown', { stage: 'resolve', decision: 'unknown', resourceId: target.eniId, detail: 'Target interface or subnet not in snapshot.' });

  const inNacl = naclHop(model, { subnetId: subnet.id, egress: false, peerIp: src, stage: 'dest-nacl-ingress' }, pkt);
  hops.push(inNacl);
  if (inNacl.decision !== 'pass') return done(inNacl.decision === 'block' ? 'blocked' : 'unknown', inNacl);
  const sgr = sgHop(model, 'dest-sg-ingress', eni, 'ingress', { ip: src, groupIds: nlbGroupIds, relation: { kind: 'same-vpc' } }, pkt);
  hops.push(sgr.hop);
  warnings.push(...sgr.warnings);
  if (sgr.hop.decision !== 'pass') return done(sgr.hop.decision === 'block' ? 'blocked' : 'unknown', sgr.hop);
  const ret = evaluateReturnNacls(model, [{ subnetId: subnet.id, egress: true, peerIp: src, stage: 'return-nacl' }], pkt, CLIENT_PROFILES);
  hops.push(...ret.hops);
  if (ret.coverage === 'none') return done(ret.blockingHop?.decision === 'unknown' ? 'unknown' : 'blocked', ret.blockingHop);
  return done('reachable', undefined, { returnPath: ret.coverage, ...(ret.profiles ? { returnProfiles: ret.profiles } : {}) });
}

export interface EvaluateOptions {
  /** Override the ephemeral profiles used for the return path. */
  returnProfiles?: EphemeralProfile[];
  /**
   * Treat the source as having these security groups for reference matching.
   * Used for NLB client IP preservation, where targets see the client address
   * but a rule referencing the NLB's group still matches.
   */
  sourceGroupIdsOverride?: string[];
}

/** Ports a NAT gateway uses for its side of a translated connection (https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-basics.html). */
export const NAT_PROFILES: EphemeralProfile[] = [{ name: 'NAT gateway', range: { from: 1024, to: 65535 } }];

type Outcome = { verdict: PathResult['verdict']; hops: Hop[]; warnings: string[]; at?: Hop | { stage: Stage; resourceId: string; detail: string; docUrl?: string }; extra?: Partial<PathResult> };

/**
 * An interface opening a connection to an internet address
 * (https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html,
 * https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html):
 *  - its security group must allow it out;
 *  - its subnet's route for the address leads, possibly through firewalls, to
 *    the VPC's internet gateway, and then the interface needs a public IPv4
 *    address or Elastic IP; or to a public NAT gateway that is available,
 *    whose own subnet's route leads, possibly through firewalls, to the
 *    internet gateway;
 *  - network ACLs allow it out and the reply back in, at every subnet boundary,
 *    the NAT gateway's subnet included (replies reach the NAT on its own ports,
 *    1024-65535, and the interface on its ephemeral ports);
 *  - the reply comes back through the internet gateway, whose route table may
 *    send it through the same firewalls; a firewall on one direction only drops it.
 */
function outboundToInternet(model: NetworkModel, eni: Eni, srcIp: number, subnet: Subnet, dstIp: number, pkt: Packet, profiles: EphemeralProfile[]): Outcome {
  const hops: Hop[] = [];
  const warnings: string[] = [];
  const stop = (h: Hop | { stage: Stage; resourceId: string; detail: string; docUrl?: string }, unknown = false): Outcome => ({ verdict: unknown ? 'unknown' : 'blocked', hops, warnings, at: h });
  const span: PortRange = { from: Math.min(...profiles.map((p) => p.range.from)), to: Math.max(...profiles.map((p) => p.range.to)) };

  const sgr = sgHop(model, 'source-sg-egress', eni, 'egress', { ip: dstIp, relation: { kind: 'external' } }, pkt);
  hops.push(sgr.hop);
  warnings.push(...sgr.warnings);
  if (sgr.hop.decision !== 'pass') return stop(sgr.hop, sgr.hop.decision !== 'block');

  const out = walkRoute(model, subnet, srcIp, dstIp);
  const w = walkHops(model, out, pkt, span);
  hops.push(...w.hops);
  if (w.blocking) return stop(w.blocking, w.blocking.decision !== 'block');
  if (out.end.kind === 'blocked') return stop(out.end);
  if (out.end.kind === 'unknown') return stop(out.end, true);
  if (out.end.kind === 'delivered') return stop({ stage: 'route', resourceId: out.end.subnet.id, detail: `${formatIpv4(dstIp)} is routed inside the network, to ${out.end.subnet.id}.` });
  const igwId = attachedIgw(model, subnet.vpcId);
  const target = out.end.target;
  const appliances = [...w.appliances];
  const limit = w.limit;
  let natLimit: PortRange[] | undefined;
  // Return checks: on the interface's side (its ephemeral ports) and on the NAT gateway's.
  const mine: NaclCheckpoint[] = out.steps.filter((x): x is { kind: 'nacl'; check: NaclCheckpoint } => x.kind === 'nacl').map((x) => ({ subnetId: x.check.subnetId, egress: !x.check.egress, peerIp: x.check.egress ? x.check.peerIp : dstIp, stage: 'return-nacl' as Stage }));
  const natSide: NaclCheckpoint[] = [];
  let publicIp: string | undefined;
  let back: { privateIp: number; privateText: string; subnet: Subnet };

  if (target.type === 'igw') {
    if (target.id !== igwId) return stop({ stage: 'route', resourceId: target.id, detail: `${target.id} is not attached to ${subnet.vpcId}.`, docUrl: DOCS.igw });
    const mapping = eni.publicAddresses.find((p) => p.privateIp === formatIpv4(srcIp)) ?? eni.publicAddresses[0];
    if (!mapping) {
      const h: Hop = { stage: 'public-ip', decision: 'block', resourceId: eni.id, detail: `${eni.id} has no public IPv4 address, and its subnet routes the internet straight to ${target.id}; an internet gateway does not translate private addresses.`, docUrl: DOCS.igw };
      hops.push(h);
      return stop(h);
    }
    publicIp = mapping.publicIp;
    hops.push({ stage: 'public-ip', decision: 'pass', resourceId: eni.id, detail: `leaves as ${mapping.elastic ? 'Elastic IP' : 'public IP'} ${mapping.publicIp} through ${target.id}`, docUrl: DOCS.igw });
    back = { privateIp: srcIp, privateText: formatIpv4(srcIp), subnet };
  } else if (target.type === 'nat') {
    const nat = model.natGateways.get(target.id);
    if (!nat) return stop({ stage: 'nat', resourceId: target.id, detail: `NAT gateway ${target.id} is not in the snapshot.` }, true);
    if (nat.state !== 'available') {
      const h: Hop = { stage: 'nat', decision: 'block', resourceId: nat.id, detail: `${nat.id} is ${nat.state}, not available.`, docUrl: DOCS.nat };
      hops.push(h);
      return stop(h);
    }
    if (nat.connectivity === 'private') {
      const h: Hop = { stage: 'nat', decision: 'block', resourceId: nat.id, detail: `${nat.id} is a private NAT gateway; it does not reach the internet.`, docUrl: DOCS.nat };
      hops.push(h);
      return stop(h);
    }
    const natSubnet = model.subnets.get(nat.subnetId);
    const natIp = nat.privateIps[0] ? parseIpv4(nat.privateIps[0]) : [...model.enis.values()].find((e) => e.interfaceType === 'nat_gateway' && e.subnetId === nat.subnetId && e.description.includes(nat.id))?.privateIps[0];
    const natPrivate = typeof natIp === 'string' ? parseIpv4(natIp) : natIp;
    if (!natSubnet || natPrivate === undefined) return stop({ stage: 'nat', resourceId: nat.id, detail: `The subnet or address of ${nat.id} is not in the snapshot.` }, true);
    publicIp = nat.publicIps[0];
    hops.push({ stage: 'nat', decision: 'pass', resourceId: nat.id, detail: `${nat.id} translates ${formatIpv4(srcIp)} to ${publicIp ?? 'its Elastic IP'}`, docUrl: DOCS.nat });
    // Into the NAT gateway's subnet, unless it is the interface's own.
    const pre: WalkStep[] = [];
    if (natSubnet.id !== subnet.id) pre.push({ kind: 'nacl', check: { subnetId: natSubnet.id, egress: false, peerIp: srcIp, stage: 'nat-nacl' } });
    else {
      // Same subnet: the interface's outbound check does not apply after all.
      const i = mine.findIndex((c) => c.subnetId === subnet.id && !c.egress);
      if (i >= 0) mine.splice(i, 1);
    }
    const on = walkRoute(model, natSubnet, natPrivate, dstIp);
    const w2 = walkHops(model, [...pre, ...on.steps], pkt, { from: 1024, to: 65535 });
    // Name the NAT gateway's leg as such.
    hops.push(...w2.hops.map((h) => (h.stage === 'source-nacl-egress' ? { ...h, stage: 'nat-nacl' as Stage } : h.stage === 'route' ? { ...h, stage: 'nat-route' as Stage } : h)));
    if (w2.blocking) return stop(w2.blocking, w2.blocking.decision !== 'block');
    if (on.end.kind === 'blocked') return stop(on.end);
    if (on.end.kind === 'unknown') return stop(on.end, true);
    if (on.end.kind !== 'egress' || on.end.target.type !== 'igw' || on.end.target.id !== igwId) {
      const h: Hop = { stage: 'nat', decision: 'block', resourceId: nat.id, detail: `${nat.id}'s subnet ${natSubnet.id} routes ${formatIpv4(dstIp)} ${on.end.kind === 'egress' ? `to ${on.end.target.id}` : 'inside the network'}, not to an internet gateway.`, docUrl: DOCS.nat };
      hops.push(h);
      return stop(h);
    }
    appliances.push(...w2.appliances);
    if (w2.limit) natLimit = w2.limit;
    // The reply: into the NAT subnet from the internet (NAT ports), out to the interface (its ports), into the interface's subnet.
    for (const st of [...pre, ...on.steps]) if (st.kind === 'nacl') natSide.push({ subnetId: st.check.subnetId, egress: !st.check.egress, peerIp: st.check.egress ? st.check.peerIp : dstIp, stage: 'return-nacl' });
    if (natSubnet.id !== subnet.id) {
      // NAT subnet outbound to the interface, on the interface's ephemeral ports.
      const i = natSide.findIndex((c) => c.subnetId === natSubnet.id && c.egress && c.peerIp === dstIp);
      if (i >= 0) natSide.splice(i, 1);
      mine.push({ subnetId: natSubnet.id, egress: true, peerIp: srcIp, stage: 'return-nacl' });
    }
    back = { privateIp: natPrivate, privateText: formatIpv4(natPrivate), subnet: natSubnet };
  } else {
    const h: Hop = { stage: 'route', decision: target.type === 'eigw' ? 'block' : 'unknown', resourceId: target.id, detail: target.type === 'eigw' ? `${formatIpv4(dstIp)} is routed to an egress-only internet gateway, which carries IPv6 only.` : `${formatIpv4(dstIp)} leaves through ${target.id} (${target.type}); paths beyond it are not followed.`, docUrl: DOCS.routePriority };
    hops.push(h);
    return stop(h, h.decision === 'unknown');
  }

  // The reply comes back through the internet gateway, maybe through its route table's firewall.
  const ing = ingressFromGateway(model, igwId!, dstIp, back.privateIp, back.privateText, back.subnet, { ...pkt }, span);
  for (const h of ing.hops) hops.push({ ...h, stage: h.stage === 'ingress-route' ? 'ingress-route' : h.stage });
  if (ing.fail) return stop(ing.fail, ing.fail.decision !== 'block');
  const backAppliances = ing.steps.filter((x): x is { kind: 'appliance'; check: ApplianceCheckpoint } => x.kind === 'appliance').map((x) => x.check.firewallArn ?? x.check.endpointId);
  const sym = symmetryHop(model, appliances, backAppliances);
  if (sym) {
    hops.push(sym);
    if (sym.decision === 'block') return stop(sym);
  }
  for (const st of ing.steps) if (st.kind === 'nacl' && st.check.stage === 'appliance-nacl') (target.type === 'nat' ? natSide : mine).push({ subnetId: st.check.subnetId, egress: st.check.egress, peerIp: st.check.peerIp, stage: 'return-nacl' });
  if (target.type === 'nat') {
    const r = evaluateReturnNacls(model, natSide, pkt, NAT_PROFILES, natLimit);
    hops.push(...r.hops);
    if (r.coverage === 'none') return stop(r.blockingHop ?? hops[hops.length - 1]!, r.blockingHop?.decision === 'unknown');
    if (r.coverage === 'partial') warnings.push(`Replies reach ${target.id} only on some of its ports; some connections through it fail.`);
  }
  const ret = evaluateReturnNacls(model, mine, pkt, profiles, limit);
  hops.push(...ret.hops);
  if (ret.coverage === 'none') return stop(ret.blockingHop ?? hops[hops.length - 1]!, ret.blockingHop?.decision === 'unknown');
  return { verdict: 'reachable', hops, warnings, extra: { returnPath: ret.coverage, ...(ret.profiles ? { returnProfiles: ret.profiles } : {}), ...(publicIp ? { via: { gateway: target.id, publicIp } } : { via: { gateway: target.id } }) } };
}

const onPremHop = (link: OnPremLink, text: string): Hop => ({
  stage: 'onprem',
  decision: 'pass',
  resourceId: link.id,
  relatedIds: [link.gateway, ...link.connections.map((c) => c.id)],
  detail: `${text}, over ${describeLink(link)}`,
  caveat: link.down ? `${ONPREM_CAVEAT} Every VPN tunnel on it was down when the snapshot was taken.` : ONPREM_CAVEAT,
  docUrl: link.attachment ? DOCS.tgwVpn : DOCS.vpn,
});

/**
 * A packet arriving over an on-premises link, to `dstIp` in `subnet`: through
 * the virtual private gateway's own route table (ingress routing) for a VPN
 * gateway, or by the attachment's route table for a transit gateway.
 * Returns the steps to evaluate, or why it does not arrive.
 */
function arriveFromOnPrem(model: NetworkModel, link: OnPremLink, srcIp: number, dstIp: number, subnet: Subnet, pkt: Packet, span: PortRange): { hops: Hop[]; steps: WalkStep[]; fail?: Hop } {
  if (!link.attachment) {
    if (!link.vpcIds.includes(subnet.vpcId)) {
      const h: Hop = { stage: 'onprem', decision: 'block', resourceId: link.id, detail: `${link.id} is not attached to ${subnet.vpcId}.`, docUrl: DOCS.vpn };
      return { hops: [h], steps: [], fail: h };
    }
    return ingressFromGateway(model, link.id, srcIp, dstIp, formatIpv4(dstIp), subnet, pkt, span);
  }
  const w = walkFromTgwAttachment(model, link.attachment, srcIp, dstIp);
  if (w.end.kind === 'delivered' && w.end.subnet.id === subnet.id) return { hops: [], steps: w.steps };
  const r = walkHops(model, w, pkt, span);
  if (r.blocking) return { hops: r.hops, steps: [], fail: r.blocking };
  const e = w.end;
  const fail: Hop =
    e.kind === 'blocked' || e.kind === 'unknown'
      ? { stage: e.stage, decision: e.kind === 'blocked' ? 'block' : 'unknown', resourceId: e.resourceId, detail: e.detail, ...(e.docUrl ? { docUrl: e.docUrl } : {}) }
      : { stage: 'tgw-route', decision: 'block', resourceId: link.attachment.associatedRouteTableId ?? link.id, detail: `Traffic from ${link.id} to ${formatIpv4(dstIp)} is routed ${e.kind === 'egress' ? `to ${e.attachment?.id ?? e.target.id}` : `to ${e.subnet.id}`}, not to ${subnet.id}.`, docUrl: DOCS.tgwRouteTables };
  return { hops: [...r.hops, fail], steps: [], fail };
}

/**
 * A client on-premises (VPN or Direct Connect) opening a connection to an
 * interface. The interface's subnet route for the client decides which link
 * the replies take, and so, for the connection to work, which link it must
 * arrive over (on-premises routing must be symmetric with it). Then the
 * arrival path, the network ACLs, the security group (the client's own
 * address: security groups cannot reference on-premises groups), and the
 * replies back over the same link.
 */
function fromOnPrem(model: NetworkModel, srcIp: number, eni: Eni, dstIp: number, subnet: Subnet, pkt: Packet, profiles: EphemeralProfile[], groupIds?: string[]): Outcome {
  const hops: Hop[] = [];
  const warnings: string[] = [];
  const stop = (h: Hop | { stage: Stage; resourceId: string; detail: string; docUrl?: string }, unknown = false): Outcome => ({ verdict: unknown ? 'unknown' : 'blocked', hops, warnings, at: h });
  const span: PortRange = { from: Math.min(...profiles.map((p) => p.range.from)), to: Math.max(...profiles.map((p) => p.range.to)) };
  const ip = formatIpv4(srcIp);

  const back = walkRoute(model, subnet, dstIp, srcIp);
  const link = back.end.kind === 'egress' ? linkOf(model, back.end.target, back.end.attachment) : undefined;
  if (!link) {
    if (back.end.kind === 'delivered') return stop({ stage: 'resolve', resourceId: back.end.subnet.id, detail: `${ip} is inside ${back.end.subnet.id}, but no interface in the snapshot has it.` }, true);
    const routeHop = back.steps.find((s) => s.kind === 'hop' && s.hop.stage === 'route');
    const e = back.end;
    const definite = e.kind === 'blocked' || (e.kind === 'egress' && ['igw', 'nat', 'eigw', 'pcx'].includes(e.target.type));
    const why = e.kind === 'egress' ? `${subnet.id} routes it to ${e.target.id}` : e.detail.replace(/\.$/, '');
    const h: Hop = {
      stage: 'return-route',
      decision: definite ? 'block' : 'unknown',
      resourceId: e.kind === 'blocked' || e.kind === 'unknown' ? e.resourceId : routeHop?.kind === 'hop' ? routeHop.hop.resourceId : subnet.id,
      detail: `Replies to ${ip} have no way back on-premises (${why}). It needs a route to a virtual private gateway, or to a transit gateway with a VPN or Direct Connect attachment.`,
      docUrl: DOCS.vpnRouting,
    };
    hops.push(h);
    return stop(h, !definite);
  }
  hops.push(onPremHop(link, `from ${ip} on-premises`));
  const arr = arriveFromOnPrem(model, link, srcIp, dstIp, subnet, pkt, span);
  hops.push(...arr.hops);
  if (arr.fail) return stop(arr.fail, arr.fail.decision !== 'block');
  const inPath = walkHops(model, arr.steps, pkt, span);
  hops.push(...inPath.hops);
  if (inPath.blocking) return stop(inPath.blocking, inPath.blocking.decision !== 'block');

  const sgr = sgHop(model, 'dest-sg-ingress', eni, 'ingress', { ip: srcIp, relation: { kind: 'external' }, ...(groupIds ? { groupIds } : {}) }, pkt);
  hops.push(sgr.hop);
  warnings.push(...sgr.warnings);
  if (sgr.hop.decision !== 'pass') return stop(sgr.hop, sgr.hop.decision !== 'block');

  for (const st of back.steps) if (st.kind === 'hop') hops.push({ ...st.hop, stage: st.hop.stage === 'route' ? 'return-route' : st.hop.stage });
  const sym = symmetryHop(model, inPath.appliances, appliancesOn(back));
  if (sym) {
    hops.push(sym);
    if (sym.decision === 'block') return stop(sym);
  }
  const checks = back.steps.filter((x): x is { kind: 'nacl'; check: NaclCheckpoint } => x.kind === 'nacl').map((x) => ({ ...x.check, stage: 'return-nacl' as Stage }));
  const ret = evaluateReturnNacls(model, checks, pkt, profiles, inPath.limit);
  hops.push(...ret.hops);
  if (ret.coverage === 'none') return stop(ret.blockingHop ?? hops[hops.length - 1]!, ret.blockingHop?.decision === 'unknown');
  return { verdict: 'reachable', hops, warnings, extra: { returnPath: ret.coverage, ...(ret.profiles ? { returnProfiles: ret.profiles } : {}), via: { gateway: link.id } } };
}

/**
 * An interface opening a connection to an address on-premises, after its
 * security group and route have sent it to a VPN or Direct Connect link: the
 * replies must come back over the same link to its subnet, through the same
 * firewalls, and its network ACLs must let them in on its ephemeral ports.
 */
function toOnPrem(model: NetworkModel, link: OnPremLink, srcIp: number, subnet: Subnet, dstIp: number, pkt: Packet, profiles: EphemeralProfile[], forwardAppliances: string[], limit: PortRange[] | undefined): Outcome {
  const hops: Hop[] = [onPremHop(link, `to ${formatIpv4(dstIp)} on-premises`)];
  const warnings: string[] = [];
  const stop = (h: Hop, unknown = false): Outcome => ({ verdict: unknown ? 'unknown' : 'blocked', hops, warnings, at: h });
  const span: PortRange = { from: Math.min(...profiles.map((p) => p.range.from)), to: Math.max(...profiles.map((p) => p.range.to)) };
  const reply = arriveFromOnPrem(model, link, dstIp, srcIp, subnet, pkt, span);
  hops.push(...reply.hops.map((h) => (h.stage === 'tgw-route' || h.stage === 'ingress-route' ? { ...h, stage: 'return-route' as Stage } : h)));
  if (reply.fail) return stop(hops[hops.length - 1]!, reply.fail.decision !== 'block');
  const back = reply.steps.filter((x): x is { kind: 'appliance'; check: ApplianceCheckpoint } => x.kind === 'appliance').map((x) => x.check.firewallArn ?? x.check.endpointId);
  const sym = symmetryHop(model, forwardAppliances, back);
  if (sym) {
    hops.push(sym);
    if (sym.decision === 'block') return stop(sym);
  }
  for (const st of reply.steps) if (st.kind === 'hop') hops.push({ ...st.hop, stage: st.hop.stage === 'tgw-route' || st.hop.stage === 'dest-vpc-route' ? 'return-route' : st.hop.stage });
  const checks = reply.steps.filter((x): x is { kind: 'nacl'; check: NaclCheckpoint } => x.kind === 'nacl').map((x) => ({ ...x.check, stage: 'return-nacl' as Stage }));
  const ret = evaluateReturnNacls(model, checks, pkt, profiles, limit);
  hops.push(...ret.hops);
  if (ret.coverage === 'none') return stop(ret.blockingHop ?? hops[hops.length - 1]!, ret.blockingHop?.decision === 'unknown');
  return { verdict: 'reachable', hops, warnings, extra: { returnPath: ret.coverage, ...(ret.profiles ? { returnProfiles: ret.profiles } : {}), via: { gateway: link.id } } };
}

export function evaluatePath(model: NetworkModel, query: PathQuery, options: EvaluateOptions = {}): PathResult {
  const warnings: string[] = [];
  const hops: Hop[] = [];

  let src: Resolved;
  let dst: Resolved;
  let pkt: Packet;
  try {
    src = resolve(model, query.from);
    dst = resolve(model, query.to);
    pkt = packetFor(query.protocol, query.port);
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    return { verdict: 'unknown', summary: detail, hops: [], blockedAt: { stage: 'resolve', resourceId: '', detail }, warnings };
  }

  const finish = (verdict: PathResult['verdict'], at?: Hop | { stage: Stage; resourceId: string; detail: string; docUrl?: string }, extra: Partial<PathResult> = {}): PathResult => {
    const blockedAt = at ? { stage: at.stage, resourceId: at.resourceId, detail: at.detail, ...(at.docUrl ? { docUrl: at.docUrl } : {}) } : undefined;
    const what = `${describePacket(pkt)} from ${formatIpv4(src.ip)} to ${formatIpv4(dst.ip)}`;
    const summary =
      verdict === 'reachable'
        ? `${what}: reachable${extra.returnPath === 'partial' ? ' (return traffic only for some client port ranges)' : ''}`
        : verdict === 'blocked'
          ? `${what}: blocked at ${blockedAt?.stage} (${blockedAt?.detail})`
          : `${what}: unknown at ${blockedAt?.stage} (${blockedAt?.detail})`;
    return { verdict, summary, hops, ...(blockedAt ? { blockedAt } : {}), warnings, ...extra };
  };

  if (dst.kind === 'internet' && src.kind === 'eni') {
    const r = outboundToInternet(model, src.eni, src.ip, src.subnet, dst.ip, pkt, options.returnProfiles ?? CLIENT_PROFILES);
    hops.push(...r.hops);
    warnings.push(...r.warnings);
    return finish(r.verdict, r.at, r.extra);
  }
  if (dst.kind !== 'eni') {
    if (src.kind !== 'eni') return finish('unknown', { stage: 'resolve', resourceId: '', detail: 'At least one end of a query must be an interface in the snapshot.' });
    // Outbound to an address outside the snapshot: we can follow it until it
    // leaves the modelled network, but cannot see the far end.
    const sgr = sgHop(model, 'source-sg-egress', src.eni, 'egress', { ip: dst.ip, relation: { kind: 'external' } }, pkt);
    hops.push(sgr.hop);
    warnings.push(...sgr.warnings);
    if (sgr.hop.decision !== 'pass') return finish(sgr.hop.decision === 'block' ? 'blocked' : 'unknown', sgr.hop);
    const walk = walkRoute(model, src.subnet, src.ip, dst.ip);
    const w = walkHops(model, walk, pkt);
    hops.push(...w.hops);
    if (w.blocking) return finish(w.blocking.decision === 'block' ? 'blocked' : 'unknown', w.blocking);
    if (walk.end.kind === 'blocked') return finish('blocked', walk.end);
    if (walk.end.kind === 'unknown') return finish('unknown', walk.end);
    const link = walk.end.kind === 'egress' ? linkOf(model, walk.end.target, walk.end.attachment) : undefined;
    if (link) {
      const r = toOnPrem(model, link, src.ip, src.subnet, dst.ip, pkt, options.returnProfiles ?? CLIENT_PROFILES, w.appliances, w.limit);
      hops.push(...r.hops);
      warnings.push(...r.warnings);
      return finish(r.verdict, r.at, r.extra);
    }
    const leaves = walk.end.kind === 'egress' ? `leaves through ${walk.end.target.id}` : 'arrives at an address with no interface in the snapshot';
    return finish('unknown', { stage: 'scope', resourceId: walk.end.kind === 'egress' ? walk.end.target.id : '', detail: `Traffic ${leaves}; the far end is outside the snapshot.` });
  }

  const dstEni = dst.eni;
  const profiles = options.returnProfiles ?? (src.kind === 'eni' && isElbNode(src.eni) ? ELB_PROFILES : CLIENT_PROFILES);

  // ---------------------------------------------------------------- internet source
  if (src.kind === 'internet' || src.kind === 'outside') {
    if (src.kind === 'outside') {
      const r = fromOnPrem(model, src.ip, dstEni, dst.ip, dst.subnet, pkt, profiles, options.sourceGroupIdsOverride);
      hops.push(...r.hops);
      warnings.push(...r.warnings);
      return finish(r.verdict, r.at, r.extra);
    }
    const mapping = dstEni.publicAddresses.find((p) => p.privateIp === formatIpv4(dst.ip)) ?? dstEni.publicAddresses[0];
    if (!mapping) {
      const h: Hop = { stage: 'public-ip', decision: 'block', resourceId: dstEni.id, detail: `${dstEni.id} has no public IPv4 address or Elastic IP.`, docUrl: DOCS.igw };
      hops.push(h);
      return finish('blocked', h);
    }
    const dstPrivate = parseIpv4(mapping.privateIp);
    hops.push({ stage: 'public-ip', decision: 'pass', resourceId: dstEni.id, detail: `${mapping.elastic ? 'Elastic IP' : 'public IP'} ${mapping.publicIp} -> ${mapping.privateIp}`, docUrl: DOCS.igw });
    const igwId = attachedIgw(model, dst.subnet.vpcId);
    if (!igwId) {
      const h: Hop = { stage: 'igw', decision: 'block', resourceId: dst.subnet.vpcId, detail: `${dst.subnet.vpcId} has no attached internet gateway.`, docUrl: DOCS.igw };
      hops.push(h);
      return finish('blocked', h);
    }
    hops.push({ stage: 'igw', decision: 'pass', resourceId: igwId, detail: `${igwId} attached to ${dst.subnet.vpcId}`, docUrl: DOCS.igw });
    const span: PortRange = { from: Math.min(...profiles.map((p) => p.range.from)), to: Math.max(...profiles.map((p) => p.range.to)) };

    // Inbound: the gateway's own route table (ingress routing) may send the
    // packet through a firewall or appliance before it reaches the subnet.
    const ing = ingressFromGateway(model, igwId, src.ip, dstPrivate, mapping.privateIp, dst.subnet, pkt, span);
    hops.push(...ing.hops);
    if (ing.fail) return finish(ing.fail.decision === 'block' ? 'blocked' : 'unknown', ing.fail);
    const inbound = ing.steps;
    const inPath = walkHops(model, inbound, pkt, span);
    hops.push(...inPath.hops);
    if (inPath.blocking) return finish(inPath.blocking.decision === 'block' ? 'blocked' : 'unknown', inPath.blocking);
    const sgPeer: SgPeer = { ip: src.ip, relation: { kind: 'external' }, ...(options.sourceGroupIdsOverride ? { groupIds: options.sourceGroupIdsOverride } : {}) };
    const sgr = sgHop(model, 'dest-sg-ingress', dstEni, 'ingress', sgPeer, pkt);
    hops.push(sgr.hop);
    warnings.push(...sgr.warnings);
    if (sgr.hop.decision !== 'pass') return finish(sgr.hop.decision === 'block' ? 'blocked' : 'unknown', sgr.hop);

    // Return: the subnet's route for the client must lead, through the same appliances, to the same IGW.
    const back = walkRoute(model, dst.subnet, dstPrivate, src.ip);
    const routeHop = back.steps.find((s) => s.kind === 'hop' && s.hop.stage === 'route');
    if (back.end.kind !== 'egress' || back.end.target.type !== 'igw' || back.end.target.id !== igwId) {
      const via = back.end.kind === 'egress' ? back.end.target.id : back.end.kind === 'blocked' || back.end.kind === 'unknown' ? back.end.detail : 'a VPC destination';
      // A NAT gateway rewrites the source address, so the client never sees a
      // reply from the address it connected to: blocked. A VPN gateway or an
      // instance may forward the reply on: not modelled, unknown.
      const definite = back.end.kind === 'blocked' || (back.end.kind === 'egress' && (back.end.target.type === 'nat' || back.end.target.type === 'igw'));
      const h: Hop = {
        stage: 'return-route',
        decision: definite ? 'block' : 'unknown',
        resourceId: routeHop?.kind === 'hop' ? routeHop.hop.resourceId : dst.subnet.id,
        detail: `Response to ${formatIpv4(src.ip)} is routed to ${via}, not ${igwId}${routeHop?.kind === 'hop' ? ` (${routeHop.hop.detail})` : ''}.`,
        docUrl: DOCS.igw,
      };
      hops.push(h);
      return finish(h.decision === 'unknown' ? 'unknown' : 'blocked', h);
    }
    for (const st of back.steps) if (st.kind === 'hop') hops.push({ ...st.hop, stage: st.hop.stage === 'route' ? 'return-route' : st.hop.stage });
    const sym = symmetryHop(model, inPath.appliances, appliancesOn(back));
    if (sym) {
      hops.push(sym);
      if (sym.decision === 'block') return finish('blocked', sym);
    }
    const checks = back.steps.filter((x): x is { kind: 'nacl'; check: NaclCheckpoint } => x.kind === 'nacl').map((x) => ({ ...x.check, stage: 'return-nacl' as Stage }));
    const ret = evaluateReturnNacls(model, checks, pkt, profiles, inPath.limit);
    hops.push(...ret.hops);
    if (ret.coverage === 'none') return finish(ret.blockingHop?.decision === 'unknown' ? 'unknown' : 'blocked', ret.blockingHop ?? inPath.hops.find((h) => h.stage === 'firewall'));
    return finish('reachable', undefined, { returnPath: ret.coverage, ...(ret.profiles ? { returnProfiles: ret.profiles } : {}) });
  }

  // ---------------------------------------------------------------- interface to interface
  const srcEni = src.eni;
  const forward = walkRoute(model, src.subnet, src.ip, dst.ip);
  const relation: PeerRelation = forward.end.kind === 'delivered' ? forward.end.relation : { kind: 'same-vpc' };

  const egr = sgHop(model, 'source-sg-egress', srcEni, 'egress', { ip: dst.ip, groupIds: dstEni.groupIds, relation }, pkt);
  hops.push(egr.hop);
  warnings.push(...egr.warnings);
  if (egr.hop.decision !== 'pass') return finish(egr.hop.decision === 'block' ? 'blocked' : 'unknown', egr.hop);

  const span: PortRange = { from: Math.min(...profiles.map((p) => p.range.from)), to: Math.max(...profiles.map((p) => p.range.to)) };
  const fw = walkHops(model, forward, pkt, span);
  hops.push(...fw.hops);
  if (fw.blocking) return finish(fw.blocking.decision === 'block' ? 'blocked' : 'unknown', fw.blocking);
  if (forward.end.kind === 'blocked') return finish('blocked', forward.end);
  if (forward.end.kind === 'unknown') return finish('unknown', forward.end);
  if (forward.end.kind === 'egress') {
    // The packet leaves through a NAT gateway, VPN gateway, endpoint or
    // appliance. It may still arrive (for example through an inspection
    // appliance), but v1 does not follow it, so the answer is unknown.
    return finish('unknown', { stage: 'scope', resourceId: forward.end.target.id, detail: `${formatIpv4(dst.ip)} is routed to ${forward.end.target.id} (${forward.end.target.type}); paths through it are not followed in v1.`, docUrl: DOCS.routePriority });
  }
  if (forward.end.subnet.id !== dst.subnet.id) {
    return finish('blocked', { stage: 'route', resourceId: forward.end.subnet.id, detail: `Routing delivers ${formatIpv4(dst.ip)} to ${forward.end.subnet.id}, not to ${dst.subnet.id}.` });
  }

  const ing = sgHop(model, 'dest-sg-ingress', dstEni, 'ingress', { ip: src.ip, groupIds: options.sourceGroupIdsOverride ?? srcEni.groupIds, relation }, pkt);
  hops.push(ing.hop);
  warnings.push(...ing.warnings);
  if (ing.hop.decision !== 'pass') return finish(ing.hop.decision === 'block' ? 'blocked' : 'unknown', ing.hop);

  // Return traffic: needs its own route back and passes the NACLs again.
  const back = walkRoute(model, dst.subnet, dst.ip, src.ip);
  const routeHops = back.steps.filter((s): s is { kind: 'hop'; hop: Hop } => s.kind === 'hop').map((s) => ({ ...s.hop, stage: (s.hop.stage === 'route' ? 'return-route' : s.hop.stage) as Stage }));
  const failedRoute = routeHops.find((h) => h.decision === 'block' || h.decision === 'unknown');
  if (back.end.kind !== 'delivered' || back.end.subnet.id !== src.subnet.id || failedRoute) {
    hops.push(...routeHops);
    const detail =
      back.end.kind === 'blocked' || back.end.kind === 'unknown'
        ? back.end.detail
        : back.end.kind === 'egress'
          ? `routed to ${back.end.target.id}`
          : `delivered to ${back.end.subnet.id} instead of ${src.subnet.id}`;
    const decision = back.end.kind === 'unknown' || back.end.kind === 'egress' ? 'unknown' : 'block';
    const h: Hop = {
      stage: 'return-route',
      decision,
      resourceId: back.end.kind === 'blocked' || back.end.kind === 'unknown' ? back.end.resourceId : dst.subnet.id,
      detail: `Return traffic to ${formatIpv4(src.ip)}: ${detail}`,
      ...(back.end.kind === 'blocked' && back.end.docUrl ? { docUrl: back.end.docUrl } : {}),
    };
    hops.push(h);
    return finish(h.decision === 'unknown' ? 'unknown' : 'blocked', h);
  }
  hops.push(...routeHops);
  const sym = symmetryHop(model, fw.appliances, appliancesOn(back));
  if (sym) {
    hops.push(sym);
    if (sym.decision === 'block') return finish('blocked', sym);
  }
  const checks = back.steps.filter((s): s is { kind: 'nacl'; check: NaclCheckpoint } => s.kind === 'nacl').map((s) => s.check);
  const ret = evaluateReturnNacls(model, checks, pkt, profiles, fw.limit);
  hops.push(...ret.hops);
  if (ret.coverage === 'none') return finish(ret.blockingHop?.decision === 'unknown' ? 'unknown' : 'blocked', ret.blockingHop ?? fw.hops.find((h) => h.stage === 'firewall'));
  return finish('reachable', undefined, { returnPath: ret.coverage, ...(ret.profiles ? { returnProfiles: ret.profiles } : {}) });
}
