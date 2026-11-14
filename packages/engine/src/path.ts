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
import type { Hop, NaclCheckpoint, Stage, Walk } from './walk.js';
import { walkRoute } from './walk.js';

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
    detail: `${acl.id} ${dir} rule ${rule} ${d.action}s ${describePacket(pkt)} ${check.egress ? 'to' : 'from'} ${formatIpv4(check.peerIp)}`,
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
  let allowed: PortRange[] = [span];
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

function walkHops(model: NetworkModel, walk: Walk, pkt: Packet): { hops: Hop[]; blocking?: Hop } {
  const hops: Hop[] = [];
  for (const s of walk.steps) {
    const h = s.kind === 'hop' ? s.hop : naclHop(model, s.check, pkt);
    hops.push(h);
    if (h.decision === 'block' || h.decision === 'unknown') return { hops, blocking: h };
  }
  return { hops };
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
    const leaves = walk.end.kind === 'egress' ? `leaves through ${walk.end.target.id}` : 'arrives at an address with no interface in the snapshot';
    return finish('unknown', { stage: 'scope', resourceId: walk.end.kind === 'egress' ? walk.end.target.id : '', detail: `Traffic ${leaves}; the far end is outside the snapshot.` });
  }

  const dstEni = dst.eni;
  const profiles = options.returnProfiles ?? (src.kind === 'eni' && isElbNode(src.eni) ? ELB_PROFILES : CLIENT_PROFILES);

  // ---------------------------------------------------------------- internet source
  if (src.kind === 'internet' || src.kind === 'outside') {
    if (src.kind === 'outside') {
      return finish('unknown', { stage: 'resolve', resourceId: '', detail: `${formatIpv4(src.ip)} is a private address outside the snapshot; use an interface or an internet address as the source.` });
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
    const edge = [...model.routeTables.values()].find((rt) => rt.gatewayIds.includes(igwId));
    if (edge) {
      const h: Hop = { stage: 'scope', decision: 'unknown', resourceId: edge.id, detail: `${igwId} has a gateway route table (${edge.id}); ingress routing through an appliance is not modelled in v1.`, docUrl: DOCS.gatewayRouteTables };
      hops.push(h);
      return finish('unknown', h);
    }
    const inNacl = naclHop(model, { subnetId: dst.subnet.id, egress: false, peerIp: src.ip, stage: 'dest-nacl-ingress' }, pkt);
    hops.push(inNacl);
    if (inNacl.decision !== 'pass') return finish(inNacl.decision === 'block' ? 'blocked' : 'unknown', inNacl);
    const sgPeer: SgPeer = { ip: src.ip, relation: { kind: 'external' }, ...(options.sourceGroupIdsOverride ? { groupIds: options.sourceGroupIdsOverride } : {}) };
    const sgr = sgHop(model, 'dest-sg-ingress', dstEni, 'ingress', sgPeer, pkt);
    hops.push(sgr.hop);
    warnings.push(...sgr.warnings);
    if (sgr.hop.decision !== 'pass') return finish(sgr.hop.decision === 'block' ? 'blocked' : 'unknown', sgr.hop);

    // Return: the subnet's route for the client must lead to the same IGW.
    const back = walkRoute(model, dst.subnet, dstPrivate, src.ip);
    const routeHop = back.steps.find((s) => s.kind === 'hop' && s.hop.stage === 'route');
    if (back.end.kind !== 'egress' || back.end.target.type !== 'igw' || back.end.target.id !== igwId) {
      const via = back.end.kind === 'egress' ? back.end.target.id : back.end.kind === 'blocked' || back.end.kind === 'unknown' ? back.end.detail : 'a VPC destination';
      // A NAT gateway rewrites the source address, so the client never sees a
      // reply from the address it connected to: blocked. An appliance, firewall
      // endpoint or VPN gateway may forward the reply on: not modelled, unknown.
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
    if (routeHop?.kind === 'hop') hops.push({ ...routeHop.hop, stage: 'return-route' });
    const ret = evaluateReturnNacls(model, [{ subnetId: dst.subnet.id, egress: true, peerIp: src.ip, stage: 'return-nacl' }], pkt, profiles);
    hops.push(...ret.hops);
    if (ret.coverage === 'none') return finish(ret.blockingHop?.decision === 'unknown' ? 'unknown' : 'blocked', ret.blockingHop);
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

  const fw = walkHops(model, forward, pkt);
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
  const checks = back.steps.filter((s): s is { kind: 'nacl'; check: NaclCheckpoint } => s.kind === 'nacl').map((s) => s.check);
  const ret = evaluateReturnNacls(model, checks, pkt, profiles);
  hops.push(...ret.hops);
  if (ret.coverage === 'none') return finish(ret.blockingHop?.decision === 'unknown' ? 'unknown' : 'blocked', ret.blockingHop);
  return finish('reachable', undefined, { returnPath: ret.coverage, ...(ret.profiles ? { returnProfiles: ret.profiles } : {}) });
}
