/**
 * Repair: the smallest set of changes that makes a blocked connection work,
 * each one verified by evaluating the path again.
 *
 * The connection is evaluated; at the hop that stops it (or, for a partial
 * return path, the network ACL that turns replies away), one narrow change
 * is proposed that lets exactly this traffic through:
 *  - a security group: a rule for this protocol and port, from the source's
 *    own security group when both ends are in one VPC (so it follows the
 *    source if its address changes), otherwise from its address (/32);
 *  - a network ACL: an allow entry for the peer's address (/32) and this
 *    port (the client's ephemeral range for replies), numbered just below
 *    the entry that denies it, so it is evaluated first;
 *  - a route: to the gateway, peering connection, transit gateway or VPN
 *    gateway that already connects the two ends, for the narrowest
 *    destination that does the job;
 *  - a public IP or an internet gateway, when those are what is missing.
 * The change is applied to a copy of the model and the path evaluated again,
 * until it works, a hop is reached that cannot be repaired by configuration
 * Pinhole can write (a firewall rule, a NAT gateway, an appliance), or no
 * progress is made. Then the internet exposure before and after is compared,
 * so a repair that opens something to the internet says so.
 */
import { analyzeExposure } from './exposure.js';
import { formatIpv4, INTERNET, parseIpv4 } from './ipv4.js';
import { onPremLinks, onPremNetworks } from './onprem.js';
import { evaluatePath, CLIENT_PROFILES } from './path.js';
import type { PathQuery, PathResult } from './path.js';
import { attachedIgw, eniByPrivateIp, naclForSubnet, routeTableForSubnet } from './topology.js';
import { applyChanges, cliFor, describeChange, diffExposure } from './whatif.js';
import type { Change, ExposureDelta } from './whatif.js';
import type { Eni, NetworkModel, Subnet } from './types.js';
import type { Hop } from './walk.js';

export interface RepairStep {
  /** The hop that stopped the connection. */
  blockedAt: { stage: string; resourceId: string; detail: string };
  change: Change;
  text: string;
  cli: string[];
  /** Why this change, and anything to know about it. */
  notes: string[];
}

export interface RepairResult {
  /** already: it works; repaired: the steps make it work; partial: it works only for some client ports; stuck: a hop cannot be repaired. */
  verdict: 'already' | 'repaired' | 'partial' | 'stuck';
  before: PathResult;
  after: PathResult;
  steps: RepairStep[];
  stuck?: { stage: string; resourceId: string; detail: string; advice: string };
  /** Internet exposure the steps would add or widen. */
  opens: ExposureDelta[];
}

type End = { kind: 'eni'; eni: Eni; ip: number; subnet: Subnet } | { kind: 'outside'; ip: number; internet: boolean };

function endOf(model: NetworkModel, ep: PathQuery['from']): End | undefined {
  let eni: Eni | undefined;
  if ('eni' in ep) eni = model.enis.get(ep.eni);
  else if ('instance' in ep) {
    const id = model.instances.get(ep.instance)?.primaryEniId;
    eni = id ? model.enis.get(id) : undefined;
  } else {
    const text = 'internet' in ep ? ep.internet : ep.ip;
    const ip = parseIpv4(text);
    eni = eniByPrivateIp(model, ip);
    if (!eni) return { kind: 'outside', ip, internet: INTERNET.containsIp(ip) };
  }
  if (!eni) return undefined;
  const subnet = model.subnets.get(eni.subnetId);
  const ipText = 'eni' in ep && ep.ip ? ep.ip : 'ip' in ep ? ep.ip : eni.privateIps[0];
  if (!subnet || !ipText) return undefined;
  return { kind: 'eni', eni, ip: parseIpv4(ipText), subnet };
}

/** The group of an interface attached to the fewest other interfaces: a rule there opens the least. */
function narrowestGroup(model: NetworkModel, eni: Eni): string | undefined {
  const members = (g: string) => [...model.enis.values()].filter((e) => e.groupIds.includes(g)).length;
  return [...eni.groupIds].sort((a, b) => members(a) - members(b) || a.localeCompare(b))[0];
}

const protoText = (p: string) => p.toLowerCase();
const ephemeral = () => ({ from: Math.min(...CLIENT_PROFILES.map((p) => p.range.from)), to: Math.max(...CLIENT_PROFILES.map((p) => p.range.to)) });

/** A free rule number below `n` in one direction of a network ACL, as high as possible. */
function freeNumberBelow(model: NetworkModel, naclId: string, egress: boolean, n: number): number | undefined {
  const acl = model.nacls.get(naclId);
  const used = new Set((acl?.entries ?? []).filter((e) => e.egress === egress).map((e) => e.ruleNumber));
  for (let k = n - 1; k >= 1; k--) if (!used.has(k)) return k;
  return undefined;
}

const peerOf = (h: Hop) => /(?:to|from) (\d+\.\d+\.\d+\.\d+)/.exec(h.detail)?.[1];
const naclRef = (h: Hop) => {
  const m = /^(acl-[^#]+)#(ingress|egress)#(\d+|\*)$/.exec(h.ruleIds?.[0] ?? '');
  return m ? { naclId: m[1]!, egress: m[2] === 'egress', rule: m[3] === '*' ? 32767 : Number(m[3]) } : undefined;
};

/** For a partial return path: the network ACL hop that turns some client ports away. */
function partialReturnHop(r: PathResult): Hop | undefined {
  return r.hops.find((h) => {
    const m = h.stage === 'return-nacl' ? /ports (.+) of (\d+-\d+) allowed/.exec(h.detail) : null;
    return !!m && m[1] !== m[2];
  });
}

interface Ctx {
  model: NetworkModel;
  query: PathQuery;
  src: End;
  dst: End;
}

type Proposal = { change: Change; notes: string[] } | { advice: string };

function routeTo(ctx: Ctx, from: Subnet, toIp: number, toEnd: End): Proposal {
  const { model } = ctx;
  const rt = routeTableForSubnet(model, from);
  if (!rt) return { advice: `${from.id} has no route table in the snapshot.` };
  let target: string | undefined;
  let dest: string | undefined;
  const notes: string[] = [];
  if (toEnd.kind === 'eni' && toEnd.subnet.vpcId !== from.vpcId) {
    const other = model.vpcs.get(toEnd.subnet.vpcId);
    const pcx = [...model.peerings.values()].find((p) => p.status === 'active' && ((p.requesterVpcId === from.vpcId && p.accepterVpcId === toEnd.subnet.vpcId) || (p.accepterVpcId === from.vpcId && p.requesterVpcId === toEnd.subnet.vpcId)));
    const cidr = other?.cidrs.find((c) => toIp >= c.start && toIp <= c.end)?.text;
    if (pcx) target = pcx.id;
    else {
      const atts = [...model.tgwAttachments.values()].filter((a) => a.resourceType === 'vpc' && a.state === 'available');
      const mine = atts.find((a) => a.resourceId === from.vpcId);
      const theirs = mine && atts.find((a) => a.resourceId === toEnd.subnet.vpcId && a.tgwId === mine.tgwId);
      if (theirs) target = mine!.tgwId;
    }
    if (!target) return { advice: `${from.vpcId} and ${toEnd.subnet.vpcId} are not connected by an active peering connection or a shared transit gateway. Create one first; then a route can use it.` };
    dest = cidr ?? `${formatIpv4(toIp)}/32`;
  } else if (toEnd.kind === 'outside' && toEnd.internet) {
    const igw = attachedIgw(model, from.vpcId);
    if (!igw) return { advice: `${from.vpcId} has no internet gateway attached.` };
    // Outbound from a server without a public address: through a NAT gateway that already reaches the internet.
    const self = ctx.src.kind === 'eni' && ctx.src.subnet.id === from.id ? ctx.src.eni : undefined;
    const nat = self && !self.publicAddresses.length
      ? [...model.natGateways.values()].find((n) => {
          const ns = model.subnets.get(n.subnetId);
          const nrt = ns && routeTableForSubnet(model, ns);
          return n.vpcId === from.vpcId && n.state === 'available' && n.connectivity === 'public' && n.subnetId !== from.id && !!nrt?.routes.some((r) => r.destination?.text === '0.0.0.0/0' && r.target.id === igw);
        })
      : undefined;
    target = nat?.id ?? igw;
    if (nat) notes.push(`${self!.id} has no public address, so it goes out through ${nat.id}, whose subnet already routes to ${igw}.`);
    const hasDefault = rt.routes.some((r) => r.destination?.text === '0.0.0.0/0');
    dest = hasDefault ? `${formatIpv4(toIp)}/32` : '0.0.0.0/0';
    if (hasDefault) notes.push(`${rt.id} already sends 0.0.0.0/0 elsewhere, so the route covers only ${formatIpv4(toIp)}. A server that should be reached from the internet usually belongs in a public subnet instead.`);
  } else if (toEnd.kind === 'outside') {
    const net = onPremNetworks(model).find((n) => toIp >= n.range.start && toIp <= n.range.end);
    const link = onPremLinks(model).find((l) => (l.attachment ? [...model.tgwAttachments.values()].some((a) => a.tgwId === l.gateway && a.resourceType === 'vpc' && a.resourceId === from.vpcId) : l.vpcIds.includes(from.vpcId)) && (!net || net.links.includes(l.id)));
    if (!link) return { advice: `No VPN or Direct Connect link reaches ${from.vpcId} for ${formatIpv4(toIp)}.` };
    target = link.attachment ? link.gateway : link.id;
    dest = net ? `${formatIpv4(net.range.start)}/${32 - Math.log2(net.range.end - net.range.start + 1)}` : `${formatIpv4(toIp)}/32`;
    if (link.attachment) notes.push(`The transit gateway's route table must also send ${dest} to ${link.id}; check it after the change.`);
  } else return { advice: `${formatIpv4(toIp)} is in the same VPC; the local route already covers it.` };
  const shared = rt.isMain ? [...model.subnets.values()].filter((x) => x.vpcId === rt.vpcId && routeTableForSubnet(model, x)?.id === rt.id).length : rt.subnetIds.length;
  if (shared > 1 || rt.isMain) notes.push(`${rt.id} is ${rt.isMain ? 'the main route table of its VPC' : 'shared'}: the route applies to ${shared} subnet${shared === 1 ? '' : 's'}.`);
  if (rt.routes.some((r) => r.destination?.text === dest)) return { advice: `${rt.id} already has a route for ${dest} to another target; replace it (aws ec2 replace-route) if that target is wrong.` };
  return { change: { kind: 'add-route', routeTableId: rt.id, destination: dest!, targetId: target! }, notes };
}

function propose(ctx: Ctx, r: PathResult): { hop: Hop; p: Proposal } | undefined {
  const { model, query, src, dst } = ctx;
  const proto = protoText(query.protocol);
  const port = query.port;
  const ports = proto === 'icmp' ? {} : port !== undefined ? { fromPort: port, toPort: port } : {};
  const blocking = r.blockedAt ? r.hops.find((h) => h.stage === r.blockedAt!.stage && h.resourceId === r.blockedAt!.resourceId && (h.decision === 'block' || h.decision === 'unknown')) ?? ({ ...r.blockedAt, decision: 'block' } as Hop) : partialReturnHop(r);
  if (!blocking) return undefined;
  const h = blocking;
  const sameVpc = src.kind === 'eni' && dst.kind === 'eni' && src.subnet.vpcId === dst.subnet.vpcId;

  switch (h.stage) {
    case 'dest-sg-ingress': {
      if (dst.kind !== 'eni') break;
      const g = narrowestGroup(model, dst.eni);
      if (!g) break;
      const ref = sameVpc && src.kind === 'eni' ? narrowestGroup(model, src.eni) : undefined;
      const others = [...model.enis.values()].filter((e) => e.id !== dst.eni.id && e.groupIds.includes(g)).length;
      return {
        hop: h,
        p: {
          change: { kind: 'add-sg-rule', groupId: g, egress: false, protocol: proto, ...ports, ...(ref ? { referencedGroupId: ref } : { cidr: `${formatIpv4(src.ip)}/32` }), description: 'Added by pinhole repair' },
          notes: [ref ? `From ${ref}, the source's own group, so it keeps working if the source's address changes.` : `From ${formatIpv4(src.ip)} only.`, ...(others ? [`${g} is also attached to ${others} other interface${others === 1 ? '' : 's'}; they get the same rule.`] : [])],
        },
      };
    }
    case 'source-sg-egress': {
      if (src.kind !== 'eni') break;
      const g = narrowestGroup(model, src.eni);
      if (!g) break;
      const ref = sameVpc && dst.kind === 'eni' ? narrowestGroup(model, dst.eni) : undefined;
      return { hop: h, p: { change: { kind: 'add-sg-rule', groupId: g, egress: true, protocol: proto, ...ports, ...(ref ? { referencedGroupId: ref } : { cidr: `${formatIpv4(dst.ip)}/32` }), description: 'Added by pinhole repair' }, notes: [ref ? `To ${ref}, the destination's own group.` : `To ${formatIpv4(dst.ip)} only.`] } };
    }
    case 'source-nacl-egress':
    case 'dest-nacl-ingress':
    case 'tgw-nacl':
    case 'nat-nacl':
    case 'appliance-nacl':
    case 'return-nacl': {
      const ref = naclRef(h);
      const peer = peerOf(h);
      if (!ref || !peer) break;
      const ret = h.stage === 'return-nacl';
      // Replies go to the client's ephemeral ports; requests to the service port.
      const range = ret ? ephemeral() : port !== undefined ? { from: port, to: port } : undefined;
      const limit = ret ? Math.min(ref.rule, ...((h.ruleIds ?? []).map((x) => Number(x.split('#')[2])).filter((n) => Number.isFinite(n)))) : ref.rule;
      const num = freeNumberBelow(model, ref.naclId, ref.egress, limit);
      const users = [...model.subnets.values()].filter((x) => naclForSubnet(model, x)?.id === ref.naclId).length;
      if (num === undefined) return { hop: h, p: { advice: `${ref.naclId} has no free rule number before rule ${limit}; renumber its entries first.` } };
      return {
        hop: h,
        p: {
          change: { kind: 'add-nacl-entry', naclId: ref.naclId, egress: ref.egress, ruleNumber: num, action: 'allow', protocol: proto, cidr: `${peer}/32`, ...(proto !== 'icmp' && range ? { fromPort: range.from, toPort: range.to } : {}) },
          notes: [...(users > 1 ? [`${ref.naclId} is used by ${users} subnets; the entry applies to all of them.`] : []), ret ? `Replies go back to the client's ephemeral ports (${range!.from}-${range!.to} covers Linux and Windows clients).` : `Rule ${num} is evaluated before rule ${limit === 32767 ? '*' : limit}, which ${h.decision === 'block' ? 'denies' : 'decides'} it now.`],
        },
      };
    }
    case 'route':
    case 'return-route': {
      if (h.stage === 'route' && src.kind === 'eni') return { hop: h, p: routeTo(ctx, src.subnet, dst.ip, dst) };
      if (h.stage === 'return-route' && dst.kind === 'eni') return { hop: h, p: routeTo(ctx, dst.subnet, src.ip, src) };
      break;
    }
    case 'public-ip': {
      const eni = dst.kind === 'eni' && h.resourceId === dst.eni.id ? dst.eni : src.kind === 'eni' && h.resourceId === src.eni.id ? src.eni : undefined;
      if (!eni) break;
      return { hop: h, p: { change: { kind: 'add-public-ip', eniId: eni.id, publicIp: 'new Elastic IP', elastic: true }, notes: ['Allocate an Elastic IP and associate it with the interface (aws ec2 allocate-address, then associate-address).'] } };
    }
    case 'igw': {
      const vpc = dst.kind === 'eni' ? dst.subnet.vpcId : undefined;
      if (!vpc) break;
      return { hop: h, p: { change: { kind: 'attach-igw', igwId: 'igw-new', vpcId: vpc }, notes: ['Create an internet gateway (aws ec2 create-internet-gateway) and attach it; then a route to it is needed too.'] } };
    }
  }
  const advice: Record<string, string> = {
    firewall: `Change the rules of firewall ${h.resourceId}: Pinhole does not write firewall rules.`,
    appliance: `The appliance behind ${h.resourceId} decides this; check it on the appliance.`,
    nat: 'Fix the NAT gateway: it must be available and public, and its subnet must route to the internet gateway.',
    'tgw-route': `Add a route for this destination to the transit gateway route table ${h.resourceId}.`,
    'tgw-attachment': `Give the transit gateway attachment a subnet in this Availability Zone (${h.resourceId}).`,
    onprem: `Attach the virtual private gateway (${h.resourceId}) to the VPC.`,
    resolve: 'One end is not in the snapshot.',
  };
  return { hop: h, p: { advice: advice[h.stage] ?? `Pinhole cannot write a change for ${h.stage}; ${h.detail}` } };
}

const MAX_STEPS = 8;

export function repairPath(model: NetworkModel, query: PathQuery): RepairResult {
  const before = evaluatePath(model, query);
  const done = (verdict: RepairResult['verdict'], after: PathResult, steps: RepairStep[], current: NetworkModel, stuck?: RepairResult['stuck']): RepairResult => {
    let opens: ExposureDelta[] = [];
    if (steps.length) opens = diffExposure(analyzeExposure(model), analyzeExposure(current)).deltas.filter((d) => d.status === 'opened' || d.status === 'widened');
    return { verdict, before, after, steps, ...(stuck ? { stuck } : {}), opens };
  };
  if (before.verdict === 'reachable' && before.returnPath !== 'partial') return done('already', before, [], model);
  const src = endOf(model, query.from);
  const dst = endOf(model, query.to);
  if (!src || !dst) return done('stuck', before, [], model, { stage: 'resolve', resourceId: '', detail: before.summary, advice: 'One end is not in the snapshot.' });

  let current = model;
  let result = before;
  const steps: RepairStep[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < MAX_STEPS; i++) {
    const ctx: Ctx = { model: current, query, src: endOf(current, query.from)!, dst: endOf(current, query.to)! };
    const prop = propose(ctx, result);
    if (!prop) break;
    const at = { stage: prop.hop.stage, resourceId: prop.hop.resourceId, detail: prop.hop.detail };
    if ('advice' in prop.p) return done(steps.length ? 'stuck' : 'stuck', result, steps, current, { ...at, advice: prop.p.advice });
    const key = JSON.stringify(prop.p.change);
    if (seen.has(key)) return done('stuck', result, steps, current, { ...at, advice: 'The proposed change did not get past this hop.' });
    seen.add(key);
    const next = applyChanges(current, [prop.p.change]);
    steps.push({ blockedAt: at, change: prop.p.change, text: describeChange(current, prop.p.change), cli: cliFor(current, prop.p.change), notes: prop.p.notes });
    current = next;
    result = evaluatePath(current, query);
    if (result.verdict === 'reachable' && result.returnPath !== 'partial') return done('repaired', result, steps, current);
  }
  return done(result.verdict === 'reachable' ? 'partial' : 'stuck', result, steps, current, result.verdict === 'reachable' ? undefined : { stage: result.blockedAt?.stage ?? '', resourceId: result.blockedAt?.resourceId ?? '', detail: result.blockedAt?.detail ?? result.summary, advice: 'No further change could be found.' });
}
