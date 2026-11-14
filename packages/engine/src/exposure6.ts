/**
 * IPv6 internet exposure of network interfaces.
 *
 * An IPv6 address in a VPC is a global unicast address. It is reachable from
 * the internet, with no public IP or NAT, when all of these hold
 * (https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html,
 * https://docs.aws.amazon.com/vpc/latest/userguide/working-with-igw.html):
 *
 * - the VPC has an internet gateway attached;
 * - the subnet's network ACL allows the request in, by its IPv6 rules
 *   (lowest rule number first; IPv4 rules never match IPv6 traffic);
 * - a security group on the interface allows it, by an IPv6 CIDR rule
 *   (security group references and IPv4 rules never match internet IPv6);
 * - the subnet's route for the client's address is an internet gateway
 *   route (an egress-only internet gateway carries only outbound
 *   connections: https://docs.aws.amazon.com/vpc/latest/userguide/egress-only-internet-gateway.html);
 * - the network ACL lets the response out to the client's ephemeral ports.
 *
 * As for IPv4, the answer is exact: ports are cut at every rule boundary and
 * source addresses at every CIDR boundary, then each piece is decided once.
 * TCP and UDP are analysed; ICMPv6 is not.
 */
import { DOCS } from './docs.js';
import type { ExposureFinding } from './exposure.js';
import { INTERNET6, parseCidr6, parseIpv6, RangeSet6 } from './ipv6.js';
import { hasPorts, protocolName } from './packet.js';
import { CLIENT_PROFILES } from './path.js';
import type { ReturnCoverage, ReturnProfileResult } from './path.js';
import { assessPorts } from './risk.js';
import { attachedIgw, displayName, naclForSubnet, routeTableForSubnet } from './topology.js';
import type { Eni, Nacl, NaclEntry, NetworkModel, PortRange, ProtocolNumber, SgRule, Warning } from './types.js';
import type { Hop } from './walk.js';

const ANALYSED: ProtocolNumber[] = ['6', '17'];
const WORLD6 = '::/0 (every internet address)';

const covers = (r: PortRange | undefined, port: number) => !r || (r.from <= port && port <= r.to);
const protoMatch = (ruleProto: string, p: ProtocolNumber) => ruleProto === '-1' || ruleProto === p;

/** IPv6 security group rules on the interface that can admit `p`. */
function sgRules6(model: NetworkModel, eni: Eni, p: ProtocolNumber): SgRule[] {
  return eni.groupIds.flatMap((g) => model.securityGroups.get(g)?.ingress ?? []).filter((r) => r.ipv6CidrText && protoMatch(r.protocol, p));
}
const sgPorts = (r: SgRule): PortRange | undefined => (r.protocol === '-1' || r.fromPort === undefined || r.fromPort === -1 ? undefined : { from: r.fromPort, to: r.toPort ?? r.fromPort });

/** IPv6 network ACL entries for one direction, in evaluation order. */
function naclEntries6(nacl: Nacl, egress: boolean, p: ProtocolNumber): NaclEntry[] {
  return nacl.entries.filter((e) => e.egress === egress && e.ipv6CidrText && protoMatch(e.protocol, p)).sort((a, b) => a.ruleNumber - b.ruleNumber);
}
const naclPorts = (e: NaclEntry): PortRange | undefined => (e.protocol === '-1' || !hasPorts(e.protocol) ? undefined : e.portRange);

/** Sources the ACL lets in on `port`: first matching rule wins, then the implicit deny. */
function naclAllowed(entries: NaclEntry[], port: number): RangeSet6 {
  let pending = RangeSet6.fromCidrs(['::/0']);
  let allowed = RangeSet6.empty();
  for (const e of entries) {
    if (!covers(naclPorts(e), port)) continue;
    const hit = pending.intersect(RangeSet6.fromCidrs([e.ipv6CidrText!]));
    if (hit.isEmpty()) continue;
    if (e.action === 'allow') allowed = allowed.union(hit);
    pending = pending.subtract(hit);
  }
  return allowed;
}

/** First matching outbound rule for one client address, across a port range: allowed port ranges. */
function naclReturn(entries: NaclEntry[], client: bigint, range: PortRange): PortRange[] {
  let pending: PortRange[] = [{ ...range }];
  const allowed: PortRange[] = [];
  for (const e of entries) {
    if (!pending.length) break;
    if (!RangeSet6.fromCidrs([e.ipv6CidrText!]).contains(client)) continue;
    const r = naclPorts(e) ?? { from: 0, to: 65535 };
    const next: PortRange[] = [];
    for (const p of pending) {
      const from = Math.max(p.from, r.from);
      const to = Math.min(p.to, r.to);
      if (from > to) {
        next.push(p);
        continue;
      }
      if (e.action === 'allow') allowed.push({ from, to });
      if (p.from < from) next.push({ from: p.from, to: from - 1 });
      if (to < p.to) next.push({ from: to + 1, to: p.to });
    }
    pending = next;
  }
  return allowed.sort((a, b) => a.from - b.from);
}

/** Client addresses whose longest-prefix IPv6 route in this table is the internet gateway. */
function viaIgw(model: NetworkModel, eni: Eni, igw: string): RangeSet6 {
  const subnet = model.subnets.get(eni.subnetId)!;
  const rt = routeTableForSubnet(model, subnet);
  const routes = [...(rt?.routes6 ?? [])].map((r) => ({ r, c: parseCidr6(r.destination) })).sort((a, b) => b.c.prefixLength - a.c.prefixLength);
  let pending = RangeSet6.fromCidrs(['::/0']);
  let out = RangeSet6.empty();
  for (const { r, c } of routes) {
    const hit = pending.intersect(RangeSet6.of([c]));
    if (hit.isEmpty()) continue;
    if (r.state === 'active' && r.target.type === 'igw' && r.target.id === igw) out = out.union(hit);
    pending = pending.subtract(hit);
  }
  return out;
}

/** Cut `set` at every CIDR boundary of `entries`, so each piece meets the same rules. */
function atoms(set: RangeSet6, entries: NaclEntry[]): RangeSet6[] {
  const cuts = new Set<bigint>();
  for (const e of entries) {
    const c = parseCidr6(e.ipv6CidrText!);
    cuts.add(c.start).add(c.end + 1n);
  }
  const out: RangeSet6[] = [];
  for (const r of set.list()) {
    const inside = [...cuts].filter((x) => x > r.start && x <= r.end).sort((a, b) => (a < b ? -1 : 1));
    let start = r.start;
    for (const c of [...inside, r.end + 1n]) {
      out.push(RangeSet6.of([{ start, end: c - 1n }]));
      start = c;
    }
  }
  return out;
}

function coverage(allowed: PortRange[], range: PortRange): ReturnCoverage {
  const n = allowed.reduce((s, a) => s + Math.min(a.to, range.to) - Math.max(a.from, range.from) + 1, 0);
  return n <= 0 ? 'none' : n >= range.to - range.from + 1 ? 'all' : 'partial';
}

interface Piece {
  ports: PortRange;
  sources: RangeSet6;
  returnPath: ReturnCoverage;
  profiles: ReturnProfileResult[];
  sample: bigint;
}

function analyse(model: NetworkModel, eni: Eni, nacl: Nacl, igw: string, p: ProtocolNumber): Piece[] {
  const rules = sgRules6(model, eni, p);
  if (!rules.length) return [];
  const inEntries = naclEntries6(nacl, false, p);
  const outEntries = naclEntries6(nacl, true, p);
  const routed = viaIgw(model, eni, igw);
  if (routed.isEmpty()) return [];

  // Port cells: every rule boundary, restricted to ports some security group rule admits.
  const cuts = new Set<number>([0, 65536]);
  for (const r of rules) {
    const pr = sgPorts(r);
    if (pr) cuts.add(pr.from).add(pr.to + 1);
  }
  for (const e of inEntries) {
    const pr = naclPorts(e);
    if (pr) cuts.add(pr.from).add(pr.to + 1);
  }
  const edges = [...cuts].sort((a, b) => a - b);
  const pieces: Piece[] = [];
  for (let i = 0; i < edges.length - 1; i++) {
    const ports = { from: edges[i]!, to: edges[i + 1]! - 1 };
    const port = ports.from;
    const sg = RangeSet6.fromCidrs(rules.filter((r) => covers(sgPorts(r), port)).map((r) => r.ipv6CidrText!)).intersect(INTERNET6);
    if (sg.isEmpty()) continue;
    const sources = sg.intersect(naclAllowed(inEntries, port)).intersect(routed);
    if (sources.isEmpty()) continue;
    // Responses: decided per client address piece, against each client OS's ephemeral range.
    const byCoverage = new Map<string, Piece>();
    for (const a of atoms(sources, outEntries)) {
      const sample = a.list()[0]!.start;
      const profiles = CLIENT_PROFILES.map((prof) => {
        const allowed = naclReturn(outEntries, sample, prof.range);
        return { profile: prof.name, range: prof.range, allowed, coverage: coverage(allowed, prof.range) };
      });
      const cov: ReturnCoverage = profiles.every((x) => x.coverage === 'all') ? 'all' : profiles.every((x) => x.coverage === 'none') ? 'none' : 'partial';
      if (cov === 'none') continue;
      const k = `${cov}|${JSON.stringify(profiles.map((x) => x.allowed))}`;
      const cur = byCoverage.get(k);
      if (cur) cur.sources = cur.sources.union(a);
      else byCoverage.set(k, { ports, sources: a, returnPath: cov, profiles, sample });
    }
    pieces.push(...byCoverage.values());
  }
  // Merge neighbouring port cells that behave the same.
  const merged: Piece[] = [];
  for (const x of pieces) {
    const last = merged.find((m) => m.ports.to + 1 === x.ports.from && m.returnPath === x.returnPath && m.sources.equals(x.sources) && JSON.stringify(m.profiles.map((y) => y.allowed)) === JSON.stringify(x.profiles.map((y) => y.allowed)));
    if (last) last.ports = { from: last.ports.from, to: x.ports.to };
    else merged.push({ ...x });
  }
  return merged;
}

function trace(model: NetworkModel, eni: Eni, nacl: Nacl, igw: string, p: ProtocolNumber, x: Piece): Hop[] {
  const port = x.ports.from;
  const proto = protocolName(p);
  const firstIn = naclEntries6(nacl, false, p).find((e) => covers(naclPorts(e), port) && RangeSet6.fromCidrs([e.ipv6CidrText!]).contains(x.sample));
  const sg = sgRules6(model, eni, p).filter((r) => covers(sgPorts(r), port) && RangeSet6.fromCidrs([r.ipv6CidrText!]).contains(x.sample));
  const rt = routeTableForSubnet(model, model.subnets.get(eni.subnetId)!);
  const back = (rt?.routes6 ?? []).filter((r) => r.target.id === igw).map((r) => r.destination);
  return [
    { stage: 'igw', decision: 'pass', resourceId: igw, detail: `${igw} attached to ${eni.vpcId}, reached directly over IPv6 with no public IP`, docUrl: DOCS.ipv6Addressing },
    { stage: 'dest-nacl-ingress', decision: 'pass', resourceId: nacl.id, detail: firstIn ? `inbound rule ${firstIn.ruleNumber} allows ${proto}/${port} from ${firstIn.ipv6CidrText}` : 'allowed', ...(firstIn ? { ruleIds: [`${nacl.id}#ingress#${firstIn.ruleNumber}`] } : {}), docUrl: DOCS.naclCustom },
    { stage: 'dest-sg-ingress', decision: 'pass', resourceId: sg[0]?.groupId ?? eni.groupIds[0] ?? '', detail: `inbound ${proto}/${port} from ${sg.map((r) => r.ipv6CidrText).join(', ')} allowed by ${sg.map((r) => `${r.id} (${r.groupId})`).join(', ')}`, ruleIds: sg.map((r) => r.id), docUrl: DOCS.sgRules },
    { stage: 'return-route', decision: 'pass', resourceId: rt?.id ?? '', detail: `${rt?.id ?? 'route table'}: ${back.join(', ')} -> ${igw}`, docUrl: DOCS.routePriority },
    { stage: 'return-nacl', decision: 'pass', resourceId: nacl.id, detail: `outbound IPv6 to clients: ${x.profiles.map((y) => `${y.profile} ${y.coverage}`).join('; ')}`, docUrl: DOCS.naclCustom },
  ];
}

/** IPv6 findings for every interface with an IPv6 address. */
export function analyzeExposure6(model: NetworkModel, skip: (eni: Eni) => boolean, only: Set<string> | undefined, warnings: Warning[]): { findings: ExposureFinding[]; analysed: number } {
  const findings: ExposureFinding[] = [];
  let analysed = 0;
  let prefixListWarned = false;
  for (const eni of model.enis.values()) {
    const addrs = (eni.ipv6Addresses ?? []).filter((a) => {
      try {
        return INTERNET6.contains(parseIpv6(a));
      } catch {
        return false;
      }
    });
    if (!addrs.length || skip(eni) || (only && !only.has(eni.id))) continue;
    const subnet = model.subnets.get(eni.subnetId);
    const igw = subnet ? attachedIgw(model, subnet.vpcId) : undefined;
    if (!subnet || !igw) continue;
    const nacl = naclForSubnet(model, subnet);
    if (!nacl) {
      warnings.push({ code: 'nacl-missing', message: `${eni.id}: the network ACL of ${subnet.id} is not in the snapshot; its IPv6 exposure is not analysed.`, resourceIds: [eni.id, subnet.id] });
      continue;
    }
    analysed++;
    if (!prefixListWarned && eni.groupIds.some((g) => model.securityGroups.get(g)?.ingress.some((r) => r.prefixListId && model.prefixLists.get(r.prefixListId)?.hasIpv6Entries))) {
      prefixListWarned = true;
      warnings.push({ code: 'ipv6-prefix-list', message: 'Security group rules use prefix lists with IPv6 entries; those IPv6 sources are not analysed.', resourceIds: [eni.id] });
    }
    const name = displayName(model, eni);
    for (const p of ANALYSED) {
      for (const x of analyse(model, eni, nacl, igw, p)) {
        const proto = protocolName(p);
        const risk = assessPorts(proto, x.ports);
        // "Every internet address" for IPv6 means global unicast outside the VPC's own blocks,
        // which are local to it, not internet.
        const world = INTERNET6.subtract(RangeSet6.fromCidrs(model.vpcs.get(eni.vpcId)?.ipv6CidrTexts ?? []));
        const all = x.sources.equals(world) || x.sources.equals(INTERNET6);
        const ranges = all ? [WORLD6] : x.sources.toCidrs();
        const missing = all ? [] : world.subtract(x.sources).toCidrs();
        const labels = all ? [WORLD6] : missing.length && missing.length <= 3 ? [`${WORLD6} except ${missing.join(', ')}`] : ranges;
        findings.push({
          kind: 'interface',
          family: 'ipv6',
          resourceId: eni.id,
          resourceName: name,
          vpcId: eni.vpcId,
          publicIps: addrs,
          protocol: proto,
          ports: x.ports,
          sources: labels,
          sourceRanges: ranges,
          returnPath: x.returnPath,
          returnProfiles: x.profiles,
          severity: risk.severity,
          reasons: risk.reasons,
          trace: trace(model, eni, nacl, igw, p, x),
        });
      }
    }
  }
  return { findings, analysed };
}
