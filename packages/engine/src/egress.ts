/**
 * Outbound: what each interface can open to the internet, and how.
 *
 * The questions an auditor asks the other way round from exposure: which
 * servers can send data out, to which addresses and ports, through which
 * gateway, and as which public address. A database that can open any port to
 * any internet address is an exfiltration path even if nothing can reach it.
 *
 * For each interface the destination addresses are cut at every boundary that
 * can decide differently (security group egress rules, network ACL entries
 * and routes of its subnet and of its NAT gateway's subnet, firewall rules and
 * endpoint subnets), the ports likewise, and one connection per cell is put
 * through the same path evaluation as everything else (path.ts,
 * outboundToInternet). Cells with the same answer and the same deciding rules
 * are merged. Interfaces with the same security groups, subnet and public
 * address status give the same answer, so they are evaluated once.
 */
import { inspectionBoundaries } from './firewall.js';
import { INTERNET, RangeSet, formatIpv4 } from './ipv4.js';
import { jewelTag } from './jewels.js';
import { hasPorts, protocolName } from './packet.js';
import { evaluatePath } from './path.js';
import type { PathResult, ReturnCoverage } from './path.js';
import { categorize, compareSeverity } from './risk.js';
import type { Severity } from './risk.js';
import { canSend } from './internal.js';
import { displayName, isElbNode, naclForSubnet, routeTableForSubnet } from './topology.js';
import { PROTO_ICMP, PROTO_TCP, PROTO_UDP } from './types.js';
import type { Eni, IpRange, NetworkModel, PortRange, ProtocolNumber, Subnet } from './types.js';
import type { Hop } from './walk.js';
import { inspection } from './exposure.js';

export interface EgressFinding {
  resourceId: string;
  resourceName: string;
  vpcId: string;
  protocol: string;
  ports: PortRange;
  /** Destination ranges; "0.0.0.0/0 (every internet address)" when it is all of them. */
  destinations: string[];
  /** The gateway it leaves through, and the public address it leaves as. */
  via: { gateway: string; publicIp?: string };
  returnPath: ReturnCoverage;
  severity: Severity;
  reasons: string[];
  /** The interface holds data (a data service, or a crown jewel tag). */
  dataStore: boolean;
  /** A sample connection, hop by hop. */
  trace: Hop[];
  inspectedBy?: string[];
  caveats?: string[];
}

export interface EgressReport {
  findings: EgressFinding[];
  /** Interfaces analysed, and how many can reach the internet at all, or on every port. */
  interfaces: number;
  open: number;
  wide: number;
  stats: { cells: number; evaluated: number };
}

const ALL_INTERNET = 'every internet address';
const isAll = (r: PortRange) => r.from === 0 && r.to === 65535;

function addCuts(cuts: Set<number>, r: IpRange) {
  cuts.add(r.start);
  if (r.end < 0xffffffff) cuts.add(r.end + 1);
}

/** The NAT gateway subnet an interface's internet traffic would use, if any. */
function natSubnets(model: NetworkModel, subnet: Subnet): Subnet[] {
  const out: Subnet[] = [];
  for (const r of routeTableForSubnet(model, subnet)?.routes ?? []) {
    if (r.target.type !== 'nat') continue;
    const nat = model.natGateways.get(r.target.id);
    const s = nat ? model.subnets.get(nat.subnetId) : undefined;
    if (s) out.push(s);
  }
  return out;
}

/** Internet addresses the interface's security groups allow out to, for a protocol and port range. */
function candidates(model: NetworkModel, eni: Eni, protocol: ProtocolNumber, ports: PortRange | undefined): RangeSet {
  const ranges: IpRange[] = [];
  for (const gid of eni.groupIds) {
    for (const r of model.securityGroups.get(gid)?.egress ?? []) {
      if (r.protocol !== '-1' && r.protocol !== protocol) continue;
      if (ports && hasPorts(r.protocol) && r.fromPort !== undefined && r.fromPort !== -1 && ((r.toPort ?? r.fromPort) < ports.from || r.fromPort > ports.to)) continue;
      if (r.cidr) ranges.push(r.cidr);
      if (r.prefixListId) ranges.push(...(model.prefixLists.get(r.prefixListId)?.entries ?? []));
    }
  }
  return RangeSet.of(ranges).intersect(INTERNET);
}

function subnetsOnPath(model: NetworkModel, eni: Eni): Subnet[] {
  const s = model.subnets.get(eni.subnetId);
  return s ? [s, ...natSubnets(model, s)] : [];
}

function addressCells(model: NetworkModel, eni: Eni, limit: RangeSet): IpRange[] {
  const cuts = new Set<number>([0]);
  for (const r of limit.toCidrs()) {
    const [ip, len] = r.split('/') as [string, string];
    const start = ip.split('.').reduce((n, o) => n * 256 + Number(o), 0);
    addCuts(cuts, { start, end: start + 2 ** (32 - Number(len)) - 1 });
  }
  for (const gid of eni.groupIds) for (const r of model.securityGroups.get(gid)?.egress ?? []) if (r.cidr) addCuts(cuts, r.cidr);
  for (const s of subnetsOnPath(model, eni)) {
    for (const e of naclForSubnet(model, s)?.entries ?? []) if (e.cidr) addCuts(cuts, e.cidr);
    for (const r of routeTableForSubnet(model, s)?.routes ?? []) if (r.destination) addCuts(cuts, r.destination);
  }
  const insp = inspectionBoundaries(model);
  for (const r of [...insp.addrs, ...insp.routes]) addCuts(cuts, r);
  for (const acl of insp.acls) for (const e of acl.entries) if (e.cidr) addCuts(cuts, e.cidr);
  // Ingress routing on the gateway decides the replies.
  for (const rt of model.routeTables.values()) if (rt.gatewayIds.length) for (const r of rt.routes) if (r.destination) addCuts(cuts, r.destination);
  const sorted = [...cuts].sort((a, b) => a - b);
  const cells: IpRange[] = [];
  for (let i = 0; i < sorted.length; i++) {
    const start = sorted[i]!;
    const end = i + 1 < sorted.length ? sorted[i + 1]! - 1 : 0xffffffff;
    if (limit.containsIp(start)) cells.push({ start, end });
  }
  return cells;
}

function portCells(model: NetworkModel, eni: Eni, protocol: ProtocolNumber): PortRange[] {
  const cuts = new Set<number>([0, 65536]);
  const add = (from: number | undefined, to: number | undefined) => {
    if (from === undefined || from < 0) return;
    cuts.add(from);
    cuts.add((to ?? from) + 1);
  };
  for (const gid of eni.groupIds) for (const r of model.securityGroups.get(gid)?.egress ?? []) if (r.protocol === protocol) add(r.fromPort, r.toPort);
  for (const s of subnetsOnPath(model, eni)) for (const e of naclForSubnet(model, s)?.entries ?? []) if (e.protocol === protocol && e.portRange) add(e.portRange.from, e.portRange.to);
  const insp = inspectionBoundaries(model);
  for (const r of insp.ports) add(r.from, r.to);
  for (const acl of insp.acls) for (const e of acl.entries) if (e.protocol === protocol && e.portRange) add(e.portRange.from, e.portRange.to);
  const sorted = [...cuts].filter((c) => c <= 65536).sort((a, b) => a - b);
  const out: PortRange[] = [];
  for (let i = 0; i + 1 < sorted.length; i++) out.push({ from: sorted[i]!, to: sorted[i + 1]! - 1 });
  return out;
}

const signature = (r: PathResult) => `${r.via?.gateway}|${r.returnPath}|${r.hops.filter((h) => h.decision === 'pass' && h.ruleIds?.length).map((h) => `${h.stage}=${[...h.ruleIds!].sort().join('+')}`).join('|')}`;

interface Group {
  protocol: ProtocolNumber;
  ports: PortRange;
  dests: RangeSet;
  sig: string;
  sample: PathResult;
}

function analyse(model: NetworkModel, eni: Eni, counter: { cells: number }): Group[] {
  const groups: Group[] = [];
  for (const protocol of [PROTO_TCP, PROTO_UDP, PROTO_ICMP]) {
    const portList: PortRange[] = protocol === PROTO_ICMP ? [{ from: 8, to: 8 }] : portCells(model, eni, protocol);
    let open: Group[] = [];
    for (const ports of portList) {
      const cand = candidates(model, eni, protocol, protocol === PROTO_ICMP ? undefined : ports);
      const bySig = new Map<string, { cells: IpRange[]; sample: PathResult }>();
      if (!cand.isEmpty()) {
        for (const cell of addressCells(model, eni, cand)) {
          counter.cells += 1;
          const r = evaluatePath(model, { from: { eni: eni.id }, to: { internet: formatIpv4(cell.start) }, protocol: protocolName(protocol), ...(protocol === PROTO_ICMP ? {} : { port: ports.from }) });
          if (r.verdict !== 'reachable') continue;
          const sig = signature(r);
          const e = bySig.get(sig);
          if (e) e.cells.push(cell);
          else bySig.set(sig, { cells: [cell], sample: r });
        }
      }
      const next: Group[] = [];
      for (const [sig, { cells, sample }] of bySig) {
        const set = RangeSet.of(cells);
        const prev = open.find((g) => g.sig === sig && g.ports.to + 1 === ports.from && g.dests.equals(set));
        if (prev) {
          prev.ports = { from: prev.ports.from, to: ports.to };
          next.push(prev);
        } else next.push({ protocol, ports, dests: set, sig, sample });
      }
      for (const g of open) if (!next.includes(g)) groups.push(g);
      open = next;
    }
    groups.push(...open);
  }
  return groups;
}

/** Whether the interface holds data: a crown jewel tag, or a data service its security groups let in. */
function holdsData(model: NetworkModel, eni: Eni): boolean {
  if (jewelTag(model, eni)) return true;
  for (const gid of eni.groupIds) {
    for (const r of model.securityGroups.get(gid)?.ingress ?? []) {
      if (r.protocol !== PROTO_TCP || r.fromPort === undefined || r.fromPort < 0) continue;
      const to = r.toPort ?? r.fromPort;
      if (to - r.fromPort > 100) continue; // a wide range says nothing about what runs there
      if (categorize('tcp', { from: r.fromPort, to }) === 'data') return true;
    }
  }
  return false;
}

function assess(protocol: string, ports: PortRange, world: boolean, data: boolean): { severity: Severity; reasons: string[] } {
  const wide = protocol !== 'icmp' && ports.to - ports.from >= 1000;
  const reasons: string[] = [];
  let severity: Severity = 'info';
  if (wide && world) {
    reasons.push(isAll(ports) ? 'any port to any internet address' : `${ports.to - ports.from + 1} ports to any internet address`);
    severity = data ? 'high' : 'medium';
    if (data) reasons.push('the server holds data, so this is an exfiltration path');
  } else if (data) {
    reasons.push('the server holds data');
    severity = 'low';
  }
  if (protocol === 'tcp' && ports.from <= 25 && ports.to >= 25) {
    reasons.push('SMTP (25) out: spam and data exfiltration');
    if (compareSeverity(severity, 'low') > 0) severity = 'low';
  }
  if (protocol === 'tcp' && ((ports.from <= 22 && ports.to >= 22) || (ports.from <= 3389 && ports.to >= 3389)) && !wide) {
    reasons.push('remote administration out: a common way to move data or reach a command server');
    if (compareSeverity(severity, 'low') > 0) severity = 'low';
  }
  if (!reasons.length) reasons.push(world ? 'to any internet address' : 'to some internet addresses');
  return { severity, reasons };
}

/** Every interface that can open connections to the internet, how, and how far. */
export function analyzeEgress(model: NetworkModel, opts: { only?: Set<string> } = {}): EgressReport {
  const counter = { cells: 0 };
  const findings: EgressFinding[] = [];
  const cache = new Map<string, Group[]>();
  let interfaces = 0;
  const open = new Set<string>();
  const wide = new Set<string>();
  for (const eni of model.enis.values()) {
    if (!canSend(eni) || isElbNode(eni) || eni.interfaceType === 'nat_gateway') continue;
    if (opts.only && !opts.only.has(eni.id)) continue;
    interfaces += 1;
    const key = `${eni.subnetId}|${[...eni.groupIds].sort().join(',')}|${eni.publicAddresses.length ? 'public' : 'private'}`;
    let groups = cache.get(key);
    let reused = true;
    if (!groups) {
      groups = analyse(model, eni, counter);
      cache.set(key, groups);
      reused = false;
    }
    const data = holdsData(model, eni);
    for (const g of groups) {
      // A cached result has another interface's trace; the decisions are the same, the addresses are not.
      const first = g.dests.toCidrs()[0];
      const sample = reused && first ? evaluatePath(model, { from: { eni: eni.id }, to: { internet: formatIpv4(parseStart(first)) }, protocol: protocolName(g.protocol), ...(g.protocol === PROTO_ICMP ? {} : { port: g.ports.from }) }) : g.sample;
      const all = g.dests.equals(INTERNET);
      const proto = protocolName(g.protocol);
      const risk = assess(proto, g.ports, all, data);
      open.add(eni.id);
      if (all && proto !== 'icmp' && g.ports.to - g.ports.from >= 1000) wide.add(eni.id);
      findings.push({
        resourceId: eni.id,
        resourceName: displayName(model, eni),
        vpcId: eni.vpcId,
        protocol: proto,
        ports: g.ports,
        destinations: all ? [`0.0.0.0/0 (${ALL_INTERNET})`] : g.dests.toCidrs(),
        via: sample.via ?? g.sample.via ?? { gateway: '?' },
        returnPath: sample.returnPath ?? 'all',
        severity: risk.severity,
        reasons: risk.reasons,
        dataStore: data,
        trace: sample.hops,
        ...inspection(sample.hops),
      });
    }
  }
  findings.sort((a, b) => compareSeverity(a.severity, b.severity) || a.resourceName.localeCompare(b.resourceName) || a.protocol.localeCompare(b.protocol) || a.ports.from - b.ports.from);
  return { findings, interfaces, open: open.size, wide: wide.size, stats: { cells: counter.cells, evaluated: cache.size } };
}

function parseStart(cidr: string): number {
  return cidr.split('/')[0]!.split('.').reduce((n, o) => n * 256 + Number(o), 0);
}
