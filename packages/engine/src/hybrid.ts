/**
 * Reachable from on-premises: every interface a client in an on-premises
 * network (over Site-to-Site VPN or Direct Connect) can open a connection to,
 * with protocol, ports, the on-premises addresses that work, the link it
 * arrives over, and the exact path.
 *
 * The method is the one used for internet exposure (exposure.ts): the
 * on-premises address space (onprem.ts) is cut at every boundary that can
 * decide differently (security group rules, network ACL entries and routes in
 * the interface's VPC, transit gateway routes, gateway route tables, firewall
 * rules), the ports likewise, and one connection per cell is evaluated with
 * evaluatePath. Cells with the same answer and the same deciding rules are
 * merged. Interfaces with the same subnet and security groups give the same
 * answer, so they are evaluated once.
 */
import { inspectionBoundaries } from './firewall.js';
import { RangeSet, formatIpv4 } from './ipv4.js';
import { hasPorts, protocolName } from './packet.js';
import { evaluatePath } from './path.js';
import type { PathResult, ReturnCoverage } from './path.js';
import { assessPorts, compareSeverity, SEVERITY_ORDER } from './risk.js';
import type { Severity } from './risk.js';
import { canTake } from './internal.js';
import { onPremLinks, onPremNetworks, describeLink } from './onprem.js';
import type { OnPremLink } from './onprem.js';
import { displayName, naclForSubnet, routeTableForSubnet } from './topology.js';
import { PROTO_ICMP, PROTO_TCP, PROTO_UDP } from './types.js';
import type { Eni, IpRange, NetworkModel, PortRange, ProtocolNumber } from './types.js';
import type { Hop } from './walk.js';
import { inspection } from './exposure.js';

export interface OnPremFinding {
  resourceId: string;
  resourceName: string;
  vpcId: string;
  protocol: string;
  ports: PortRange;
  /** On-premises address ranges that can connect. */
  sources: string[];
  /** The link (vgw- or transit gateway attachment) the traffic arrives over. */
  via: string;
  linkKind: OnPremLink['kind'];
  returnPath: ReturnCoverage;
  severity: Severity;
  reasons: string[];
  trace: Hop[];
  inspectedBy?: string[];
  caveats?: string[];
}

export interface OnPremReport {
  links: (OnPremLink & { description: string; networks: string[] })[];
  findings: OnPremFinding[];
  /** Interfaces analysed, and how many on-premises clients can reach. */
  interfaces: number;
  reachable: number;
  stats: { cells: number; evaluated: number };
}

const NOT_HERE = new Set(['network_load_balancer', 'gateway_load_balancer', 'gateway_load_balancer_endpoint']);

function addCuts(cuts: Set<number>, r: IpRange) {
  cuts.add(r.start);
  if (r.end < 0xffffffff) cuts.add(r.end + 1);
}

/** On-premises addresses some inbound rule of the interface admits, for a protocol and port range. */
function candidates(model: NetworkModel, eni: Eni, space: RangeSet, protocol: ProtocolNumber, ports: PortRange | undefined): RangeSet {
  const ranges: IpRange[] = [];
  for (const gid of eni.groupIds) {
    for (const r of model.securityGroups.get(gid)?.ingress ?? []) {
      if (r.protocol !== '-1' && r.protocol !== protocol) continue;
      if (ports && hasPorts(r.protocol) && r.fromPort !== undefined && r.fromPort !== -1 && ((r.toPort ?? r.fromPort) < ports.from || r.fromPort > ports.to)) continue;
      if (r.cidr) ranges.push(r.cidr);
      if (r.prefixListId) ranges.push(...(model.prefixLists.get(r.prefixListId)?.entries ?? []));
    }
  }
  return RangeSet.of(ranges).intersect(space);
}

function vpcSubnets(model: NetworkModel, vpcId: string) {
  return [...model.subnets.values()].filter((s) => s.vpcId === vpcId);
}

function addressCells(model: NetworkModel, eni: Eni, limit: RangeSet): IpRange[] {
  const cuts = new Set<number>([0]);
  for (const r of limit.ranges) addCuts(cuts, r);
  for (const n of onPremNetworks(model)) addCuts(cuts, n.range);
  for (const gid of eni.groupIds) for (const r of model.securityGroups.get(gid)?.ingress ?? []) if (r.cidr) addCuts(cuts, r.cidr);
  for (const s of vpcSubnets(model, eni.vpcId)) {
    for (const e of naclForSubnet(model, s)?.entries ?? []) if (e.cidr) addCuts(cuts, e.cidr);
    for (const r of routeTableForSubnet(model, s)?.routes ?? []) if (r.destination) addCuts(cuts, r.destination);
  }
  for (const t of model.tgwRouteTables.values()) for (const r of t.routes) if (r.destination) addCuts(cuts, r.destination);
  for (const rt of model.routeTables.values()) if (rt.gatewayIds.length) for (const r of rt.routes) if (r.destination) addCuts(cuts, r.destination);
  const insp = inspectionBoundaries(model);
  for (const r of [...insp.addrs, ...insp.routes]) addCuts(cuts, r);
  for (const acl of insp.acls) for (const e of acl.entries) if (e.cidr) addCuts(cuts, e.cidr);
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
  for (const gid of eni.groupIds) for (const r of model.securityGroups.get(gid)?.ingress ?? []) if (r.protocol === protocol) add(r.fromPort, r.toPort);
  for (const s of vpcSubnets(model, eni.vpcId)) for (const e of naclForSubnet(model, s)?.entries ?? []) if (e.protocol === protocol && e.portRange) add(e.portRange.from, e.portRange.to);
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
  sources: RangeSet;
  sig: string;
  sample: PathResult;
}

function analyse(model: NetworkModel, eni: Eni, space: RangeSet, counter: { cells: number }): Group[] {
  const groups: Group[] = [];
  for (const protocol of [PROTO_TCP, PROTO_UDP, PROTO_ICMP]) {
    const portList: PortRange[] = protocol === PROTO_ICMP ? [{ from: 8, to: 8 }] : portCells(model, eni, protocol);
    let open: Group[] = [];
    for (const ports of portList) {
      const cand = candidates(model, eni, space, protocol, protocol === PROTO_ICMP ? undefined : ports);
      const bySig = new Map<string, { cells: IpRange[]; sample: PathResult }>();
      if (!cand.isEmpty()) {
        for (const cell of addressCells(model, eni, cand)) {
          counter.cells += 1;
          const r = evaluatePath(model, { from: { ip: formatIpv4(cell.start) }, to: { eni: eni.id }, protocol: protocolName(protocol), ...(protocol === PROTO_ICMP ? {} : { port: ports.from }) });
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
        const prev = open.find((g) => g.sig === sig && g.ports.to + 1 === ports.from && g.sources.equals(set));
        if (prev) {
          prev.ports = { from: prev.ports.from, to: ports.to };
          next.push(prev);
        } else next.push({ protocol, ports, sources: set, sig, sample });
      }
      for (const g of open) if (!next.includes(g)) groups.push(g);
      open = next;
    }
    groups.push(...open);
  }
  return groups;
}

const lower = (s: Severity, by: number): Severity => SEVERITY_ORDER[Math.min(SEVERITY_ORDER.length - 1, SEVERITY_ORDER.indexOf(s) + by)]!;

/**
 * On-premises networks are trusted more than the internet, so a service is
 * rated one level below its internet rating, and one more when only a narrow
 * range of on-premises addresses (256 or fewer) can reach it.
 */
function assess(protocol: string, ports: PortRange, sources: RangeSet): { severity: Severity; reasons: string[] } {
  const base = assessPorts(protocol, protocol === 'icmp' ? undefined : ports);
  const n = sources.size();
  const narrow = n <= 256;
  const reasons = [...base.reasons, `from ${narrow ? `${n} on-premises address${n === 1 ? '' : 'es'}` : 'a wide on-premises range'}`];
  return { severity: lower(base.severity, narrow ? 2 : 1), reasons };
}

/** Every interface that clients on-premises can open connections to, and how. */
export function analyzeOnPrem(model: NetworkModel, opts: { only?: Set<string> } = {}): OnPremReport {
  const links = onPremLinks(model);
  const nets = onPremNetworks(model);
  const report: OnPremReport = {
    links: links.map((l) => ({ ...l, description: describeLink(l), networks: RangeSet.of(nets.filter((n) => n.links.includes(l.id)).map((n) => n.range)).toCidrs() })),
    findings: [],
    interfaces: 0,
    reachable: 0,
    stats: { cells: 0, evaluated: 0 },
  };
  const space = RangeSet.of(nets.map((n) => n.range));
  if (space.isEmpty()) return report;
  const counter = { cells: 0 };
  const cache = new Map<string, Group[]>();
  const reachable = new Set<string>();
  for (const eni of model.enis.values()) {
    if (!canTake(eni) || NOT_HERE.has(eni.interfaceType) || !eni.privateIps.length) continue;
    if (opts.only && !opts.only.has(eni.id)) continue;
    report.interfaces += 1;
    const key = `${eni.subnetId}|${[...eni.groupIds].sort().join(',')}`;
    let groups = cache.get(key);
    let reused = true;
    if (!groups) {
      groups = analyse(model, eni, space, counter);
      cache.set(key, groups);
      reused = false;
    }
    for (const g of groups) {
      const first = g.sources.ranges[0];
      const proto = protocolName(g.protocol);
      const sample = reused && first ? evaluatePath(model, { from: { ip: formatIpv4(first.start) }, to: { eni: eni.id }, protocol: proto, ...(g.protocol === PROTO_ICMP ? {} : { port: g.ports.from }) }) : g.sample;
      const via = sample.via?.gateway ?? g.sample.via?.gateway ?? '?';
      const risk = assess(proto, g.ports, g.sources);
      reachable.add(eni.id);
      report.findings.push({
        resourceId: eni.id,
        resourceName: displayName(model, eni),
        vpcId: eni.vpcId,
        protocol: proto,
        ports: g.ports,
        sources: g.sources.toCidrs(),
        via,
        linkKind: links.find((l) => l.id === via)?.kind ?? 'vpn-or-direct-connect',
        returnPath: sample.returnPath ?? 'all',
        severity: risk.severity,
        reasons: risk.reasons,
        trace: sample.hops,
        ...inspection(sample.hops),
      });
    }
  }
  report.findings.sort((a, b) => compareSeverity(a.severity, b.severity) || a.resourceName.localeCompare(b.resourceName) || a.protocol.localeCompare(b.protocol) || a.ports.from - b.ports.from);
  report.reachable = reachable.size;
  report.stats = { cells: counter.cells, evaluated: cache.size };
  return report;
}
