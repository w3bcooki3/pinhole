/**
 * Service reachability between two interfaces: every protocol and port that
 * one interface can open a connection to on another, decided exactly.
 *
 * The port space is cut at every boundary of every rule that could matter
 * (the destination's inbound security group rules that could match the
 * source, the source's outbound rules, and every network ACL entry for the
 * protocol), and one representative packet per cell is evaluated with the
 * full path model in path.ts. Cells with the same outcome and the same
 * deciding rules are merged back into ranges.
 */
import { evaluatePath } from './path.js';
import type { PathResult, ReturnCoverage } from './path.js';
import { parseIpv4, rangeContains } from './ipv4.js';
import { hasPorts, protocolName } from './packet.js';
import { assessPorts, categorize, isPivotService, serviceName } from './risk.js';
import type { ServiceCategory, Severity } from './risk.js';
import { isElbNode } from './topology.js';
import { PROTO_ALL, PROTO_ICMP, PROTO_TCP, PROTO_UDP } from './types.js';
import type { Eni, NetworkModel, PortRange, ProtocolNumber, SgRule } from './types.js';

export interface ServiceReach {
  protocol: string;
  /** Port range (TCP/UDP), ICMP echo as {8, 8}, absent for other protocols. */
  ports?: PortRange;
  verdict: 'reachable' | 'unknown';
  returnPath?: ReturnCoverage;
  severity: Severity;
  category: ServiceCategory;
  /** Remote administration, a control plane or a wide range: enough to take over the host. */
  pivot: boolean;
  name?: string;
  /** Hops for one representative packet. */
  trace: PathResult['hops'];
  /** Why it is unknown, when it is. */
  unknownAt?: string;
}

export interface PairReach {
  from: string;
  to: string;
  services: ServiceReach[];
  /** Representative packets evaluated. */
  cells: number;
}

/** Interface types that cannot be the target of a new inbound connection worth reporting. */
const NOT_A_TARGET = new Set(['nat_gateway', 'vpc_endpoint', 'gateway_load_balancer', 'gateway_load_balancer_endpoint', 'transit_gateway', 'lambda', 'network_load_balancer', 'global_accelerator_managed']);

export function isLateralTarget(eni: Eni): boolean {
  return !NOT_A_TARGET.has(eni.interfaceType) && !isElbNode(eni);
}

/**
 * Inbound rules on `dst` that could match a connection from `src`, before any
 * routing or NACL check. If there are none, no connection is possible, which
 * lets callers skip most pairs cheaply. Interfaces without security groups
 * (some managed interfaces) admit everything.
 */
export function candidateRules(model: NetworkModel, src: Eni, dst: Eni, srcIp: number): SgRule[] | 'any' {
  if (dst.groupIds.length === 0) return 'any';
  const out: SgRule[] = [];
  for (const gid of dst.groupIds) {
    for (const r of model.securityGroups.get(gid)?.ingress ?? []) {
      if (r.cidr && rangeContains(r.cidr, srcIp)) out.push(r);
      else if (r.referencedGroupId && src.groupIds.includes(r.referencedGroupId)) out.push(r);
      else if (r.prefixListId && (model.prefixLists.get(r.prefixListId)?.entries ?? []).some((c) => rangeContains(c, srcIp))) out.push(r);
    }
  }
  return out;
}

function cuts(set: Set<number>, from: number | undefined, to: number | undefined, within: PortRange) {
  if (from === undefined || from < 0) return;
  if (from > within.from && from <= within.to) set.add(from);
  const t = (to ?? from) + 1;
  if (t > within.from && t <= within.to) set.add(t);
}

function covers(r: SgRule, protocol: ProtocolNumber, cell: PortRange | undefined): boolean {
  if (r.protocol !== PROTO_ALL && r.protocol !== protocol) return false;
  if (!cell || !hasPorts(protocol) || r.protocol === PROTO_ALL || r.fromPort === undefined || r.fromPort === -1) return true;
  return r.fromPort <= cell.to && (r.toPort ?? r.fromPort) >= cell.from;
}

function signature(r: PathResult): string {
  const ids = r.hops.filter((h) => h.decision === 'pass' && h.ruleIds?.length).map((h) => `${h.stage}=${[...h.ruleIds!].sort().join('+')}`);
  return `${r.verdict}|${r.returnPath}|${ids.join('|')}`;
}

export interface ReachOptions {
  /** Source private IP (default: primary). */
  srcIp?: string;
  /** Destination private IP (default: primary). */
  dstIp?: string;
  /** Only this protocol and port. */
  only?: { protocol: string; port?: number };
}

/** Everything `srcId` can open a connection to on `dstId`. */
export function reachServices(model: NetworkModel, srcId: string, dstId: string, opts: ReachOptions = {}): PairReach {
  const out: PairReach = { from: srcId, to: dstId, services: [], cells: 0 };
  const src = model.enis.get(srcId);
  const dst = model.enis.get(dstId);
  if (!src || !dst || src.id === dst.id) return out;
  const srcIpText = opts.srcIp ?? src.privateIps[0];
  if (!srcIpText) return out;
  const srcIp = parseIpv4(srcIpText);
  const rules = candidateRules(model, src, dst, srcIp);
  if (rules !== 'any' && rules.length === 0) return out;

  const protocols = new Set<ProtocolNumber>();
  if (opts.only) {
    const p = opts.only.protocol === 'tcp' ? PROTO_TCP : opts.only.protocol === 'udp' ? PROTO_UDP : opts.only.protocol === 'icmp' ? PROTO_ICMP : (opts.only.protocol as ProtocolNumber);
    protocols.add(p);
  } else if (rules === 'any') {
    [PROTO_TCP, PROTO_UDP, PROTO_ICMP].forEach((p) => protocols.add(p));
  } else {
    for (const r of rules) {
      if (r.protocol === PROTO_ALL) [PROTO_TCP, PROTO_UDP, PROTO_ICMP].forEach((p) => protocols.add(p));
      else protocols.add(r.protocol);
    }
  }

  const to = { eni: dst.id, ...(opts.dstIp ? { ip: opts.dstIp } : {}) };
  const from = { eni: src.id, ip: srcIpText };
  for (const protocol of protocols) {
    const name = protocolName(protocol);
    const portBased = hasPorts(protocol);
    let cells: (PortRange | undefined)[];
    if (protocol === PROTO_ICMP) cells = [{ from: 8, to: 8 }];
    else if (!portBased) cells = [undefined];
    else {
      const within: PortRange = opts.only?.port !== undefined ? { from: opts.only.port, to: opts.only.port } : { from: 0, to: 65535 };
      const set = new Set<number>([within.from, within.to + 1]);
      if (rules !== 'any') for (const r of rules) if (r.protocol === protocol) cuts(set, r.fromPort, r.toPort, within);
      for (const gid of src.groupIds) for (const r of model.securityGroups.get(gid)?.egress ?? []) if (r.protocol === protocol) cuts(set, r.fromPort, r.toPort, within);
      for (const n of model.nacls.values()) for (const e of n.entries) if (e.protocol === protocol && e.portRange) cuts(set, e.portRange.from, e.portRange.to, within);
      const sorted = [...set].sort((a, b) => a - b);
      cells = [];
      for (let i = 0; i + 1 < sorted.length; i++) cells.push({ from: sorted[i]!, to: sorted[i + 1]! - 1 });
    }
    let last: { sig: string; svc: ServiceReach } | undefined;
    for (const cell of cells) {
      // Cells that no candidate inbound rule covers are blocked by the security group.
      if (rules !== 'any' && !rules.some((r) => covers(r, protocol, cell))) {
        last = undefined;
        continue;
      }
      out.cells += 1;
      const r = evaluatePath(model, { from, to, protocol: name, ...(cell ? { port: cell.from } : {}) });
      if (r.verdict === 'blocked') {
        last = undefined;
        continue;
      }
      const sig = signature(r);
      if (last && last.sig === sig && last.svc.ports && cell && last.svc.ports.to + 1 === cell.from) {
        last.svc.ports = { from: last.svc.ports.from, to: cell.to };
        continue;
      }
      const svc: ServiceReach = {
        protocol: name,
        ...(cell ? { ports: { ...cell } } : {}),
        verdict: r.verdict,
        ...(r.returnPath ? { returnPath: r.returnPath } : {}),
        severity: 'info',
        category: 'other',
        pivot: false,
        trace: r.hops,
        ...(r.verdict === 'unknown' && r.blockedAt ? { unknownAt: `${r.blockedAt.resourceId}: ${r.blockedAt.detail}` } : {}),
      };
      out.services.push(svc);
      last = { sig, svc };
    }
  }
  // Classify after merging, so a merged range is judged as a whole.
  for (const s of out.services) {
    s.severity = assessPorts(s.protocol, s.ports).severity;
    s.category = categorize(s.protocol, s.ports);
    s.pivot = isPivotService(s.protocol, s.ports);
    const n = serviceName(s.protocol, s.ports);
    if (n) s.name = n;
  }
  return out;
}

/** "tcp/22", "tcp/1024-65535", "icmp", "proto 50". */
export function serviceLabel(s: { protocol: string; ports?: PortRange }): string {
  if (s.protocol === 'icmp') return 'icmp';
  if (!s.ports) return s.protocol === 'all' ? 'all traffic' : `proto ${s.protocol}`;
  return `${s.protocol}/${s.ports.from === s.ports.to ? s.ports.from : `${s.ports.from}-${s.ports.to}`}`;
}

