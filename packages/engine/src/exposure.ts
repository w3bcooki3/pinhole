/**
 * Internet exposure: every interface and load balancer listener that a client
 * on the internet can open a connection to, with protocol, ports, the source
 * addresses that work, and the exact path.
 *
 * Method (exact, not sampled):
 * For one interface, every rule that can influence the answer has a source or
 * destination CIDR and a port range: SG inbound rules, prefix-list entries,
 * the subnet's NACL entries, and the subnet's routes (for the return route).
 * Cutting the IPv4 space at every CIDR boundary, and the port space at every
 * port boundary, produces cells in which every rule either matches the whole
 * cell or none of it. Evaluating one representative packet per cell with
 * evaluatePath() therefore gives the answer for the whole cell. Adjacent cells
 * with the same answer and the same deciding rules are merged into a finding.
 */
import { DOCS } from './docs.js';
import { INTERNET, RangeSet, formatIpv4, parseIpv4 } from './ipv4.js';
import { hasPorts, protocolName } from './packet.js';
import type { EphemeralProfile, PathResult, ReturnCoverage, ReturnProfileResult } from './path.js';
import { CLIENT_PROFILES, ELB_PROFILES, evaluateClientPreservedTarget, evaluatePath } from './path.js';
import type { RiskAssessment, Severity } from './risk.js';
import { assessPorts, compareSeverity } from './risk.js';
import { detectOutOfScope } from './scope.js';
import { attachedIgw, displayName, eniByPrivateIp, isElbNode, naclForSubnet, routeTableForSubnet } from './topology.js';
import { PROTO_ICMP, PROTO_TCP, PROTO_UDP } from './types.js';
import type { Eni, IpRange, LoadBalancer, NetworkModel, PortRange, ProtocolNumber, SgRule, TargetGroup, Warning } from './types.js';
import type { Hop, Stage } from './walk.js';

export interface LbTargetResult {
  targetGroupArn: string;
  targetId: string;
  eniId?: string;
  ip?: string;
  port: number;
  verdict: 'reachable' | 'partial' | 'blocked' | 'unknown';
  /** How many load balancer nodes can reach this target. */
  nodesReachable: number;
  nodesTotal: number;
  clientIpPreserved: boolean;
  blockedAt?: { stage: Stage; resourceId: string; detail: string };
  hops: Hop[];
  notes: string[];
}

export interface ExposureFinding {
  kind: 'interface' | 'load-balancer';
  /** ENI ID, or load balancer ARN. */
  resourceId: string;
  resourceName: string;
  vpcId: string;
  publicIps: string[];
  protocol: string;
  /** Port range (TCP/UDP), or ICMP type 8 represented as {8, 8}. */
  ports: PortRange;
  /** Source labels from the deciding SG rules, e.g. "0.0.0.0/0" or "pl-123 (office)". */
  sources: string[];
  /** Exact set of internet addresses that can connect, as CIDRs. */
  sourceRanges: string[];
  returnPath: ReturnCoverage;
  returnProfiles?: ReturnProfileResult[];
  severity: Severity;
  reasons: string[];
  /** Hops for one representative packet. */
  trace: Hop[];
  /** For load balancers: what is reachable behind this listener. */
  listener?: { arn: string; port: number; protocol: string };
  targets?: LbTargetResult[];
}

export interface ExposureReport {
  findings: ExposureFinding[];
  warnings: Warning[];
  stats: { interfacesWithPublicIp: number; interfacesAnalysed: number; loadBalancersAnalysed: number; cellsEvaluated: number };
}

/** Interfaces whose exposure is reported elsewhere or that cannot accept inbound connections. */
const NOT_DIRECTLY_EXPOSED = new Set([
  'nat_gateway', // external services can't initiate connections through a NAT gateway
  'network_load_balancer', // analysed per listener
  'gateway_load_balancer',
  'gateway_load_balancer_endpoint',
  'vpc_endpoint',
  'transit_gateway',
  'global_accelerator_managed', // out of scope, warned separately
]);

// ------------------------------------------------------------------ cells

function addCuts(cuts: Set<number>, r: IpRange) {
  cuts.add(r.start);
  if (r.end < 0xffffffff) cuts.add(r.end + 1);
}

/** Address cells inside `limit`, cut at every boundary relevant to `eni`. */
function addressCells(model: NetworkModel, eni: Eni, limit: RangeSet): IpRange[] {
  const cuts = new Set<number>([0]);
  for (const r of limit.ranges) addCuts(cuts, r);
  for (const gid of eni.groupIds) {
    for (const rule of model.securityGroups.get(gid)?.ingress ?? []) {
      if (rule.cidr) addCuts(cuts, rule.cidr);
      if (rule.prefixListId) for (const c of model.prefixLists.get(rule.prefixListId)?.entries ?? []) addCuts(cuts, c);
    }
  }
  const subnet = model.subnets.get(eni.subnetId);
  if (subnet) {
    for (const e of naclForSubnet(model, subnet)?.entries ?? []) if (e.cidr) addCuts(cuts, e.cidr);
    for (const r of routeTableForSubnet(model, subnet)?.routes ?? []) {
      if (r.destination) addCuts(cuts, r.destination);
      if (r.destinationPrefixListId) for (const c of model.prefixLists.get(r.destinationPrefixListId)?.entries ?? []) addCuts(cuts, c);
    }
  }
  const sorted = [...cuts].sort((a, b) => a - b);
  const cells: IpRange[] = [];
  for (let i = 0; i < sorted.length; i++) {
    const start = sorted[i]!;
    const end = i + 1 < sorted.length ? sorted[i + 1]! - 1 : 0xffffffff;
    if (limit.containsIp(start)) cells.push({ start, end });
  }
  return cells;
}

/** Port cells for one protocol, cut at every SG and NACL port boundary. */
function portCells(model: NetworkModel, eni: Eni, protocol: ProtocolNumber, within: PortRange): PortRange[] {
  const cuts = new Set<number>([within.from, within.to + 1]);
  const add = (from: number | undefined, to: number | undefined) => {
    if (from === undefined || from < 0) return;
    if (from > within.from && from <= within.to) cuts.add(from);
    const t = (to ?? from) + 1;
    if (t > within.from && t <= within.to) cuts.add(t);
  };
  for (const gid of eni.groupIds) {
    for (const r of model.securityGroups.get(gid)?.ingress ?? []) if (r.protocol === protocol) add(r.fromPort, r.toPort);
  }
  const subnet = model.subnets.get(eni.subnetId);
  for (const e of subnet ? naclForSubnet(model, subnet)?.entries ?? [] : []) {
    if (!e.egress && e.protocol === protocol && e.portRange) add(e.portRange.from, e.portRange.to);
  }
  const sorted = [...cuts].sort((a, b) => a - b);
  const out: PortRange[] = [];
  for (let i = 0; i + 1 < sorted.length; i++) out.push({ from: sorted[i]!, to: sorted[i + 1]! - 1 });
  return out;
}

/**
 * Internet addresses that some SG inbound rule could admit for this protocol
 * and port cell. Cells outside this set cannot be reachable, so we skip them.
 * Rules referencing security groups never match internet sources.
 */
function sgCandidateSources(model: NetworkModel, eni: Eni, protocol: ProtocolNumber, ports: PortRange | undefined): RangeSet {
  if (eni.groupIds.length === 0) return INTERNET; // e.g. an NLB node without security groups
  const ranges: IpRange[] = [];
  for (const gid of eni.groupIds) {
    for (const r of model.securityGroups.get(gid)?.ingress ?? []) {
      if (r.protocol !== '-1' && r.protocol !== protocol) continue;
      if (ports && hasPorts(r.protocol) && r.fromPort !== undefined && r.fromPort !== -1) {
        if ((r.toPort ?? r.fromPort) < ports.from || r.fromPort > ports.to) continue;
      }
      if (r.cidr) ranges.push(r.cidr);
      if (r.prefixListId) ranges.push(...(model.prefixLists.get(r.prefixListId)?.entries ?? []));
    }
  }
  return RangeSet.of(ranges).intersect(INTERNET);
}

function protocolsFor(model: NetworkModel, eni: Eni): ProtocolNumber[] {
  const set = new Set<ProtocolNumber>([PROTO_TCP, PROTO_UDP, PROTO_ICMP]);
  for (const gid of eni.groupIds) for (const r of model.securityGroups.get(gid)?.ingress ?? []) if (r.protocol !== '-1') set.add(r.protocol);
  return [...set];
}

/** Signature of the rules that decided a reachable result, used for merging cells. */
function signature(r: PathResult): string {
  const ids = r.hops.filter((h) => h.decision === 'pass' && h.ruleIds?.length).map((h) => `${h.stage}=${[...h.ruleIds!].sort().join('+')}`);
  return `${r.returnPath}|${ids.join('|')}`;
}

/** Ingress rules by rule ID, built once per model. */
const ruleIndex = new WeakMap<NetworkModel, Map<string, SgRule>>();
function ingressRule(model: NetworkModel, id: string): SgRule | undefined {
  let idx = ruleIndex.get(model);
  if (!idx) {
    idx = new Map();
    for (const g of model.securityGroups.values()) for (const r of g.ingress) if (!idx.has(r.id)) idx.set(r.id, r);
    ruleIndex.set(model, idx);
  }
  return idx.get(id);
}

function sourceLabels(model: NetworkModel, r: PathResult): string[] {
  const hop = r.hops.find((h) => h.stage === 'dest-sg-ingress');
  const labels = new Set<string>();
  for (const id of hop?.ruleIds ?? []) {
    const rule = ingressRule(model, id);
    if (!rule) continue;
    if (rule.cidr) labels.add(rule.cidr.text);
    if (rule.prefixListId) labels.add(`${rule.prefixListId} (${model.prefixLists.get(rule.prefixListId)?.name ?? 'prefix list'})`);
  }
  if (labels.size === 0 && hop?.decision === 'pass') labels.add('any (no security group)');
  return [...labels];
}

interface CellGroup {
  protocol: ProtocolNumber;
  ports: PortRange;
  sources: RangeSet;
  sig: string;
  sample: PathResult;
}

interface AnalyseOptions {
  /** Restrict to one protocol and port range (load balancer listeners). */
  only?: { protocol: ProtocolNumber; ports: PortRange };
  profiles?: EphemeralProfile[];
}

/**
 * Exposure of one interface through one of its public addresses.
 * Returns merged groups of cells that are reachable.
 */
function analyseInterface(model: NetworkModel, eni: Eni, privateIp: string, opts: AnalyseOptions, counter: { cells: number }): CellGroup[] {
  const protocols = opts.only ? [opts.only.protocol] : protocolsFor(model, eni);
  const groups: CellGroup[] = [];

  for (const protocol of protocols) {
    const portList: (PortRange | undefined)[] = hasPorts(protocol)
      ? portCells(model, eni, protocol, opts.only?.ports ?? { from: 0, to: 65535 })
      : protocol === PROTO_ICMP
        ? [{ from: 8, to: 8 }]
        : [undefined];

    // Per port cell: map signature -> sources and a sample result.
    const perPort: { ports: PortRange | undefined; bySig: Map<string, { sources: IpRange[]; sample: PathResult }> }[] = [];
    for (const ports of portList) {
      const candidates = sgCandidateSources(model, eni, protocol, ports);
      const bySig = new Map<string, { sources: IpRange[]; sample: PathResult }>();
      if (!candidates.isEmpty()) {
        for (const cell of addressCells(model, eni, candidates)) {
          counter.cells += 1;
          const r = evaluatePath(
            model,
            { from: { internet: formatIpv4(cell.start) }, to: { eni: eni.id, ip: privateIp }, protocol, ...(ports ? { port: ports.from } : {}) },
            opts.profiles ? { returnProfiles: opts.profiles } : {},
          );
          if (r.verdict !== 'reachable') continue;
          const sig = signature(r);
          const entry = bySig.get(sig);
          if (entry) entry.sources.push(cell);
          else bySig.set(sig, { sources: [cell], sample: r });
        }
      }
      perPort.push({ ports, bySig });
    }

    // Merge adjacent port cells with the same signature and the same sources.
    let open: CellGroup[] = [];
    for (const { ports, bySig } of perPort) {
      const next: CellGroup[] = [];
      for (const [sig, { sources, sample }] of bySig) {
        const set = RangeSet.of(sources);
        const prev = open.find((g) => g.sig === sig && ports && g.ports.to + 1 === ports.from && g.sources.equals(set));
        if (prev && ports) {
          prev.ports = { from: prev.ports.from, to: ports.to };
          next.push(prev);
        } else {
          next.push({ protocol, ports: ports ?? { from: 0, to: 0 }, sources: set, sig, sample });
        }
      }
      for (const g of open) if (!next.includes(g)) groups.push(g);
      open = next;
    }
    groups.push(...open);
  }
  return groups;
}

function toFinding(model: NetworkModel, g: CellGroup, base: { kind: ExposureFinding['kind']; resourceId: string; resourceName: string; vpcId: string; publicIps: string[] }): ExposureFinding {
  const proto = protocolName(g.protocol);
  const risk: RiskAssessment = assessPorts(proto, hasPorts(g.protocol) || g.protocol === PROTO_ICMP ? g.ports : undefined);
  const all = g.sources.equals(INTERNET);
  return {
    ...base,
    protocol: proto,
    ports: g.ports,
    sources: sourceLabels(model, g.sample),
    sourceRanges: all ? ['0.0.0.0/0 (every internet address)'] : g.sources.toCidrs(),
    returnPath: g.sample.returnPath ?? 'all',
    ...(g.sample.returnProfiles ? { returnProfiles: g.sample.returnProfiles } : {}),
    severity: risk.severity,
    reasons: risk.reasons,
    trace: g.sample.hops,
  };
}

// ------------------------------------------------------------------ load balancers

function listenerProtocols(lb: LoadBalancer, protocol: string): ProtocolNumber[] {
  if (lb.type === 'application') return [PROTO_TCP]; // HTTP and HTTPS
  switch (protocol.toUpperCase()) {
    case 'UDP':
    case 'QUIC':
      return [PROTO_UDP];
    case 'TCP_UDP':
    case 'TCP_QUIC':
      return [PROTO_TCP, PROTO_UDP];
    default:
      return [PROTO_TCP]; // TCP, TLS
  }
}

/**
 * NLB client IP preservation
 * (https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html#client-ip-preservation):
 *  - UDP, TCP_UDP, QUIC, TCP_QUIC: always on, cannot be disabled.
 *  - TCP, TLS: configurable; default on for instance targets, off for IP targets.
 */
function clientIpPreserved(lb: LoadBalancer, tg: TargetGroup): boolean {
  if (lb.type !== 'network') return false;
  const p = (tg.protocol ?? '').toUpperCase();
  if (['UDP', 'TCP_UDP', 'QUIC', 'TCP_QUIC'].includes(p)) return true;
  if (tg.preserveClientIp !== undefined) return tg.preserveClientIp;
  return tg.targetType === 'instance';
}

function evaluateTargets(model: NetworkModel, lb: LoadBalancer, listenerPort: number, protocol: ProtocolNumber, clientSample: string | undefined, tgArns: string[]): LbTargetResult[] {
  const nodes = lb.nodeEniIds.map((id) => model.enis.get(id)).filter((e): e is Eni => !!e);
  const results: LbTargetResult[] = [];
  for (const arn of tgArns) {
    const tg = model.targetGroups.get(arn);
    if (!tg) continue;
    const preserved = clientIpPreserved(lb, tg);
    for (const t of tg.targets) {
      const port = t.port ?? tg.port ?? listenerPort;
      const notes: string[] = [];
      if (tg.healthCheckPort && tg.healthCheckPort !== 'traffic-port' && Number(tg.healthCheckPort) !== port) {
        notes.push(`Health checks use port ${tg.healthCheckPort}; health check reachability is not evaluated in v1.`);
      }
      let eni: Eni | undefined;
      let ip: string | undefined;
      if (tg.targetType === 'instance') {
        const inst = model.instances.get(t.id);
        eni = inst?.primaryEniId ? model.enis.get(inst.primaryEniId) : undefined;
        ip = eni?.privateIps[0];
      } else if (tg.targetType === 'ip') {
        ip = t.id;
        eni = eniByPrivateIp(model, parseIpv4(t.id));
      }
      const base = { targetGroupArn: arn, targetId: t.id, port, clientIpPreserved: preserved, ...(eni ? { eniId: eni.id } : {}), ...(ip ? { ip } : {}) };
      if (tg.targetType === 'lambda' || tg.targetType === 'alb') {
        results.push({ ...base, verdict: 'unknown', nodesReachable: 0, nodesTotal: nodes.length, hops: [], notes: [...notes, `${tg.targetType} targets are not analysed in v1.`] });
        continue;
      }
      if (!eni || !ip) {
        results.push({ ...base, verdict: 'unknown', nodesReachable: 0, nodesTotal: nodes.length, hops: [], notes: [...notes, `Target ${t.id} has no interface in the snapshot.`] });
        continue;
      }

      const outcomes: PathResult[] = [];
      if (preserved && clientSample) {
        // Targets see the client's address. A rule that references the NLB's
        // security group still matches (NLB security groups documentation).
        notes.push('Client IP preservation is on: target rules are evaluated against the client address.');
        outcomes.push(evaluateClientPreservedTarget(model, clientSample, { eniId: eni.id, ip }, protocol, port, lb.securityGroupIds));
      } else {
        for (const node of nodes) {
          outcomes.push(evaluatePath(model, { from: { eni: node.id }, to: { eni: eni.id, ip }, protocol, port }, { returnProfiles: ELB_PROFILES }));
        }
      }
      const ok = outcomes.filter((o) => o.verdict === 'reachable').length;
      const unknown = outcomes.some((o) => o.verdict === 'unknown');
      const verdict: LbTargetResult['verdict'] = outcomes.length === 0 ? 'unknown' : ok === outcomes.length ? 'reachable' : ok > 0 ? 'partial' : unknown ? 'unknown' : 'blocked';
      const sample = outcomes.find((o) => o.verdict !== 'reachable') ?? outcomes[0];
      results.push({
        ...base,
        verdict,
        nodesReachable: preserved && clientSample ? (ok ? nodes.length : 0) : ok,
        nodesTotal: nodes.length,
        ...(sample?.blockedAt ? { blockedAt: sample.blockedAt } : {}),
        hops: sample?.hops ?? [],
        notes,
      });
    }
  }
  return results;
}

function analyseLoadBalancer(model: NetworkModel, lb: LoadBalancer, counter: { cells: number }, warnings: Warning[]): ExposureFinding[] {
  const findings: ExposureFinding[] = [];
  const nodes = lb.nodeEniIds.map((id) => model.enis.get(id)).filter((e): e is Eni => !!e);
  if (nodes.length === 0) {
    warnings.push({ code: 'lb-nodes-missing', message: `No node interfaces found for ${lb.name}; its listeners were not analysed.`, resourceIds: [lb.arn] });
    return findings;
  }
  if (!nodes.some((n) => n.publicAddresses.length > 0)) {
    warnings.push({ code: 'lb-nodes-without-public-ip', message: `${lb.name} is internet-facing but none of its node interfaces has a public IP in the snapshot; its listeners were not reported.`, resourceIds: [lb.arn] });
    return findings;
  }
  const docUrl = lb.type === 'application' ? DOCS.albSecurityGroups : DOCS.nlbSecurityGroups;
  for (const l of model.listeners.filter((x) => x.loadBalancerArn === lb.arn)) {
    for (const protocol of listenerProtocols(lb, l.protocol)) {
      // Front leg: analyse each node interface restricted to the listener port.
      const merged = new Map<string, { group: CellGroup; nodes: string[] }>();
      for (const node of nodes) {
        const ip = node.publicAddresses[0]?.privateIp ?? node.privateIps[0];
        if (!ip) continue;
        for (const g of analyseInterface(model, node, ip, { only: { protocol, ports: { from: l.port, to: l.port } }, profiles: CLIENT_PROFILES }, counter)) {
          const key = `${g.sample.returnPath}`;
          const prev = merged.get(key);
          if (prev) {
            prev.group.sources = prev.group.sources.union(g.sources);
            prev.nodes.push(node.id);
          } else merged.set(key, { group: { ...g }, nodes: [node.id] });
        }
      }
      for (const { group, nodes: reached } of merged.values()) {
        const clientSample = group.sources.ranges[0] ? formatIpv4(group.sources.ranges[0].start) : undefined;
        const f = toFinding(model, group, {
          kind: 'load-balancer',
          resourceId: lb.arn,
          resourceName: `${lb.type === 'application' ? 'ALB' : 'NLB'} ${lb.name}`,
          vpcId: lb.vpcId,
          publicIps: nodes.flatMap((n) => n.publicAddresses.map((p) => p.publicIp)),
        });
        f.listener = { arn: l.arn, port: l.port, protocol: l.protocol };
        f.targets = evaluateTargets(model, lb, l.port, protocol, clientSample, l.targetGroupArns);
        if (reached.length < nodes.length) f.reasons.push(`reachable through ${reached.length} of ${nodes.length} load balancer nodes`);
        f.trace = [{ stage: 'scope', decision: 'info', resourceId: lb.arn, detail: `${lb.scheme} ${lb.type} load balancer ${lb.name}, listener ${l.protocol}:${l.port}`, docUrl }, ...f.trace];
        findings.push(f);
      }
    }
  }
  return findings;
}

// ------------------------------------------------------------------ interface classes

/**
 * Internet-to-interface paths depend only on the subnet (route table, NACL,
 * internet gateway), the security groups and the interface type, not on which
 * interface or private address it is. Interfaces that share those are
 * analysed once; for each further interface every resulting group is
 * re-evaluated once on its own address as a check, and any disagreement falls
 * back to the full cell-by-cell analysis.
 */
type ClassCache = Map<string, CellGroup[]>;
function analyseInterfaceCached(model: NetworkModel, eni: Eni, privateIp: string, counter: { cells: number }, cache: ClassCache): CellGroup[] {
  const key = `${eni.subnetId}|${eni.interfaceType}|${[...eni.groupIds].sort().join(',')}`;
  const known = cache.get(key);
  if (!known) {
    const groups = analyseInterface(model, eni, privateIp, {}, counter);
    cache.set(key, groups);
    return groups;
  }
  const out: CellGroup[] = [];
  for (const g of known) {
    const first = g.sources.ranges[0];
    if (!first) continue;
    const withPort = hasPorts(g.protocol) || g.protocol === PROTO_ICMP;
    counter.cells += 1;
    const r = evaluatePath(model, { from: { internet: formatIpv4(first.start) }, to: { eni: eni.id, ip: privateIp }, protocol: g.protocol, ...(withPort ? { port: g.ports.from } : {}) });
    if (r.verdict !== 'reachable' || signature(r) !== g.sig) return analyseInterface(model, eni, privateIp, {}, counter);
    out.push({ ...g, sample: r });
  }
  return out;
}

// ------------------------------------------------------------------ entry point

/**
 * Cells are grouped by the rules that decided them, so two rules allowing the
 * same port from overlapping sources give two findings for one service. Merge
 * findings for the same resource, protocol, ports, listener and return path
 * into one, with the union of their sources. The trace of the widest one is kept.
 */
function mergeFindings(list: ExposureFinding[]): ExposureFinding[] {
  const byKey = new Map<string, ExposureFinding[]>();
  for (const f of list) {
    const k = `${f.resourceId}|${f.protocol}|${f.ports.from}-${f.ports.to}|${f.listener?.arn ?? ''}|${f.returnPath}|${f.publicIps.join()}`;
    (byKey.get(k) ?? byKey.set(k, []).get(k)!).push(f);
  }
  const out: ExposureFinding[] = [];
  for (const group of byKey.values()) {
    if (group.length === 1) {
      out.push(group[0]!);
      continue;
    }
    const sets = group.map((f) => (f.sourceRanges.some((r) => r.startsWith('0.0.0.0/0 (')) ? INTERNET : RangeSet.fromCidrs(f.sourceRanges)));
    const union = sets.reduce((a, b) => a.union(b));
    const widest = group[sets.reduce((bi, s, i) => (s.size() > sets[bi]!.size() ? i : bi), 0)]!;
    out.push({
      ...widest,
      sources: [...new Set(group.flatMap((f) => f.sources))],
      sourceRanges: union.equals(INTERNET) ? ['0.0.0.0/0 (every internet address)'] : union.toCidrs(),
    });
  }
  return out;
}

export interface ExposureOptions {
  /** Analyse only these interfaces and load balancers (by ENI ID or LB ARN). Used to re-check a change quickly. */
  only?: Set<string>;
}

export function analyzeExposure(model: NetworkModel, opts: ExposureOptions = {}): ExposureReport {
  const only = opts.only;
  const warnings: Warning[] = [...model.warnings, ...detectOutOfScope(model)];
  const counter = { cells: 0 };
  const findings: ExposureFinding[] = [];
  let withPublic = 0;
  let analysed = 0;
  const classes: ClassCache = new Map();

  for (const eni of model.enis.values()) {
    if (eni.publicAddresses.length === 0) continue;
    if (only && !only.has(eni.id)) continue;
    withPublic += 1;
    if (NOT_DIRECTLY_EXPOSED.has(eni.interfaceType) || isElbNode(eni)) continue;
    const subnet = model.subnets.get(eni.subnetId);
    if (!subnet || !attachedIgw(model, subnet.vpcId)) continue;
    analysed += 1;
    const missing = eni.groupIds.filter((g) => !model.securityGroups.has(g));
    if (missing.length) {
      warnings.push({ code: 'security-group-missing', message: `${eni.id} uses security groups that are not in the snapshot (${missing.join(', ')}); its exposure may be under-reported.`, resourceIds: [eni.id, ...missing] });
    }
    const name = displayName(model, eni);
    for (const pub of eni.publicAddresses) {
      for (const g of analyseInterfaceCached(model, eni, pub.privateIp, counter, classes)) {
        findings.push(toFinding(model, g, { kind: 'interface', resourceId: eni.id, resourceName: name, vpcId: eni.vpcId, publicIps: [pub.publicIp] }));
      }
    }
  }

  let lbs = 0;
  for (const lb of model.loadBalancers.values()) {
    if (lb.scheme !== 'internet-facing' || lb.type === 'gateway') continue;
    if (only && !only.has(lb.arn)) continue;
    lbs += 1;
    findings.push(...analyseLoadBalancer(model, lb, counter, warnings));
  }

  const merged = mergeFindings(findings);
  merged.sort((a, b) => compareSeverity(a.severity, b.severity) || a.resourceName.localeCompare(b.resourceName) || a.protocol.localeCompare(b.protocol) || a.ports.from - b.ports.from);
  return { findings: merged, warnings, stats: { interfacesWithPublicIp: withPublic, interfacesAnalysed: analysed, loadBalancersAnalysed: lbs, cellsEvaluated: counter.cells } };
}

