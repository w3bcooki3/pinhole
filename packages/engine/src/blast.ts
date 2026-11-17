/**
 * Blast radius: what an attacker can reach after taking over a resource that
 * the internet can reach.
 *
 * Entry points are interfaces with an internet exposure finding, and load
 * balancer targets that the internet reaches through a listener. From each
 * entry, the analysis follows connections to other interfaces using the exact
 * service reachability in reach.ts. Every reachable service is recorded, but
 * the attacker only moves on (pivots) through services that normally give
 * command execution: remote administration, container and cluster control
 * planes, and wide port ranges. A database reached on 5432 is a target, not a
 * new foothold.
 *
 * This is a model of what the network allows, not of what an attacker could
 * exploit: it assumes credentials or a vulnerability on each pivot service.
 */
import type { ExposureFinding, ExposureReport } from './exposure.js';
import { parseCidr, parseIpv4 } from './ipv4.js';
import { firewallAddressCuts } from './firewall.js';
import { candidateRules, isLateralTarget, reachServices, serviceLabel } from './reach.js';
import type { OnPremReport } from './hybrid.js';
import { pairReach, touchedInterfaces } from './internal.js';
import { LINEAGE } from './lineage.js';
import type { PairReach, ServiceReach } from './reach.js';
import { compareSeverity, isPivotService, SEVERITY_ORDER } from './risk.js';
import type { ServiceCategory, Severity } from './risk.js';
import { displayName } from './topology.js';
import { jewelTag } from './jewels.js';
import type { Eni, IpRange, NetworkModel } from './types.js';
import type { Change } from './whatif.js';

export interface BlastEntry {
  eniId: string;
  name: string;
  /** How the internet gets in: the worst exposure finding on it, or the listener in front of it. */
  how: string;
  via: 'direct' | 'load-balancer' | 'onprem';
  severity: Severity;
  findingKeys: string[];
}

export interface LateralEdge {
  from: string;
  to: string;
  services: ServiceReach[];
  /** True when at least one service lets the attacker move on from `to`. */
  pivot: boolean;
}

export interface ChainStep {
  eniId: string;
  name: string;
  /** Service used to reach this step from the previous one (absent for the entry). */
  service?: string;
  serviceName?: string;
  category?: ServiceCategory;
}

export interface AttackChain {
  /** Target interface and impact: stable across what-if runs, so a chain is "closed" only when no entry point reaches it any more. */
  id: string;
  /** The entry point on the most damaging route. */
  entry: BlastEntry;
  /** Every internet-facing resource that can reach this target, worst first. */
  entries: BlastEntry[];
  /** Number of distinct routes found (one per entry point). */
  routes: number;
  /** The other routes, from the other entry points. */
  altRoutes: ChainStep[][];
  steps: ChainStep[];
  /** The interface the chain ends at. */
  targetId: string;
  /** What is reached at the end: a data store, a control plane, or remote administration. */
  impact: ServiceCategory;
  severity: Severity;
  score: number;
  why: string[];
  /** Set when the target is tagged as a crown jewel: the tag. */
  crownJewel?: string;
}

export interface BlastFootprint {
  entry: BlastEntry;
  /** Interfaces reachable at all, with the shortest number of lateral hops. */
  reachable: { eniId: string; depth: number }[];
  dataStores: number;
  takeovers: number;
  /** Of the reachable resources, how many the internet cannot reach directly. */
  internalOnly: number;
}

export interface BlastReport {
  entries: BlastEntry[];
  edges: LateralEdge[];
  chains: AttackChain[];
  /** IDs (target|impact) of chains not reported because the target is open to the internet on that service. */
  hidden: string[];
  footprints: BlastFootprint[];
  stats: { pairsConsidered: number; pairsEvaluated: number; cellsEvaluated: number; truncated: boolean; redundantChains: number };
}

export interface BlastOptions {
  /** Lateral hops to follow from each entry point (default 3). */
  maxDepth?: number;
  /** Stop evaluating new pairs after this many (default 50,000), and say so. */
  maxPairs?: number;
}

const WEIGHT: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const down = (s: Severity, n = 1): Severity => SEVERITY_ORDER[Math.min(SEVERITY_ORDER.indexOf(s) + n, SEVERITY_ORDER.indexOf('low'))]!;

export const findingKey = (f: Pick<ExposureFinding, 'resourceId' | 'protocol' | 'ports'> & { listener?: { port: number } }) =>
  `${f.resourceId}|${f.protocol}|${f.ports.from}-${f.ports.to}${f.listener ? `|l${f.listener.port}` : ''}`;

function entriesFrom(model: NetworkModel, exposure: ExposureReport): BlastEntry[] {
  const byEni = new Map<string, BlastEntry>();
  const put = (eniId: string, how: string, via: BlastEntry['via'], sev: Severity, key: string) => {
    const eni = model.enis.get(eniId);
    if (!eni || !isLateralTarget(eni)) return;
    const cur = byEni.get(eniId);
    if (!cur) {
      byEni.set(eniId, { eniId, name: displayName(model, eni), how, via, severity: sev, findingKeys: [key] });
      return;
    }
    cur.findingKeys.push(key);
    if (compareSeverity(sev, cur.severity) < 0) Object.assign(cur, { how, via, severity: sev });
  };
  for (const f of exposure.findings) {
    const label = `${serviceLabel(f)} from ${f.sources.join(', ') || 'the internet'}`;
    if (f.kind === 'interface') put(f.resourceId, label, 'direct', f.severity, findingKey(f));
    for (const t of f.targets ?? []) {
      if (!t.eniId || (t.verdict !== 'reachable' && t.verdict !== 'partial')) continue;
      put(t.eniId, `${f.listener?.protocol ?? f.protocol} ${f.listener?.port ?? f.ports.from} on ${f.resourceName}, forwarded to port ${t.port}`, 'load-balancer', f.severity, findingKey(f));
    }
  }
  return [...byEni.values()].sort((a, b) => compareSeverity(a.severity, b.severity) || a.name.localeCompare(b.name));
}

/**
 * How bad a chain is. The impact at the end sets the ceiling; an entry point
 * that is only reachable on web ports, or a long chain, lowers it by a level.
 */
function chainSeverity(entry: Severity, target: ServiceReach, depth: number): Severity {
  let s: Severity = target.category === 'data' || target.category === 'control' || target.category === 'admin' ? 'critical' : target.severity === 'critical' ? 'high' : target.severity;
  if (compareSeverity(entry, 'medium') >= 0) s = down(s);
  if (depth >= 3) s = down(s);
  return s;
}

type Direct = Map<string, { protocol: string; from: number; to: number }[]>;

export function analyzeBlastRadius(model: NetworkModel, exposure: ExposureReport, opts: BlastOptions = {}): BlastReport {
  // Services the internet already reaches directly, or through a load balancer.
  // A chain that ends at one of these tells the reader nothing the exposure
  // report does not, so it is counted but not reported.
  const direct: Direct = new Map();
  const addDirect = (eniId: string, protocol: string, from: number, to: number) => (direct.get(eniId) ?? direct.set(eniId, []).get(eniId)!).push({ protocol, from, to });
  for (const f of exposure.findings) {
    if (f.kind === 'interface') addDirect(f.resourceId, f.protocol, f.ports.from, f.ports.to);
    for (const t of f.targets ?? []) if (t.eniId && (t.verdict === 'reachable' || t.verdict === 'partial')) addDirect(t.eniId, 'tcp', t.port, t.port);
  }
  return blastFrom(model, entriesFrom(model, exposure), direct, opts, 'the internet');
}

/**
 * Attack chains that start on-premises: a host in an on-premises network
 * (over Site-to-Site VPN or Direct Connect) is taken over, and the attacker
 * moves into AWS. Footholds are the interfaces on-premises clients reach on
 * a service that gives command execution (remote administration, control
 * planes, wide port ranges); from there the chains are followed as for the
 * internet. Services on-premises clients reach directly are in the
 * on-premises report, so chains that end at them are not repeated.
 */
export function analyzeOnPremBlast(model: NetworkModel, onprem: OnPremReport, opts: BlastOptions = {}): BlastReport {
  const direct: Direct = new Map();
  const byEni = new Map<string, BlastEntry>();
  for (const f of onprem.findings) {
    (direct.get(f.resourceId) ?? direct.set(f.resourceId, []).get(f.resourceId)!).push({ protocol: f.protocol, from: f.ports.from, to: f.ports.to });
    if (f.protocol === 'icmp' || !isPivotService(f.protocol, f.ports)) continue;
    const eni = model.enis.get(f.resourceId);
    if (!eni || !isLateralTarget(eni)) continue;
    const how = `${serviceLabel(f)} from ${f.sources.slice(0, 2).join(', ')}${f.sources.length > 2 ? ', ...' : ''} on-premises, over ${f.via}`;
    const cur = byEni.get(f.resourceId);
    if (!cur) byEni.set(f.resourceId, { eniId: f.resourceId, name: displayName(model, eni), how, via: 'onprem', severity: f.severity, findingKeys: [findingKey(f)] });
    else {
      cur.findingKeys.push(findingKey(f));
      if (compareSeverity(f.severity, cur.severity) < 0) Object.assign(cur, { how, severity: f.severity });
    }
  }
  const entries = [...byEni.values()].sort((a, b) => compareSeverity(a.severity, b.severity) || a.name.localeCompare(b.name));
  return blastFrom(model, entries, direct, opts, 'on-premises');
}

/**
 * Interfaces that no rule, route or firewall can tell apart: same subnet,
 * same security groups, same interface type and crown jewel tag, and a
 * private IP in the same cell of every address range anywhere in the model.
 * Reachability between two interfaces depends only on these, so it is
 * evaluated once per pair of groups instead of once per pair of interfaces.
 * Only the interface IDs and addresses in a trace differ within a group.
 */
interface Groups {
  of: Map<string, number>;
  /** Members of each group, in model order. */
  members: string[][];
  cuts: Set<number>;
  /** Results per pair of groups (index from * count + to); null when no rule can match. */
  memo: Map<number, PairReach | null>;
  /** For a changed copy that shares the grouping: the original's groups, and the groups the changes touch. */
  parent?: { groups: Groups; touched: Set<number> };
}
const groupCache = new WeakMap<NetworkModel, Groups>();
const groupsByReport = new WeakMap<BlastReport, Map<string, string>>();

/** Every address boundary in the model: any parsed range, wherever it is held. */
function addressCuts(model: NetworkModel): number[] {
  const cuts = new Set<number>();
  const seen = new WeakSet<object>();
  const add = (r: IpRange) => {
    cuts.add(r.start);
    cuts.add(r.end + 1);
  };
  const visit = (v: unknown, depth: number): void => {
    if (!v || typeof v !== 'object' || depth > 12 || seen.has(v)) return;
    seen.add(v);
    if (v instanceof Map) {
      for (const x of v.values()) visit(x, depth + 1);
      return;
    }
    if (v instanceof Set || Array.isArray(v)) {
      for (const x of v) visit(x, depth + 1);
      return;
    }
    const o = v as Record<string, unknown>;
    if (typeof o.start === 'number' && typeof o.end === 'number') add(o as unknown as IpRange);
    for (const k in o) {
      const x = o[k];
      if (typeof x === 'string' && x.includes('/') && /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(x)) {
        try {
          add(parseCidr(x));
        } catch {
          /* not an address */
        }
      } else if (x && typeof x === 'object') visit(x, depth + 1);
    }
  };
  // Interfaces are what is being grouped; their own addresses are not boundaries.
  for (const [k, v] of Object.entries(model)) if (k !== 'enis' && k !== 'instances') visit(v, 0);
  for (const r of firewallAddressCuts(model)) add(r);
  return [...cuts].sort((a, b) => a - b);
}

/** Changes that neither move an interface between groups nor add an address boundary the grouping lacks. */
function keepsGrouping(base: Groups, changes: Change[]): boolean {
  const known = (cidr?: string) => {
    if (!cidr || cidr.includes(':')) return true;
    try {
      const r = parseCidr(cidr);
      return base.cuts.has(r.start) && base.cuts.has(r.end + 1);
    } catch {
      return false;
    }
  };
  return changes.every((c) => {
    switch (c.kind) {
      case 'revoke-sg-rule':
      case 'remove-public-ip':
      case 'add-public-ip':
      case 'remove-nacl-entry':
        return true;
      case 'edit-sg-rule':
        return known(c.cidr);
      case 'add-sg-rule':
        return known(c.cidr) && !c.prefixListId;
      case 'add-nacl-entry':
        return known(c.cidr);
      default:
        return false;
    }
  });
}

function groupsOf(model: NetworkModel, targetList?: Eni[]): Groups {
  const hit = groupCache.get(model);
  if (hit) return hit;
  const targets = targetList ?? targetsOf(model);
  const line = LINEAGE.get(model);
  if (line) {
    const base = groupsOf(line.base);
    if (keepsGrouping(base, line.changes) && targets.length === base.of.size && targets.every((e) => base.of.has(e.id))) {
      const touched = new Set<number>();
      for (const m of [line.base, model]) for (const id of touchedInterfaces(m, line.changes)) if (base.of.has(id)) touched.add(base.of.get(id)!);
      const g: Groups = { of: base.of, members: base.members, cuts: base.cuts, memo: new Map(), parent: { groups: base, touched } };
      groupCache.set(model, g);
      return g;
    }
  }
  const cutList = addressCuts(model);
  const cuts = cutList;
  const cell = (ip: number) => {
    let lo = 0;
    let hi = cuts.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (cuts[mid]! <= ip) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };
  const byKey = new Map<string, number>();
  const g: Groups = { of: new Map(), members: [], cuts: new Set(cutList), memo: new Map() };
  for (const e of targets) {
    const ip = e.privateIps[0];
    const key = `${e.subnetId}|${[...e.groupIds].sort().join(',')}|${e.interfaceType}|${ip ? cell(parseIpv4(ip)) : 'none'}|${jewelTag(model, e) ?? ''}`;
    let i = byKey.get(key);
    if (i === undefined) {
      i = g.members.length;
      byKey.set(key, i);
      g.members.push([]);
    }
    g.members[i]!.push(e.id);
    g.of.set(e.id, i);
  }
  groupCache.set(model, g);
  return g;
}

/** A remembered result from this model or, for a pair the changes cannot touch, from the model it was made from. */
function recall(groups: Groups, key: number, gf: number, gt: number): PairReach | null | undefined {
  let g: Groups | undefined = groups;
  while (g) {
    const v = g.memo.get(key);
    if (v !== undefined) return v;
    if (!g.parent || g.parent.touched.has(gf) || g.parent.touched.has(gt)) return undefined;
    g = g.parent.groups;
  }
  return undefined;
}

const targetsOf = (model: NetworkModel) => [...model.enis.values()].filter(isLateralTarget);

/**
 * Where to keep a new result: the oldest model it is valid for. A changed
 * copy that cannot touch the pair stores it with the model it was made from,
 * so other copies made from that model (other trial changes) find it too.
 */
function home(groups: Groups, gf: number, gt: number): Groups {
  let g = groups;
  while (g.parent && !g.parent.touched.has(gf) && !g.parent.touched.has(gt)) g = g.parent.groups;
  return g;
}

/**
 * Every service `from` can open on `to`, shared between interfaces that no
 * rule tells apart. The per-hop explanations are left out: callers read only
 * the services and the rules that let each through. Use reachServices for a
 * full trace of one pair.
 */
export function reachBetween(model: NetworkModel, from: string, to: string): PairReach {
  const groups = groupsOf(model);
  const gf = groups.of.get(from);
  const gt = groups.of.get(to);
  if (gf === undefined || gt === undefined || from === to) return slim(pairReach(model, from, to));
  const key = gf * groups.members.length + gt;
  let hit = recall(groups, key, gf, gt);
  if (hit === undefined) {
    const src = model.enis.get(from)!;
    const ip = src.privateIps[0];
    const rules = ip ? candidateRules(model, src, model.enis.get(to)!, parseIpv4(ip)) : [];
    hit = rules !== 'any' && rules.length === 0 ? null : slim(reachServices(model, from, to));
  }
  const at = home(groups, gf, gt);
  if (!at.memo.has(key)) at.memo.set(key, hit);
  if (hit === null) return { from, to, services: [], cells: 0 };
  return hit.from === from && hit.to === to ? hit : { from, to, services: hit.services, cells: hit.cells };
}

/** The interface that stands for `eniId` in a report's grouped lateral edges (itself when ungrouped). */
export function blastGroupRep(report: BlastReport, eniId: string): string {
  return groupsByReport.get(report)?.get(eniId) ?? eniId;
}

/**
 * A pair result without the per-hop explanations: lateral edges are many,
 * and only the rules on each hop are read from them. The edges that make up
 * attack chains are evaluated again in full.
 */
function slim(r: PairReach): PairReach {
  return {
    ...r,
    services: r.services.map((s) => ({ ...s, trace: s.trace.filter((h) => h.ruleIds?.length).map((h) => ({ stage: h.stage, decision: h.decision, resourceId: h.resourceId, detail: '', ruleIds: h.ruleIds! })) })),
  };
}

function blastFrom(model: NetworkModel, entries: BlastEntry[], direct: Direct, opts: BlastOptions, origin: string): BlastReport {
  const maxDepth = opts.maxDepth ?? 3;
  const maxPairs = opts.maxPairs ?? 50_000;
  const groups = groupsOf(model);
  const G = groups.members.length;
  const stats = { pairsConsidered: 0, pairsEvaluated: 0, cellsEvaluated: 0, truncated: false, redundantChains: 0 };

  const reachableFromInternet = (eniId: string, s: ServiceReach) =>
    (direct.get(eniId) ?? []).some((d) => d.protocol === s.protocol && (!s.ports || (d.from <= s.ports.to && d.to >= s.ports.from)));

  /** Reachability between two distinct interfaces, evaluated once per pair of groups. */
  const pair = (from: string, to: string): PairReach | undefined => {
    const gf = groups.of.get(from);
    const gt = groups.of.get(to);
    const key = gf === undefined || gt === undefined ? -1 : gf * G + gt;
    if (key >= 0) {
      const hit = recall(groups, key, gf!, gt!);
      if (hit === null) return { from, to, services: [], cells: 0 };
      if (hit) return hit.from === from && hit.to === to ? hit : { from, to, services: hit.services, cells: hit.cells };
    }
    stats.pairsConsidered += 1;
    const src = model.enis.get(from)!;
    const dst = model.enis.get(to)!;
    const ip = src.privateIps[0];
    // Cheap check first: no inbound rule that could match means no connection.
    const rules = ip ? candidateRules(model, src, dst, parseIpv4(ip)) : [];
    if (rules !== 'any' && rules.length === 0) {
      if (key >= 0) home(groups, gf!, gt!).memo.set(key, null);
      return { from, to, services: [], cells: 0 };
    }
    if (stats.pairsEvaluated >= maxPairs) {
      stats.truncated = true;
      return undefined;
    }
    stats.pairsEvaluated += 1;
    const r = slim(reachServices(model, from, to));
    stats.cellsEvaluated += r.cells;
    if (key >= 0) home(groups, gf!, gt!).memo.set(key, r);
    return r;
  };

  const edges = new Map<number, LateralEdge>();
  const chains: AttackChain[] = [];
  const hidden = new Set<string>();
  const footprints: BlastFootprint[] = [];
  const isPivot = (r: PairReach) => r.services.some((s) => s.pivot && s.verdict === 'reachable');
  const isImportant = (s: ServiceReach) => s.verdict === 'reachable' && (s.category === 'data' || s.category === 'control' || s.category === 'admin' || s.severity === 'critical');
  type Hit = { svc: ServiceReach; via: string; depth: number };
  // Per pair of groups, computed once: the services, whether one gives a foothold, and those that can end a chain.
  const facts = new Map<number, { r: PairReach; pivot: boolean; important: ServiceReach[]; takeover: boolean } | null>();
  const factsOf = (gf: number, gt: number, from: string, dst: string) => {
    const k = gf * G + gt;
    let f = facts.get(k);
    if (f !== undefined) return f;
    const r = pair(from, dst);
    if (!r) return undefined; // stopped early: try again next time, in case the limit changes nothing
    f = r.services.length ? { r, pivot: isPivot(r), important: r.services.filter(isImportant), takeover: r.services.some((s) => s.pivot && s.verdict === 'reachable') } : null;
    facts.set(k, f);
    if (f) edges.set(k, { from, to: dst, services: r.services, pivot: f.pivot });
    return f;
  };

  for (const entry of entries) {
    // Where the attacker stands in a group: its first member, or the second when
    // the first is the entry itself (the attacker already holds that one).
    const others = (g: number) => (groups.members[g]![0] === entry.eniId || groups.members[g]!.includes(entry.eniId) ? groups.members[g]!.filter((id) => id !== entry.eniId) : groups.members[g]!);
    const entryG = groups.of.get(entry.eniId)!;
    const pos = (g: number) => {
      const m = g === entryG ? others(g) : groups.members[g]!;
      return m;
    };
    // Breadth-first over groups, so each interface is reached by its shortest chain.
    const depthG = new Map<number, number>();
    const parentG = new Map<number, { from: string; svc: ServiceReach }>();
    const hitsG = new Map<number, { svc: ServiceReach; via: string; alt?: string; depth: number }[]>();
    const takeG = new Set<number>();
    let frontier: (number | 'entry')[] = ['entry'];
    for (let depth = 1; depth <= maxDepth && frontier.length; depth++) {
      const next: number[] = [];
      for (const fg of frontier) {
        const fm = fg === 'entry' ? [entry.eniId] : pos(fg);
        const from = fm[0];
        if (!from) continue;
        const gf = fg === 'entry' ? entryG : fg;
        const alt = fg === 'entry' ? undefined : fm[1];
        for (let tg = 0; tg < G; tg++) {
          const tm = pos(tg);
          const p0 = tm[0];
          if (!p0) continue;
          // Within one group, the attacker on one member reaches another member.
          const dst = p0 === from ? tm[1] : p0;
          if (!dst) continue;
          const f = factsOf(gf, tg, from, dst);
          if (!f) continue;
          if (f.important.length) {
            const list = hitsG.get(tg) ?? hitsG.set(tg, []).get(tg)!;
            for (const svc of f.important) list.push({ svc, via: from, ...(alt ? { alt } : {}), depth });
          }
          if (f.takeover) takeG.add(tg);
          if (!depthG.has(tg)) {
            depthG.set(tg, depth);
            parentG.set(tg, { from, svc: f.r.services.find((s) => s.pivot && s.verdict === 'reachable') ?? f.r.services[0]! });
            if (f.pivot) next.push(tg);
          }
        }
      }
      frontier = next;
    }

    // Back to interfaces: every member of a reached group, except the entry itself.
    const depthOf = new Map<string, number>([[entry.eniId, 0]]);
    const hits = new Map<string, Hit[]>();
    const takeovers0 = new Set<string>();
    for (const [g, d] of [...depthG].sort((a, b) => a[1] - b[1] || a[0] - b[0])) {
      const raw = hitsG.get(g) ?? [];
      const vias = new Set(raw.map((h) => h.via));
      let shared: Hit[] | undefined;
      for (const id of pos(g)) {
        if (!depthOf.has(id)) depthOf.set(id, d);
        if (takeG.has(g)) takeovers0.add(id);
        if (!raw.length) continue;
        if (!vias.has(id)) {
          // Most members are nobody's position: they all see the same list.
          shared ??= raw.map((h) => ({ svc: h.svc, via: h.via, depth: h.depth }));
          hits.set(id, shared);
          continue;
        }
        const list: Hit[] = [];
        for (const h of raw) {
          const via = h.via === id ? h.alt : h.via;
          if (via) list.push({ svc: h.svc, via, depth: h.depth });
        }
        if (list.length) hits.set(id, list);
      }
    }
    const parent = {
      get: (id: string): { from: string; svc: ServiceReach } | null | undefined => {
        if (id === entry.eniId) return null;
        const g = groups.of.get(id);
        return g === undefined ? undefined : parentG.get(g);
      },
    };

    let dataStores = 0;
    const takeovers = takeovers0.size;
    for (const [dstId, list] of hits) {
      // Only services that can end a chain are kept per interface (see above).
      const important = list;
      if (important.some((h) => h.svc.category === 'data')) dataStores += 1;
      const interesting = important.filter((h) => !reachableFromInternet(dstId, h.svc));
      for (const cat of new Set(important.filter((h) => reachableFromInternet(dstId, h.svc)).map((h) => h.svc.category))) hidden.add(`${dstId}|${cat}`);
      const seen = new Set<ServiceCategory>();
      for (const h of interesting.sort((a, b) => a.depth - b.depth || compareSeverity(a.svc.severity, b.svc.severity))) {
        if (seen.has(h.svc.category)) continue;
        seen.add(h.svc.category);
        // Walk back from the attacker's position before the last hop.
        const steps: ChainStep[] = [];
        let cur: string | undefined = h.via;
        while (cur) {
          const p = parent.get(cur);
          const eni = model.enis.get(cur)!;
          steps.unshift({ eniId: cur, name: displayName(model, eni), ...(p ? { service: serviceLabel(p.svc), ...(p.svc.name ? { serviceName: p.svc.name } : {}), category: p.svc.category } : {}) });
          cur = p ? p.from : undefined;
        }
        const dst = model.enis.get(dstId)!;
        steps.push({ eniId: dstId, name: displayName(model, dst), service: serviceLabel(h.svc), ...(h.svc.name ? { serviceName: h.svc.name } : {}), category: h.svc.category });
        const depth = steps.length - 1;
        const severity = chainSeverity(entry.severity, h.svc, depth);
        const jewel = jewelTag(model, dst);
        const why = [
          origin === 'the internet' ? `${entry.name} is reachable from the internet (${entry.how}).` : `${entry.name} is reachable from ${origin} (${entry.how}).`,
          ...steps.slice(1).map((s, i) => `${steps[i]!.name} can open ${s.service}${s.serviceName ? ` (${s.serviceName})` : ''} on ${s.name}.`),
          ...(jewel ? [`${steps[steps.length - 1]!.name} is a crown jewel (${jewel}).`] : []),
        ];
        chains.push({
          id: `${dstId}|${h.svc.category}`,
          entry,
          entries: [entry],
          routes: 1,
          altRoutes: [],
          steps,
          targetId: dstId,
          impact: h.svc.category,
          severity,
          // What is at stake first: tagged crown jewels, then data, then how easy the way in is.
          score: 10 * WEIGHT[severity] + 3 * WEIGHT[entry.severity] - 2 * depth + (h.svc.category === 'data' ? 5 : 0) + (jewel ? 25 : 0),
          ...(jewel ? { crownJewel: jewel } : {}),
          why,
        });
      }
    }
    const reachedIds = [...depthOf].filter(([id]) => id !== entry.eniId);
    footprints.push({ entry, reachable: reachedIds.map(([eniId, depth]) => ({ eniId, depth })), dataStores, takeovers, internalOnly: reachedIds.filter(([id]) => !direct.has(id)).length });
  }

  // One chain per target and impact: the most damaging route stands for it,
  // and every entry point that can get there is listed.
  const merged = new Map<string, AttackChain>();
  for (const c of chains.sort((a, b) => b.score - a.score || a.steps.length - b.steps.length)) {
    const cur = merged.get(c.id);
    if (!cur) {
      merged.set(c.id, c);
      continue;
    }
    if (!cur.entries.some((e) => e.eniId === c.entry.eniId)) cur.entries.push(c.entry);
    cur.routes += 1;
    cur.altRoutes.push(c.steps);
  }
  const out = [...merged.values()];
  // Every step of every route has its own edge, with the full trace for that exact pair.
  const full = new Set<string>();
  const routeEdges = new Map<string, LateralEdge>();
  for (const c of out) {
    for (const route of [c.steps, ...c.altRoutes]) {
      for (let i = 1; i < route.length; i++) {
        const a = route[i - 1]!.eniId;
        const b = route[i]!.eniId;
        if (full.has(`${a}>${b}`)) continue;
        full.add(`${a}>${b}`);
        const r = pairReach(model, a, b);
        if (!r.services.length) continue;
        routeEdges.set(`${a}>${b}`, { from: a, to: b, services: r.services, pivot: isPivot(r) });
      }
    }
  }
  for (const c of out) {
    c.entries.sort((a, b) => compareSeverity(a.severity, b.severity) || a.name.localeCompare(b.name));
    if (c.entries.length > 1) c.why.push(`Also reachable from ${c.entries.filter((e) => e.eniId !== c.entry.eniId).map((e) => e.name).join(', ')}.`);
  }
  out.sort((a, b) => b.score - a.score || a.steps.length - b.steps.length || a.id.localeCompare(b.id));
  stats.redundantChains = hidden.size;
  // Lateral edges: one per pair of groups (between their first members), and
  // every step of every chain route with its exact trace.
  const edgeList = [...routeEdges.values()];
  for (const e of edges.values()) if (!routeEdges.has(`${e.from}>${e.to}`)) edgeList.push(e);
  const report: BlastReport = { entries, edges: edgeList, chains: out, hidden: [...hidden], footprints, stats };
  const rep = new Map<string, string>();
  for (const m of groups.members) for (const id of m) rep.set(id, m[0]!);
  groupsByReport.set(report, rep);
  return report;
}
