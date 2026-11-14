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
import { parseIpv4 } from './ipv4.js';
import { candidateRules, isLateralTarget, reachServices, serviceLabel } from './reach.js';
import type { PairReach, ServiceReach } from './reach.js';
import { compareSeverity, SEVERITY_ORDER } from './risk.js';
import type { ServiceCategory, Severity } from './risk.js';
import { displayName } from './topology.js';
import type { NetworkModel } from './types.js';

export interface BlastEntry {
  eniId: string;
  name: string;
  /** How the internet gets in: the worst exposure finding on it, or the listener in front of it. */
  how: string;
  via: 'direct' | 'load-balancer';
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

export function analyzeBlastRadius(model: NetworkModel, exposure: ExposureReport, opts: BlastOptions = {}): BlastReport {
  const maxDepth = opts.maxDepth ?? 3;
  const maxPairs = opts.maxPairs ?? 50_000;
  const entries = entriesFrom(model, exposure);
  const targets = [...model.enis.values()].filter(isLateralTarget);
  const memo = new Map<string, PairReach>();
  const stats = { pairsConsidered: 0, pairsEvaluated: 0, cellsEvaluated: 0, truncated: false, redundantChains: 0 };

  // Services the internet already reaches directly, or through a load balancer.
  // A chain that ends at one of these tells the reader nothing the exposure
  // report does not, so it is counted but not reported.
  const direct = new Map<string, { protocol: string; from: number; to: number }[]>();
  const addDirect = (eniId: string, protocol: string, from: number, to: number) => (direct.get(eniId) ?? direct.set(eniId, []).get(eniId)!).push({ protocol, from, to });
  for (const f of exposure.findings) {
    if (f.kind === 'interface') addDirect(f.resourceId, f.protocol, f.ports.from, f.ports.to);
    for (const t of f.targets ?? []) if (t.eniId && (t.verdict === 'reachable' || t.verdict === 'partial')) addDirect(t.eniId, 'tcp', t.port, t.port);
  }
  const reachableFromInternet = (eniId: string, s: ServiceReach) =>
    (direct.get(eniId) ?? []).some((d) => d.protocol === s.protocol && (!s.ports || (d.from <= s.ports.to && d.to >= s.ports.from)));

  const pair = (from: string, to: string): PairReach | undefined => {
    const key = `${from}>${to}`;
    const hit = memo.get(key);
    if (hit) return hit;
    stats.pairsConsidered += 1;
    const src = model.enis.get(from)!;
    const dst = model.enis.get(to)!;
    const ip = src.privateIps[0];
    // Cheap check first: no inbound rule that could match means no connection.
    const rules = ip ? candidateRules(model, src, dst, parseIpv4(ip)) : [];
    if (rules !== 'any' && rules.length === 0) {
      const none = { from, to, services: [], cells: 0 };
      memo.set(key, none);
      return none;
    }
    if (stats.pairsEvaluated >= maxPairs) {
      stats.truncated = true;
      return undefined;
    }
    stats.pairsEvaluated += 1;
    const r = reachServices(model, from, to);
    stats.cellsEvaluated += r.cells;
    memo.set(key, r);
    return r;
  };

  const edges = new Map<string, LateralEdge>();
  const chains: AttackChain[] = [];
  const hidden = new Set<string>();
  const footprints: BlastFootprint[] = [];

  for (const entry of entries) {
    // Breadth-first, so each interface is reached by its shortest chain.
    const parent = new Map<string, { from: string; svc: ServiceReach } | null>([[entry.eniId, null]]);
    const depthOf = new Map<string, number>([[entry.eniId, 0]]);
    let frontier = [entry.eniId];
    const hits = new Map<string, { svc: ServiceReach; via: string; depth: number }[]>();
    for (let depth = 1; depth <= maxDepth && frontier.length; depth++) {
      const next: string[] = [];
      for (const from of frontier) {
        for (const dst of targets) {
          if (dst.id === from || dst.id === entry.eniId) continue;
          const r = pair(from, dst.id);
          if (!r || r.services.length === 0) continue;
          const pivot = r.services.some((s) => s.pivot && s.verdict === 'reachable');
          edges.set(`${from}>${dst.id}`, { from, to: dst.id, services: r.services, pivot });
          const list = hits.get(dst.id) ?? [];
          for (const svc of r.services) list.push({ svc, via: from, depth });
          hits.set(dst.id, list);
          if (!depthOf.has(dst.id)) {
            depthOf.set(dst.id, depth);
            const best = r.services.find((s) => s.pivot && s.verdict === 'reachable') ?? r.services[0]!;
            parent.set(dst.id, { from, svc: best });
            if (pivot) next.push(dst.id);
          }
        }
      }
      frontier = next;
    }

    // One chain per (target, impact): the most damaging service reached there.
    let dataStores = 0;
    let takeovers = 0;
    for (const [dstId, list] of hits) {
      const reachable = list.filter((h) => h.svc.verdict === 'reachable');
      if (reachable.some((h) => h.svc.category === 'data')) dataStores += 1;
      if (reachable.some((h) => h.svc.pivot)) takeovers += 1;
      const important = reachable.filter((h) => h.svc.category === 'data' || h.svc.category === 'control' || h.svc.category === 'admin' || h.svc.severity === 'critical');
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
        const why = [
          `${entry.name} is reachable from the internet (${entry.how}).`,
          ...steps.slice(1).map((s, i) => `${steps[i]!.name} can open ${s.service}${s.serviceName ? ` (${s.serviceName})` : ''} on ${s.name}.`),
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
          score: 10 * WEIGHT[severity] + 3 * WEIGHT[entry.severity] - 2 * depth + (h.svc.category === 'data' ? 5 : 0),
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
  for (const c of out) {
    c.entries.sort((a, b) => compareSeverity(a.severity, b.severity) || a.name.localeCompare(b.name));
    if (c.entries.length > 1) c.why.push(`Also reachable from ${c.entries.filter((e) => e.eniId !== c.entry.eniId).map((e) => e.name).join(', ')}.`);
  }
  out.sort((a, b) => b.score - a.score || a.steps.length - b.steps.length || a.id.localeCompare(b.id));
  stats.redundantChains = hidden.size;
  return { entries, edges: [...edges.values()], chains: out, hidden: [...hidden], footprints, stats };
}
