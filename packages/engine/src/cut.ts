/**
 * Crown jewels and the smallest cut.
 *
 * Crown jewels are the interfaces whose compromise matters most. They come
 * from tags (`pinhole:crown-jewel`, or a data classification of confidential,
 * restricted, secret, sensitive or PII on the instance, subnet or VPC), or,
 * when nothing is tagged, from what attack chains end at: data stores and
 * cluster control planes.
 *
 * The cut is the smallest set of security group rules whose removal leaves no
 * attack path from the internet to any crown jewel. It is computed as a
 * minimum cut (Edmonds-Karp max flow) on the attack graph:
 *
 *   internet -> controls(entry)        rules that let the internet in
 *   controls(u) -> controls(v)         rules for remote administration from u to v
 *   controls(u) -> reaches(jewel)      rules for the jewel's data or control service
 *   reaches(jewel) -> sink
 *
 * Each edge costs the rules that must all go to cut it (every rule that
 * matches the traffic, since any one of them lets it through), weighted by
 * how likely that traffic is wanted:
 *  - closing a public web or other low-risk service to the internet: 10 a rule;
 *  - a rule that names the source's security group, which someone wrote on
 *    purpose: 5 a rule;
 *  - anything else (remote administration open to the world, a wide range
 *    across the VPC): 1 a rule.
 * So the cut prefers the rules nobody should miss. Rules shared by several
 * edges are counted on each, so the cost is an upper bound; the rule set
 * reported is the union over the cut edges, and it is verified by removing
 * those rules from a copy of the model and re-running both analyses.
 */
import { analyzeExposure } from './exposure.js';
import type { ExposureReport } from './exposure.js';
import { analyzeBlastRadius, findingKey } from './blast.js';
import type { AttackChain, BlastReport } from './blast.js';
import { internalBreaks } from './internal.js';
import type { Breakage } from './internal.js';
import { displayName } from './topology.js';
import { jewelTag } from './jewels.js';
import { allowingRules } from './fixes.js';
import { compareSeverity } from './risk.js';
import { applyChanges, cliFor, ruleText } from './whatif.js';
import type { Change } from './whatif.js';
import type { NetworkModel } from './types.js';

export interface CrownJewel {
  eniId: string;
  name: string;
  /** Why it counts: the tag, or the service chains end at. */
  reason: string;
  /** Attack chains that end here. */
  chains: number;
}

/** Crown jewels from tags; if none are tagged, the targets of data and control-plane chains. */
export function findCrownJewels(model: NetworkModel, blast: BlastReport): CrownJewel[] {
  const chainsTo = new Map<string, AttackChain[]>();
  for (const c of blast.chains) (chainsTo.get(c.targetId) ?? chainsTo.set(c.targetId, []).get(c.targetId)!).push(c);
  const tagged: CrownJewel[] = [];
  for (const e of model.enis.values()) {
    const reason = jewelTag(model, e);
    if (reason) tagged.push({ eniId: e.id, name: displayName(model, e), reason, chains: chainsTo.get(e.id)?.length ?? 0 });
  }
  if (tagged.length) return tagged.sort((a, b) => b.chains - a.chains || a.name.localeCompare(b.name));
  const out: CrownJewel[] = [];
  for (const [id, list] of chainsTo) {
    const worth = list.filter((c) => c.impact === 'data' || c.impact === 'control');
    if (!worth.length) continue;
    const e = model.enis.get(id)!;
    out.push({ eniId: id, name: displayName(model, e), reason: worth.some((c) => c.impact === 'data') ? 'data store at the end of an attack chain' : 'control plane at the end of an attack chain', chains: list.length });
  }
  return out.sort((a, b) => b.chains - a.chains || a.name.localeCompare(b.name));
}

export interface CutEdge {
  from: string;
  fromName: string;
  to: string;
  toName: string;
  /** What the edge is: the internet getting in, a takeover, or reaching a jewel. */
  kind: 'entry' | 'pivot' | 'jewel';
  ruleIds: string[];
}

export interface MinCut {
  jewels: CrownJewel[];
  /** Edges of the minimum cut, and the rules to remove. */
  edges: CutEdge[];
  ruleIds: string[];
  changes: Change[];
  cli: string[];
  /** Rule texts, for display. */
  rules: { id: string; groupId: string; text: string }[];
  /** No path to any jewel is left after removing the rules: checked by re-analysis. */
  verified: boolean;
  /** Chains to jewels before and after. */
  before: number;
  after: number;
  /** Internal traffic the cut breaks. */
  breaks: Breakage[];
  /** Some edge cannot be cut with security group rules (a destination without security groups). */
  uncuttable: boolean;
  /** Weighted cost of the cut (see above): lower means less wanted traffic lost. */
  cost: number;
}

const INF = 1e9;

/** The smallest set of rules that cuts every attack path from the internet to the crown jewels. */
export function findMinCut(model: NetworkModel, exposure: ExposureReport, blast: BlastReport, jewelsIn?: CrownJewel[]): MinCut {
  const jewels = jewelsIn ?? findCrownJewels(model, blast);
  const jewelIds = new Set(jewels.map((j) => j.eniId));
  const empty: MinCut = { jewels, edges: [], ruleIds: [], changes: [], cli: [], rules: [], verified: true, before: 0, after: 0, breaks: [], uncuttable: false, cost: 0 };
  const before = blast.chains.filter((c) => jewelIds.has(c.targetId)).length;
  if (!before) return empty;

  // Graph: node 0 is the internet, 1 the sink; then controls(eni) and reaches(jewel).
  const ids = new Map<string, number>();
  const node = (k: string) => ids.get(k) ?? (ids.set(k, ids.size + 2), ids.size + 1);
  type E = { to: number; cap: number; rev: number; rules?: string[]; meta?: CutEdge };
  const g: E[][] = [[], []];
  const ruleById = new Map<string, { referencedGroupId?: string }>();
  for (const sg of model.securityGroups.values()) for (const r of sg.ingress) ruleById.set(r.id, r);
  const addEdge = (a: number, b: number, rules: string[] | undefined, meta: CutEdge, weight = 1) => {
    while (g.length <= Math.max(a, b)) g.push([]);
    const cost = (rules ?? []).reduce((n, id) => n + (ruleById.get(id)?.referencedGroupId ? Math.max(weight, 5) : weight), 0);
    const cap = rules === undefined ? INF : cost || INF;
    g[a]!.push({ to: b, cap, rev: g[b]!.length, rules: rules ?? [], meta });
    g[b]!.push({ to: a, cap: 0, rev: g[a]!.length - 1 });
  };
  const sgRules = (hops: { stage: string; ruleIds?: string[] }[]) => hops.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds;
  const name = (id: string) => (model.enis.get(id) ? displayName(model, model.enis.get(id)!) : id);

  // Internet -> entry: every rule that admits the internet on every finding
  // that makes it an entry. Behind a load balancer, the rules on its listener.
  const findingByKey = new Map(exposure.findings.map((f) => [findingKey(f), f]));
  for (const en of blast.entries) {
    const rules = new Set<string>();
    let open = false;
    let worst: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'info';
    for (const k of en.findingKeys) {
      const f = findingByKey.get(k);
      if (!f) continue;
      const r = allowingRules(model, f);
      if (!r.length) open = true;
      r.forEach((x) => rules.add(x));
      if (compareSeverity(f.severity, worst) < 0) worst = f.severity;
    }
    // Closing a public website or other low-risk service is a last resort.
    const weight = compareSeverity(worst, 'high') <= 0 ? 1 : 10;
    addEdge(0, node(`c:${en.eniId}`), open ? undefined : [...rules], { from: 'internet', fromName: 'the internet', to: en.eniId, toName: en.name, kind: 'entry', ruleIds: [...rules] }, weight);
  }
  // Lateral edges.
  for (const e of blast.edges) {
    const pivots = e.services.filter((s) => s.pivot && s.verdict === 'reachable');
    const cutRules = (list: typeof e.services) => {
      const rules = new Set<string>();
      for (const s of list) {
        const r = sgRules(s.trace);
        if (!r?.length) return undefined;
        r.forEach((x) => rules.add(x));
      }
      return [...rules];
    };
    if (pivots.length) addEdge(node(`c:${e.from}`), node(`c:${e.to}`), cutRules(pivots), { from: e.from, fromName: name(e.from), to: e.to, toName: name(e.to), kind: 'pivot', ruleIds: cutRules(pivots) ?? [] });
    if (jewelIds.has(e.to)) {
      const important = e.services.filter((s) => s.verdict === 'reachable' && (s.category === 'data' || s.category === 'control' || s.category === 'admin' || s.severity === 'critical'));
      if (important.length) addEdge(node(`c:${e.from}`), node(`r:${e.to}`), cutRules(important), { from: e.from, fromName: name(e.from), to: e.to, toName: name(e.to), kind: 'jewel', ruleIds: cutRules(important) ?? [] });
    }
  }
  for (const j of jewelIds) if (ids.has(`r:${j}`)) addEdge(node(`r:${j}`), 1, undefined, { from: j, fromName: name(j), to: 'sink', toName: '', kind: 'jewel', ruleIds: [] });
  // A jewel the attacker takes over is reached too.
  for (const j of jewelIds) if (ids.has(`c:${j}`)) addEdge(node(`c:${j}`), node(`r:${j}`), undefined, { from: j, fromName: name(j), to: j, toName: name(j), kind: 'jewel', ruleIds: [] });

  // Edmonds-Karp.
  let flow = 0;
  for (;;) {
    const prev: ([number, number] | undefined)[] = new Array(g.length);
    const q = [0];
    prev[0] = [-1, -1];
    while (q.length && !prev[1]) {
      const u = q.shift()!;
      g[u]!.forEach((ed, i) => {
        if (ed.cap > 0 && !prev[ed.to]) {
          prev[ed.to] = [u, i];
          q.push(ed.to);
        }
      });
    }
    if (!prev[1]) break;
    let push = INF;
    for (let v = 1; v !== 0; v = prev[v]![0]) push = Math.min(push, g[prev[v]![0]]![prev[v]![1]]!.cap);
    for (let v = 1; v !== 0; v = prev[v]![0]) {
      const ed = g[prev[v]![0]]![prev[v]![1]]!;
      ed.cap -= push;
      g[v]![ed.rev]!.cap += push;
    }
    flow += push;
    if (flow >= INF) break;
  }
  // The cut: edges from the side the internet still reaches to the other.
  const seen = new Set([0]);
  const q = [0];
  while (q.length) {
    const u = q.shift()!;
    for (const ed of g[u]!) if (ed.cap > 0 && !seen.has(ed.to)) seen.add(ed.to), q.push(ed.to);
  }
  const edges: CutEdge[] = [];
  for (const u of seen) for (const ed of g[u]!) if (ed.meta && !seen.has(ed.to)) edges.push(ed.meta);
  const uncuttable = flow >= INF;
  let ruleIds = [...new Set(edges.flatMap((e) => e.ruleIds))];
  const remaining = (list: string[]) => {
    try {
      const m1 = applyChanges(model, list.map((ruleId): Change => ({ kind: 'revoke-sg-rule', ruleId })));
      const e1 = analyzeExposure(m1);
      return analyzeBlastRadius(m1, e1).chains.filter((c) => jewelIds.has(c.targetId)).length;
    } catch {
      return Infinity;
    }
  };
  // Shared rules are counted once per edge in the flow, so the union can hold
  // a rule the others already cover: drop each one that is not needed.
  if (!uncuttable && ruleIds.length > 1 && remaining(ruleIds) === 0) {
    for (const id of [...ruleIds].reverse()) {
      const without = ruleIds.filter((x) => x !== id);
      if (without.length && remaining(without) === 0) ruleIds = without;
    }
  }
  const kept = new Set(ruleIds);
  for (const e of edges) e.ruleIds = e.ruleIds.filter((id) => kept.has(id));
  const changes: Change[] = ruleIds.map((ruleId) => ({ kind: 'revoke-sg-rule', ruleId }));
  const rules = ruleIds.map((id) => {
    for (const sg of model.securityGroups.values()) {
      const r = sg.ingress.find((x) => x.id === id);
      if (r) return { id, groupId: sg.id, text: ruleText(r) };
    }
    return { id, groupId: '', text: '' };
  });

  let after = before;
  let breaks: Breakage[] = [];
  if (changes.length && !uncuttable) {
    try {
      const m1 = applyChanges(model, changes);
      const e1 = analyzeExposure(m1);
      after = analyzeBlastRadius(m1, e1).chains.filter((c) => jewelIds.has(c.targetId)).length;
      breaks = internalBreaks(model, m1, changes);
    } catch {
      after = before;
    }
  }
  return { jewels, edges, ruleIds, changes, cli: changes.flatMap((c) => cliFor(model, c)), rules, verified: !uncuttable && after === 0, before, after, breaks, uncuttable, cost: uncuttable ? Infinity : flow };
}
