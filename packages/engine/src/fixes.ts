/**
 * Fix finder: candidate changes that close an exposure finding, each one
 * proved by applying it to a copy of the model and re-running the analysis.
 *
 * Candidates, from narrowest to broadest:
 *  - cut the finding's ports out of a wider security group rule;
 *  - remove the security group rule(s) that let the traffic in;
 *  - add a network ACL deny for the ports, ahead of the rule that allows them;
 *  - remove the public IP.
 *
 * A fix is "verified" only if the re-analysis no longer finds any internet
 * path to the finding's resource, protocol and ports. Everything else the
 * change closes or narrows is reported too: closing another critical path is
 * a bonus; closing a web or low-severity path is collateral, because it is
 * probably traffic someone wants.
 */
import { analyzeExposure } from './exposure.js';
import type { ExposureFinding, ExposureReport } from './exposure.js';
import { hasPorts, normalizeProtocol, protocolName } from './packet.js';
import { compareSeverity } from './risk.js';
import { serviceLabel } from './reach.js';
import { INTERNET6, RangeSet6 } from './ipv6.js';
import { INTERNET, RangeSet } from './ipv4.js';
import { analyzeBlastRadius, findingKey } from './blast.js';
import type { AttackChain, BlastReport } from './blast.js';
import { naclForSubnet } from './topology.js';
import { applyChanges, cliFor, describeChange, diffExposure, ruleText } from './whatif.js';
import type { Change, ExposureDelta } from './whatif.js';
import type { NetworkModel, SgRule } from './types.js';

export interface FixCandidate {
  id: string;
  title: string;
  rationale: string;
  changes: Change[];
  steps: string[];
  cli: string[];
  /** The finding is fully closed after the change. */
  verified: boolean;
  /** Changes on the finding itself. */
  closes: ExposureDelta[];
  /** Other critical or high paths the same change closes or narrows. */
  bonus: ExposureDelta[];
  /** Other, probably wanted, paths the change also closes or narrows. */
  collateral: ExposureDelta[];
  /** Paths the change would open (should be empty). */
  opened: ExposureDelta[];
  /**
   * For a change that keeps access from inside the network: attack chains that
   * still reach this resource from another internet-facing server afterwards.
   */
  stillReachable: AttackChain[];
  score: number;
}

function findRule(model: NetworkModel, id: string): SgRule | undefined {
  for (const g of model.securityGroups.values()) {
    const r = g.ingress.find((x) => x.id === id);
    if (r) return r;
  }
  return undefined;
}

/** Interfaces and load balancers a change can affect, so re-analysis can be limited to them. */
function affected(model: NetworkModel, changes: Change[], finding: ExposureFinding): Set<string> {
  const ids = new Set<string>([finding.resourceId]);
  const groups = new Set<string>();
  const subnets = new Set<string>();
  for (const c of changes) {
    if (c.kind === 'revoke-sg-rule' || c.kind === 'edit-sg-rule') {
      for (const g of model.securityGroups.values()) if (g.ingress.some((r) => r.id === c.ruleId) || g.egress.some((r) => r.id === c.ruleId)) groups.add(g.id);
    }
    if (c.kind === 'add-sg-rule') groups.add(c.groupId);
    if (c.kind === 'add-nacl-entry' || c.kind === 'remove-nacl-entry') for (const s of model.nacls.get(c.naclId)?.subnetIds ?? []) subnets.add(s);
    if (c.kind === 'remove-public-ip' || c.kind === 'detach-sg') ids.add(c.eniId);
  }
  for (const e of model.enis.values()) if (subnets.has(e.subnetId) || e.groupIds.some((g) => groups.has(g))) ids.add(e.id);
  for (const lb of model.loadBalancers.values()) if (lb.securityGroupIds.some((g) => groups.has(g)) || lb.subnetIds.some((s) => subnets.has(s))) ids.add(lb.arn);
  return ids;
}

const overlaps = (d: ExposureDelta, f: ExposureFinding) =>
  d.resourceId === f.resourceId && d.protocol === f.protocol && (!d.ports || (d.ports.from <= f.ports.to && d.ports.to >= f.ports.from)) && (f.listener ? d.listenerPort === f.listener.port : d.listenerPort === undefined);

/**
 * Every inbound rule on the resource's security groups that admits some
 * internet address on the finding's protocol and ports. The trace names the
 * rules for one representative packet; this finds the rest, so a fix can
 * cover all of them.
 */
function allowingRules(model: NetworkModel, f: ExposureFinding): string[] {
  const groups = f.kind === 'interface' ? model.enis.get(f.resourceId)?.groupIds ?? [] : model.loadBalancers.get(f.resourceId)?.securityGroupIds ?? [];
  const proto = normalizeProtocol(f.protocol);
  const out: string[] = [];
  for (const gid of groups) {
    for (const r of model.securityGroups.get(gid)?.ingress ?? []) {
      if (r.protocol !== '-1' && r.protocol !== proto) continue;
      if (hasPorts(proto) && r.protocol !== '-1' && r.fromPort !== undefined && r.fromPort !== -1 && ((r.toPort ?? r.fromPort) < f.ports.from || r.fromPort > f.ports.to)) continue;
      if (f.family === 'ipv6') {
        // IPv6 findings come only from IPv6 rules that admit some internet address.
        if (r.ipv6CidrText && !INTERNET6.intersect(RangeSet6.fromCidrs([r.ipv6CidrText])).isEmpty()) out.push(r.id);
        continue;
      }
      const sources = r.cidr ? [r.cidr] : r.prefixListId ? model.prefixLists.get(r.prefixListId)?.entries ?? [] : [];
      if (sources.some((c) => !INTERNET.intersect(RangeSet.of([c])).isEmpty())) out.push(r.id);
    }
  }
  // Fall back to the trace when groups are not in the snapshot.
  return out.length ? out : (f.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? []).filter((id) => findRule(model, id));
}

function candidates(model: NetworkModel, f: ExposureFinding): { title: string; rationale: string; changes: Change[] }[] {
  const out: { title: string; rationale: string; changes: Change[] }[] = [];
  const ruleIds = allowingRules(model, f);
  const proto = normalizeProtocol(f.protocol);
  const label = serviceLabel(f);

  for (const id of ruleIds) {
    const r = findRule(model, id)!;
    const from = r.fromPort ?? -1;
    const to = r.toPort ?? from;
    const wider = hasPorts(proto) && r.protocol === proto && from !== -1 && (from < f.ports.from || to > f.ports.to);
    if (wider) {
      const changes: Change[] = [];
      if (from < f.ports.from) changes.push({ kind: 'edit-sg-rule', ruleId: id, fromPort: from, toPort: f.ports.from - 1 });
      if (to > f.ports.to) {
        if (changes.length) changes.push({ kind: 'add-sg-rule', groupId: r.groupId, egress: false, protocol: f.protocol, fromPort: f.ports.to + 1, toPort: to, ...(r.cidr ? { cidr: r.cidr.text } : {}), ...(r.referencedGroupId ? { referencedGroupId: r.referencedGroupId } : {}), ...(r.description ? { description: r.description } : {}) });
        else changes.push({ kind: 'edit-sg-rule', ruleId: id, fromPort: f.ports.to + 1, toPort: to });
      }
      out.push({ title: `Cut ${label} out of ${id}`, rationale: `${id} allows ${ruleText(r)}. Keeping the rest of its range and dropping ${label} closes this path without touching anything else the rule allows.`, changes });
    }
    // Keep access from inside the VPC, close it to everyone else.
    const vpc = model.vpcs.get(f.vpcId);
    const inside = r.cidr && vpc?.cidrs.length && !vpc.cidrs.some((c) => c.start <= r.cidr!.start && c.end >= r.cidr!.end);
    if (inside && vpc) {
      const [first, ...rest] = vpc.cidrs;
      const ports = r.fromPort === undefined || r.fromPort === -1 ? {} : { fromPort: r.fromPort, toPort: r.toPort ?? r.fromPort };
      out.push({
        title: `Allow ${label} on ${id} only from inside ${vpc.id}`,
        rationale: `Changes the source of ${id} from ${r.cidr!.text} to ${vpc.cidrs.map((c) => c.text).join(' and ')}. Servers in the VPC keep access; the internet loses it.`,
        changes: [
          { kind: 'edit-sg-rule', ruleId: id, cidr: first!.text },
          ...rest.map((c): Change => ({ kind: 'add-sg-rule', groupId: r.groupId, egress: false, protocol: protocolName(r.protocol), ...ports, cidr: c.text, ...(r.description ? { description: r.description } : {}) })),
        ],
      });
    }
    out.push({ title: `Remove ${id}`, rationale: `${id} (${ruleText(r)}) is ${ruleIds.length > 1 ? 'one of the rules' : 'the rule'} letting this traffic in.`, changes: [{ kind: 'revoke-sg-rule', ruleId: id }] });
  }
  if (ruleIds.length > 1) {
    out.push({ title: `Remove all ${ruleIds.length} rules that allow ${label}`, rationale: `${ruleIds.join(', ')} each allow this traffic from the internet, so each must go.`, changes: ruleIds.map((ruleId) => ({ kind: 'revoke-sg-rule', ruleId })) });
    const vpc = model.vpcs.get(f.vpcId);
    if (vpc?.cidrs.length === 1 && ruleIds.every((id) => findRule(model, id)?.cidr)) {
      out.push({
        title: `Allow ${label} only from inside ${vpc.id}, on all ${ruleIds.length} rules`,
        rationale: `${ruleIds.join(', ')} each allow this traffic from the internet. Changing each source to ${vpc.cidrs[0]!.text} keeps access for servers in the VPC.`,
        changes: ruleIds.map((ruleId): Change => ({ kind: 'edit-sg-rule', ruleId, cidr: vpc.cidrs[0]!.text })),
      });
    }
  }

  // Network ACL deny, numbered just ahead of the entry that currently allows it.
  if (f.kind === 'interface' && hasPorts(proto)) {
    const eni = model.enis.get(f.resourceId);
    const subnet = eni ? model.subnets.get(eni.subnetId) : undefined;
    const acl = subnet ? naclForSubnet(model, subnet) : undefined;
    const naclHop = f.trace.find((h) => h.stage === 'dest-nacl-ingress');
    const allowing = Number(naclHop?.ruleIds?.[0]?.split('#')[2]);
    if (acl && Number.isFinite(allowing)) {
      const taken = new Set(acl.entries.filter((e) => !e.egress).map((e) => e.ruleNumber));
      let n = allowing - 1;
      while (n >= 1 && taken.has(n)) n -= 1;
      if (n >= 1) {
        out.push({
          title: `Deny ${label} in ${acl.id}`,
          rationale: `An inbound deny numbered ${n}, ahead of rule ${allowing}, blocks ${label} for every address and every interface in ${acl.subnetIds.join(', ')}, including traffic from inside the VPC.`,
          changes: [{ kind: 'add-nacl-entry', naclId: acl.id, egress: false, ruleNumber: n, action: 'deny', protocol: f.protocol, cidr: '0.0.0.0/0', fromPort: f.ports.from, toPort: f.ports.to }],
        });
      }
    }
  }

  if (f.kind === 'interface') {
    for (const ip of f.publicIps) {
      out.push({ title: `Remove public IP ${ip}`, rationale: `Without a public address nothing on the internet can start a connection to ${f.resourceName}. Reach it through a load balancer, Session Manager or a VPN instead.`, changes: [{ kind: 'remove-public-ip', eniId: f.resourceId, publicIp: ip }] });
    }
  }
  return out;
}

const SEV_WEIGHT = { critical: 8, high: 5, medium: 2, low: 1, info: 0 } as const;

/** Verified fixes for one finding, best first. */
export function findFixes(model: NetworkModel, finding: ExposureFinding): FixCandidate[] {
  const fixes: FixCandidate[] = [];
  for (const c of candidates(model, finding)) {
    let after: NetworkModel;
    try {
      after = applyChanges(model, c.changes);
    } catch {
      continue;
    }
    const only = affected(model, c.changes, finding);
    const before: ExposureReport = analyzeExposure(model, { only });
    const next: ExposureReport = analyzeExposure(after, { only });
    const diff = diffExposure(before, next);
    const verified = !next.findings.some((g) => g.resourceId === finding.resourceId && g.protocol === finding.protocol && g.ports.from <= finding.ports.to && g.ports.to >= finding.ports.from && (finding.listener ? g.listener?.port === finding.listener.port : !g.listener));
    const lost = diff.deltas.filter((d) => d.status === 'closed' || d.status === 'narrowed');
    const closes = lost.filter((d) => overlaps(d, finding));
    const others = lost.filter((d) => !overlaps(d, finding));
    const bonus = others.filter((d) => compareSeverity(d.severity, 'high') <= 0);
    const collateral = others.filter((d) => compareSeverity(d.severity, 'high') > 0);
    const opened = diff.deltas.filter((d) => d.status === 'opened' || d.status === 'widened');
    // A network ACL deny hits every interface in the subnet, and removing a public
    // IP cuts everything on the interface: prefer the targeted rule change.
    const breadth = c.changes.some((x) => x.kind === 'add-nacl-entry') ? 15 : c.changes.some((x) => x.kind === 'remove-public-ip') ? 12 : 0;
    const keepsAccess = c.changes.every((x) => x.kind === 'edit-sg-rule' || x.kind === 'add-sg-rule');
    // Restricting a rule to the VPC keeps internal access, which is the point, but
    // a compromised internet-facing server inside the VPC may then still reach it.
    let stillReachable: AttackChain[] = [];
    if (keepsAccess && verified && finding.kind !== 'load-balancer') {
      const full = analyzeExposure(after);
      stillReachable = analyzeBlastRadius(after, full).chains.filter((x) => x.targetId === finding.resourceId);
    }
    const score =
      (keepsAccess ? 3 : 0) +
      (verified ? 100 : 0) + bonus.reduce((n, d) => n + SEV_WEIGHT[d.severity], 0) - collateral.reduce((n, d) => n + 12 + SEV_WEIGHT[d.severity], 0) - 50 * opened.length - 2 * c.changes.length - breadth - 5 * stillReachable.length;
    fixes.push({
      id: c.changes.map((x) => JSON.stringify(x)).join('|'),
      ...c,
      steps: c.changes.map((x) => describeChange(model, x)),
      cli: c.changes.flatMap((x) => cliFor(model, x)),
      verified,
      closes,
      bonus,
      collateral,
      opened,
      stillReachable,
      score,
    });
  }
  return fixes.sort((a, b) => b.score - a.score);
}

// ------------------------------------------------------------------ chokepoints

export interface Chokepoint {
  ruleId: string;
  groupId: string;
  text: string;
  /** Chains (by ID) that no longer exist once this rule is removed. */
  chainsClosed: string[];
  /** Internet exposure ranges closed or narrowed. */
  exposureClosed: ExposureDelta[];
  /** Of those, the ones that are probably wanted (medium and below). */
  collateral: ExposureDelta[];
  cli: string[];
}

/**
 * The security group rules that sit on attack chains, ranked by how many
 * chains removing each one would cut. Each rule is removed on a copy of the
 * model and both analyses are run again, so the counts are exact.
 * Candidates are the rules that let traffic in on every chain step, plus the
 * rules on the entry points' internet exposure; at most `limit` of the most
 * frequent are checked.
 */
export function findChokepoints(model: NetworkModel, exposure: ExposureReport, blast: BlastReport, limit = 20): Chokepoint[] {
  const freq = new Map<string, number>();
  const bump = (id: string) => freq.set(id, (freq.get(id) ?? 0) + 1);
  const edgeOf = new Map(blast.edges.map((e) => [`${e.from}>${e.to}`, e]));
  for (const c of blast.chains) {
    for (let i = 1; i < c.steps.length; i++) {
      const e = edgeOf.get(`${c.steps[i - 1]!.eniId}>${c.steps[i]!.eniId}`);
      const svc = e?.services.find((s) => serviceLabel(s) === c.steps[i]!.service);
      for (const id of svc?.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? []) bump(id);
    }
    const keys = new Set(c.entries.flatMap((e) => e.findingKeys));
    for (const f of exposure.findings) {
      if (!keys.has(findingKey(f))) continue;
      for (const id of f.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? []) bump(id);
    }
  }
  const before = new Set(blast.chains.map((c) => c.id));
  const out: Chokepoint[] = [];
  for (const [ruleId] of [...freq].sort((a, b) => b[1] - a[1]).slice(0, limit)) {
    const rule = findRule(model, ruleId);
    if (!rule) continue;
    const change: Change = { kind: 'revoke-sg-rule', ruleId };
    const after = applyChanges(model, [change]);
    const e1 = analyzeExposure(after);
    const b1 = analyzeBlastRadius(after, e1);
    const still = new Set(b1.chains.map((c) => c.id));
    const diff = diffExposure(exposure, e1);
    const lost = diff.deltas.filter((d) => d.status === 'closed' || d.status === 'narrowed');
    out.push({
      ruleId,
      groupId: rule.groupId,
      text: ruleText(rule),
      chainsClosed: [...before].filter((id) => !still.has(id)),
      exposureClosed: lost,
      collateral: lost.filter((d) => compareSeverity(d.severity, 'high') > 0),
      cli: cliFor(model, change),
    });
  }
  return out
    .filter((c) => c.chainsClosed.length || c.exposureClosed.length)
    .sort((a, b) => b.chainsClosed.length - a.chainsClosed.length || a.collateral.length - b.collateral.length || b.exposureClosed.length - a.exposureClosed.length);
}

// ------------------------------------------------------------------ remediation plan

export interface PlanStep {
  title: string;
  rationale: string;
  changes: Change[];
  cli: string[];
  /** Critical and high exposures this step closes or narrows. */
  closes: ExposureDelta[];
  /** Attack chains this step cuts. */
  chainsCut: AttackChain[];
  /** Other paths it closes or narrows, probably wanted. */
  collateral: ExposureDelta[];
}

export interface FixPlan {
  steps: PlanStep[];
  before: { exposures: number; chains: number };
  after: { exposures: number; chains: number };
  /** Goals no single verified change could close. */
  unresolved: string[];
  /** How the plan was found: candidate changes tried, full re-analyses run, redundant steps dropped. */
  stats: { candidates: number; evaluations: number; pruned: number };
}

export interface PlanOptions {
  /** Most steps to plan (default 10). */
  maxSteps?: number;
  /** Which exposures and chains the plan must close (default: critical and high). */
  goals?: { finding?: (f: ExposureFinding) => boolean; chain?: (c: AttackChain) => boolean };
}

const W = { critical: 10, high: 6, medium: 0, low: 0, info: 0 } as const;
const isSevere = (s: { severity: keyof typeof W }) => s.severity === 'critical' || s.severity === 'high';

type Cand = { title: string; rationale: string; changes: Change[] };
type Eval = { m: NetworkModel; e: ExposureReport; b: BlastReport; diff: ReturnType<typeof diffExposure> };

/**
 * A short list of changes that, applied in order, closes every critical and
 * high exposure and attack chain it can. Nothing is guessed: every number
 * comes from applying the change to a copy of the model and re-running both
 * analyses.
 *
 * 1. Candidates: the verified fixes for the worst few open exposures, and the
 *    removal of each rule on the worst few open attack chains (every route).
 * 2. Lazy greedy selection (Minoux): each candidate keeps its last measured
 *    gain as an upper bound, because closing goals only ever lowers what is
 *    left for the others. Candidates are re-measured in bound order and the
 *    search stops as soon as no bound can beat the best fresh gain, so most
 *    candidates are not re-analysed at every step. Candidates for the goals
 *    being worked on are always re-measured, since two rules that only matter
 *    together break the bound.
 * 3. Pruning: once the plan is built, each step is taken out in turn and the
 *    rest re-applied; a step whose removal leaves every goal as closed as
 *    before is redundant (a later, broader step covered it) and is dropped.
 */
export function planFixes(model: NetworkModel, exposure: ExposureReport, blast: BlastReport, maxStepsOrOpts: number | PlanOptions = 10): FixPlan {
  const opts: PlanOptions = typeof maxStepsOrOpts === 'number' ? { maxSteps: maxStepsOrOpts } : maxStepsOrOpts;
  const maxSteps = opts.maxSteps ?? 10;
  const isGoalF = (f: ExposureFinding) => isSevere(f) && (opts.goals?.finding ? opts.goals.finding(f) : !opts.goals);
  const isGoalC = (c: AttackChain) => isSevere(c) && (opts.goals?.chain ? opts.goals.chain(c) : !opts.goals);
  const weight = (e: ExposureReport, b: BlastReport) => e.findings.filter(isGoalF).reduce((n, f) => n + W[f.severity], 0) + b.chains.filter(isGoalC).reduce((n, c) => n + W[c.severity], 0);
  const stats = { candidates: 0, evaluations: 0, pruned: 0 };

  const evaluate = (m0: NetworkModel, e0: ExposureReport, b0: BlastReport, changes: Change[]): Eval | undefined => {
    let m1: NetworkModel;
    try {
      m1 = applyChanges(m0, changes);
    } catch {
      return undefined;
    }
    stats.evaluations += 1;
    const e1 = analyzeExposure(m1);
    const b1 = analyzeBlastRadius(m1, e1);
    return { m: m1, e: e1, b: b1, diff: diffExposure(e0, e1, { before: b0, after: b1 }) };
  };
  const collateralOf = (d: ReturnType<typeof diffExposure>) => d.deltas.filter((x) => (x.status === 'closed' || x.status === 'narrowed') && compareSeverity(x.severity, 'high') > 0);

  let m = model;
  let e = exposure;
  let b = blast;
  const chosen: Cand[] = [];
  const skipped = new Set<string>();
  const unresolved: string[] = [];
  const pool = new Map<string, Cand & { bound: number }>();
  const keyOf = (c: Cand) => c.changes.map((x) => JSON.stringify(x)).join('|');
  const byGoal = new Map<string, Set<string>>();

  for (let i = 0; i < maxSteps; i++) {
    const goalF = e.findings.filter((f) => isGoalF(f) && !skipped.has(findingKey(f)));
    const goalC = b.chains.filter((c) => isGoalC(c) && !skipped.has(c.id));
    if (!goalF.length && !goalC.length) break;

    // Candidates are generated once per goal (the worst few open ones) and kept in the pool.
    // Those for the single worst goal are always re-measured; the rest use their bound.
    const forced = new Set<string>();
    const add = (c: Cand, goal: string) => {
      const k = keyOf(c);
      if (!pool.has(k)) {
        stats.candidates += 1;
        pool.set(k, { ...c, bound: Infinity });
      }
      (byGoal.get(goal) ?? byGoal.set(goal, new Set()).get(goal)!).add(k);
    };
    for (const f of goalF.slice(0, 3)) {
      const g = `f:${findingKey(f)}`;
      if (byGoal.has(g)) continue;
      byGoal.set(g, new Set());
      for (const x of findFixes(m, f).filter((x) => x.verified && !x.opened.length).slice(0, 3)) add(x, g);
    }
    const edgeOf = new Map(b.edges.map((x) => [`${x.from}>${x.to}`, x]));
    for (const c0 of goalC.slice(0, 2)) {
      const g = `c:${c0.id}`;
      if (byGoal.has(g)) continue;
      byGoal.set(g, new Set());
      // Cutting the chain where it starts: the internet exposure of its entry points.
      // One change there can break every chain from that entry at once.
      const entryKeys = new Set(c0.entries.flatMap((x) => x.findingKeys));
      for (const f of e.findings.filter((x) => entryKeys.has(findingKey(x))).slice(0, 2)) {
        for (const x of findFixes(m, f).filter((x) => x.verified && !x.opened.length).slice(0, 2)) add(x, g);
      }
      for (const route of [c0.steps, ...c0.altRoutes]) {
        for (let k = 1; k < route.length; k++) {
          const svc = edgeOf.get(`${route[k - 1]!.eniId}>${route[k]!.eniId}`)?.services.find((s) => serviceLabel(s) === route[k]!.service);
          for (const id of svc?.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? []) {
            const r = findRule(m, id);
            if (r) add({ title: `Remove ${id}`, rationale: `${id} (${ruleText(r)}) is a step on ${c0.steps.map((s) => s.name.replace(/ \(.*\)$/, '')).join(' → ')}.`, changes: [{ kind: 'revoke-sg-rule', ruleId: id }] }, g);
          }
        }
      }
    }
    for (const g of [goalF[0] ? `f:${findingKey(goalF[0])}` : '', goalC[0] ? `c:${goalC[0].id}` : '']) for (const k of byGoal.get(g) ?? []) forced.add(k);

    const w0 = weight(e, b);
    let best: { key: string; c: Cand; ev: Eval; gain: number } | undefined;
    for (const [key, c] of [...pool].sort((x, y) => y[1].bound - x[1].bound)) {
      if (best && c.bound <= best.gain && !forced.has(key)) continue;
      const ev = evaluate(m, e, b, c.changes);
      if (!ev || ev.diff.opened || ev.diff.chainsOpened.length) {
        pool.delete(key);
        continue;
      }
      // Breaking traffic someone probably wants costs more than leaving one risk open:
      // a step with collateral only wins if nothing cleaner closes as much.
      const gain = w0 - weight(ev.e, ev.b) - 15 * collateralOf(ev.diff).length - c.changes.length;
      c.bound = gain;
      if (gain > 0 && (!best || gain > best.gain)) best = { key, c, ev, gain };
    }
    if (!best) {
      // Nothing closes the worst goal on its own: leave it to a person.
      const f0 = goalF[0];
      const c0 = goalC[0];
      if (f0) {
        skipped.add(findingKey(f0));
        unresolved.push(`${f0.resourceName}: ${serviceLabel(f0)} from ${f0.sources.join(', ')}`);
      } else if (c0) {
        skipped.add(c0.id);
        unresolved.push(`attack chain ${c0.steps.map((s) => s.name).join(' → ')}`);
      }
      continue;
    }
    chosen.push(best.c);
    pool.delete(best.key);
    m = best.ev.m;
    e = best.ev.e;
    b = best.ev.b;
  }

  // Pruning: drop any step the rest of the plan already covers.
  const finalWeight = weight(e, b);
  const replay = (list: Cand[]) => {
    let mm = model;
    for (const c of list) mm = applyChanges(mm, c.changes);
    const ee = analyzeExposure(mm);
    stats.evaluations += 1;
    return { e: ee, b: analyzeBlastRadius(mm, ee) };
  };
  let plan = chosen;
  if (plan.length > 1) {
    for (let i = plan.length - 1; i >= 0; i--) {
      const trial = plan.filter((_, j) => j !== i);
      let r: { e: ExposureReport; b: BlastReport };
      try {
        r = replay(trial);
      } catch {
        continue;
      }
      if (weight(r.e, r.b) <= finalWeight) {
        plan = trial;
        stats.pruned += 1;
      }
    }
  }

  // Describe the final steps against the model as it is when each one runs.
  const steps: PlanStep[] = [];
  let mm = model;
  let ee = exposure;
  let bb = blast;
  for (const c of plan) {
    const ev = evaluate(mm, ee, bb, c.changes);
    if (!ev) break;
    const lost = ev.diff.deltas.filter((d) => d.status === 'closed' || d.status === 'narrowed');
    steps.push({
      title: c.title,
      rationale: c.rationale,
      changes: c.changes,
      cli: c.changes.flatMap((x) => cliFor(mm, x)),
      closes: lost.filter((d) => compareSeverity(d.severity, 'high') <= 0),
      chainsCut: ev.diff.chainsClosed.filter(isGoalC),
      collateral: lost.filter((d) => compareSeverity(d.severity, 'high') > 0),
    });
    mm = ev.m;
    ee = ev.e;
    bb = ev.b;
  }
  return {
    steps,
    before: { exposures: exposure.findings.filter(isGoalF).length, chains: blast.chains.filter(isGoalC).length },
    after: { exposures: ee.findings.filter(isGoalF).length, chains: bb.chains.filter(isGoalC).length },
    unresolved,
    stats,
  };
}
