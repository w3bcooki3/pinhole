/**
 * Joins snapshots that are connected to each other, so attack chains can be
 * followed across accounts and Regions.
 *
 * One snapshot covers one account in one Region. When a VPC peering connection
 * or a transit gateway links it to a VPC in another snapshot, analysing each
 * snapshot alone stops at the link ("peer VPC is not in this snapshot"). Here,
 * snapshots that share a peering connection or a transit gateway are grouped
 * (union-find over the shared IDs) and each group is merged into one model.
 * The same exact path analysis then runs on the merged model: routes on both
 * sides, NACLs on both sides, security groups on both sides, and the rules on
 * referencing groups across a peering connection or transit gateway.
 *
 * AWS resource IDs are unique, so a merged model is only built when the
 * snapshots in a group share nothing but the link itself. If they share other
 * IDs (two copies of one account, or hand-made test data), the group is not
 * joined and the reason is returned: a guess would be worse than no answer.
 *
 * Peering: https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html
 * Shared transit gateways: https://docs.aws.amazon.com/vpc/latest/tgw/tgw-transit-gateways.html
 */
import { analyzeExposure } from './exposure.js';
import type { ExposureReport } from './exposure.js';
import { analyzeBlastRadius } from './blast.js';
import type { AttackChain, BlastOptions, BlastReport, ChainStep } from './blast.js';
import type { NetworkModel } from './types.js';

export interface JoinInput {
  /** Stable key for the snapshot, e.g. "111122223333 us-east-1". */
  key: string;
  model: NetworkModel;
}

export interface JoinLink {
  kind: 'peering' | 'transit-gateway';
  id: string;
  keys: string[];
}

export interface JoinedEstate {
  /** The snapshots in this group, in input order. */
  keys: string[];
  model: NetworkModel;
  /** Which snapshot each interface, VPC, subnet and security group came from. */
  owner: Map<string, string>;
  links: JoinLink[];
}

export interface JoinResult {
  estates: JoinedEstate[];
  /** Groups that are linked but could not be merged, and why. */
  skipped: { keys: string[]; reason: string }[];
}

/** IDs that may legitimately appear in more than one snapshot: the links. */
function linkIds(m: NetworkModel): { kind: JoinLink['kind']; id: string }[] {
  const out: { kind: JoinLink['kind']; id: string }[] = [];
  for (const p of m.peerings.values()) {
    // Only a link to a VPC outside this snapshot connects it to another one.
    if (p.status === 'active' && (!m.vpcs.has(p.requesterVpcId) || !m.vpcs.has(p.accepterVpcId))) out.push({ kind: 'peering', id: p.id });
  }
  const tgws = new Set<string>([...m.transitGateways.keys(), ...[...m.tgwAttachments.values()].map((a) => a.tgwId), ...[...m.tgwRouteTables.values()].map((t) => t.tgwId)]);
  for (const id of tgws) out.push({ kind: 'transit-gateway', id });
  return out;
}

type MapKey = Exclude<keyof NetworkModel, 'accountId' | 'region' | 'listeners' | 'warnings'>;
const OWNED: MapKey[] = ['vpcs', 'subnets', 'routeTables', 'nacls', 'securityGroups', 'internetGateways', 'natGateways', 'enis', 'instances', 'loadBalancers', 'targetGroups', 'vpcEndpoints', 'firewalls'];
/** Shared between snapshots by design; the most complete copy wins. */
const SHARED: MapKey[] = ['peerings', 'transitGateways', 'tgwAttachments', 'tgwRouteTables', 'prefixLists', 'firewallPolicies', 'firewallRuleGroups'];

function emptyModel(): NetworkModel {
  return {
    vpcs: new Map(), subnets: new Map(), routeTables: new Map(), nacls: new Map(), securityGroups: new Map(), prefixLists: new Map(),
    internetGateways: new Map(), natGateways: new Map(), peerings: new Map(), transitGateways: new Map(), tgwAttachments: new Map(),
    tgwRouteTables: new Map(), enis: new Map(), instances: new Map(), loadBalancers: new Map(), listeners: [], targetGroups: new Map(),
    vpcEndpoints: new Map(), firewalls: new Map(), firewallPolicies: new Map(), firewallRuleGroups: new Map(), warnings: [],
  };
}

/** For a shared object seen in two snapshots, keep the copy that says more. */
function better(a: unknown, b: unknown): unknown {
  const routesKnown = (x: unknown) => (x as { routesKnown?: boolean }).routesKnown === true;
  if (routesKnown(b) && !routesKnown(a)) return b;
  const size = (x: unknown) => JSON.stringify(x, (_k, v) => (v instanceof Map ? [...v] : typeof v === 'bigint' ? String(v) : v)).length;
  return size(b) > size(a) ? b : a;
}

export function joinSnapshots(inputs: JoinInput[]): JoinResult {
  // Union-find over snapshots, joined through shared link IDs.
  const parent = inputs.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i]!)));
  const byLink = new Map<string, { kind: JoinLink['kind']; idx: number[] }>();
  inputs.forEach((inp, i) => {
    for (const l of linkIds(inp.model)) {
      const k = `${l.kind}:${l.id}`;
      const cur = byLink.get(k) ?? byLink.set(k, { kind: l.kind, idx: [] }).get(k)!;
      if (!cur.idx.includes(i)) cur.idx.push(i);
    }
  });
  for (const { idx } of byLink.values()) for (const i of idx.slice(1)) parent[find(i)] = find(idx[0]!);

  const groups = new Map<number, number[]>();
  inputs.forEach((_, i) => (groups.get(find(i)) ?? groups.set(find(i), []).get(find(i))!).push(i));

  const result: JoinResult = { estates: [], skipped: [] };
  for (const idx of groups.values()) {
    if (idx.length < 2) continue;
    const keys = idx.map((i) => inputs[i]!.key);
    const model = emptyModel();
    const owner = new Map<string, string>();
    const clashes: string[] = [];
    for (const i of idx) {
      const { key, model: m } = inputs[i]!;
      for (const k of OWNED) {
        const into = model[k] as Map<string, unknown>;
        for (const [id, v] of m[k] as Map<string, unknown>) {
          if (into.has(id)) clashes.push(id);
          into.set(id, v);
          owner.set(id, key);
        }
      }
      for (const k of SHARED) {
        const into = model[k] as Map<string, unknown>;
        for (const [id, v] of m[k] as Map<string, unknown>) into.set(id, into.has(id) ? better(into.get(id), v) : v);
      }
      model.listeners.push(...m.listeners);
      // Warnings about the other side of a link are answered by joining.
      model.warnings.push(...m.warnings.map((w) => ({ ...w, message: `${key}: ${w.message}` })));
    }
    if (clashes.length) {
      const shown = [...new Set(clashes)].slice(0, 3);
      result.skipped.push({ keys, reason: `These snapshots are linked but also share resource IDs (${shown.join(', ')}${clashes.length > shown.length ? ', ...' : ''}), which real AWS accounts never do. They are analysed separately.` });
      continue;
    }
    // AWS CLI commands need a Region; set it when every snapshot in the group shares one.
    const regions = new Set(idx.map((i) => inputs[i]!.model.region));
    if (regions.size === 1 && [...regions][0]) model.region = [...regions][0]!;
    const links: JoinLink[] = [];
    for (const [k, { kind, idx: li }] of byLink) {
      const inGroup = li.filter((i) => idx.includes(i));
      if (inGroup.length > 1) links.push({ kind, id: k.slice(k.indexOf(':') + 1), keys: inGroup.map((i) => inputs[i]!.key) });
    }
    result.estates.push({ keys, model, owner, links });
  }
  return result;
}

// ------------------------------------------------------------------ chains across snapshots

export interface CrossChain extends AttackChain {
  /** The snapshot each step's interface belongs to, in step order. */
  scopes: string[];
}

export interface CrossReport {
  estate: JoinedEstate;
  exposure: ExposureReport;
  blast: BlastReport;
  /** Chains whose route leaves the snapshot it started in. */
  chains: CrossChain[];
}

/** The snapshot a change runs in: the owner of the rule, group, ACL or interface it touches. */
export function changeScope(estate: JoinedEstate, change: { kind: string } & Record<string, unknown>): string | undefined {
  const own = (id: unknown) => (typeof id === 'string' ? estate.owner.get(id) : undefined);
  if (typeof change.ruleId === 'string') {
    for (const g of estate.model.securityGroups.values()) if (g.ingress.some((r) => r.id === change.ruleId) || g.egress.some((r) => r.id === change.ruleId)) return own(g.id);
  }
  return own(change.groupId) ?? own(change.naclId) ?? own(change.eniId);
}

const crosses = (owner: Map<string, string>, steps: ChainStep[]) => new Set(steps.map((s) => owner.get(s.eniId))).size > 1;

/**
 * Attack chains in a joined estate that cross from one snapshot into another.
 * Chains that stay inside one snapshot are already reported by that
 * snapshot's own analysis, so only crossing routes are kept; when a chain has
 * both, the crossing routes are the ones shown.
 */
export function crossChains(estate: JoinedEstate, opts: BlastOptions = {}): CrossReport {
  const exposure = analyzeExposure(estate.model);
  const blast = analyzeBlastRadius(estate.model, exposure, opts);
  const chains: CrossChain[] = [];
  for (const c of blast.chains) {
    const routes = [c.steps, ...c.altRoutes].filter((r) => crosses(estate.owner, r));
    if (!routes.length) continue;
    const [main, ...alt] = routes as [ChainStep[], ...ChainStep[][]];
    const entryIds = new Set(routes.map((r) => r[0]!.eniId));
    const entries = c.entries.filter((e) => entryIds.has(e.eniId));
    chains.push({
      ...c,
      steps: main,
      altRoutes: alt,
      routes: routes.length,
      entry: entries.find((e) => e.eniId === main[0]!.eniId) ?? c.entry,
      entries,
      scopes: main.map((s) => estate.owner.get(s.eniId) ?? ''),
    });
  }
  return { estate, exposure, blast, chains };
}
