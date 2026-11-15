/**
 * Rule cleanup: redundancy that pairwise checks miss, the smallest equivalent
 * rule set for each security group, and rule quotas.
 *
 * Everything here is decided on cells. The address space is cut at every CIDR
 * boundary of every rule involved, the port space at every port boundary, and
 * one packet per cell is put through the same security group and network ACL
 * evaluators the path analysis uses. Within a cell every rule either matches
 * every packet or none, so two rule sets that agree on every cell agree on
 * every packet.
 *
 *  - A rule is redundant when the other rules allow every cell it allows,
 *    even if no single one of them covers it (tcp/0-1000 and tcp/1001-2000
 *    together cover tcp/500-1500).
 *  - A rule is redundant on every interface that uses its group when another
 *    group attached to all of them allows everything it does.
 *  - A network ACL entry can never match when earlier entries together cover
 *    it.
 *  - A group's rules are compacted by merging port ranges and CIDRs with the
 *    same source, dropping what is covered; the result is checked cell by cell
 *    against the original before it is offered.
 */
import { evaluateNacl } from './nacl.js';
import { evaluateSg } from './sg.js';
import type { SgPeer } from './sg.js';
import { RangeSet } from './ipv4.js';
import { hasPorts, protocolName } from './packet.js';
import { cliFor, ruleText } from './whatif.js';
import type { HygieneFinding } from './hygiene.js';
import type { Change } from './whatif.js';
import { PROTO_ALL, PROTO_ICMP } from './types.js';
import type { Nacl, NaclEntry, NetworkModel, Packet, PrefixList, ProtocolNumber, SecurityGroup, SgRule } from './types.js';

/** AWS defaults: https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html */
export const QUOTAS = { sgRulesPerDirection: 60, naclRulesPerDirection: 20, groupsPerInterface: 5 } as const;

// ------------------------------------------------------------------ cells

const addrCuts = (cuts: Set<number>, start: number, end: number) => {
  cuts.add(start);
  if (end < 0xffffffff) cuts.add(end + 1);
};

function sources(r: { cidr?: { start: number; end: number }; prefixListId?: string }, pls: Map<string, PrefixList>) {
  if (r.cidr) return [r.cidr];
  if (r.prefixListId) return pls.get(r.prefixListId)?.entries ?? [];
  return [];
}

/** Representative packets: every protocol, port cell and ICMP type/code that any rule distinguishes. */
function packets(rules: { protocol: ProtocolNumber; fromPort?: number; toPort?: number; portRange?: { from: number; to: number }; icmp?: { type: number; code: number } }[]): Packet[] {
  const protos = new Set<ProtocolNumber>(['6', '17', '1']);
  for (const r of rules) if (r.protocol !== PROTO_ALL) protos.add(r.protocol);
  const out: Packet[] = [];
  for (const p of protos) {
    if (p === PROTO_ICMP) {
      const types = new Set<string>(['0:0', '8:0', '3:4', '250:7']);
      for (const r of rules) {
        if (r.protocol !== PROTO_ICMP) continue;
        const t = r.icmp?.type ?? r.fromPort ?? -1;
        const c = r.icmp?.code ?? r.toPort ?? -1;
        if (t >= 0) types.add(`${t}:${c >= 0 ? c : 0}`), types.add(`${t}:${c >= 0 ? (c + 1) % 256 : 1}`);
      }
      for (const tc of types) {
        const [t, c] = tc.split(':').map(Number);
        out.push({ protocol: p, icmpType: t!, icmpCode: c! });
      }
      continue;
    }
    if (!hasPorts(p)) {
      out.push({ protocol: p });
      continue;
    }
    const cuts = new Set([0]);
    for (const r of rules) {
      if (r.protocol !== p) continue;
      const from = r.portRange?.from ?? r.fromPort;
      const to = r.portRange?.to ?? r.toPort ?? from;
      if (from === undefined || from < 0) continue;
      cuts.add(from);
      if (to! < 65535) cuts.add(to! + 1);
    }
    for (const c of cuts) out.push({ protocol: p, port: c });
  }
  return out;
}

/** Representative peers: one per address cell, plus one per referenced group, outside every CIDR. */
function peers(rules: SgRule[], pls: Map<string, PrefixList>): SgPeer[] {
  const cuts = new Set([0]);
  for (const r of rules) for (const c of sources(r, pls)) addrCuts(cuts, c.start, c.end);
  const out: SgPeer[] = [...cuts].map((ip) => ({ ip, relation: { kind: 'same-vpc' as const } }));
  const covered = RangeSet.of(rules.flatMap((r) => sources(r, pls)));
  const outside = [...cuts].find((ip) => !covered.containsIp(ip));
  const refs = new Set(rules.map((r) => r.referencedGroupId).filter((x): x is string => !!x));
  for (const g of refs) {
    // A member of the group, at an address no CIDR rule matches (when there is one),
    // and one at every address cell, since a peer can be both.
    if (outside !== undefined) out.push({ ip: outside, groupIds: [g], relation: { kind: 'same-vpc' } });
    else for (const ip of cuts) out.push({ ip, groupIds: [g], relation: { kind: 'same-vpc' } });
  }
  return out;
}

const asGroup = (id: string, rules: SgRule[]): SecurityGroup => ({ id, name: id, vpcId: '', ingress: rules, egress: rules });

/** Rule sets `a` and `b` (one direction) allow exactly the same IPv4 traffic; IPv6 rules are compared as text. */
export function sameRules(a: SgRule[], b: SgRule[], pls: Map<string, PrefixList>): boolean {
  const v6 = (list: SgRule[]) => list.filter((r) => r.ipv6CidrText).map((r) => `${r.protocol}|${r.fromPort}|${r.toPort}|${r.ipv6CidrText}`).sort().join(',');
  if (v6(a) !== v6(b)) return false;
  const all = [...a, ...b];
  const ga = [asGroup('a', a)];
  const gb = [asGroup('b', b)];
  for (const peer of peers(all, pls)) for (const pkt of packets(all)) if (evaluateSg(ga, 'ingress', peer, pkt, pls).allowed !== evaluateSg(gb, 'ingress', peer, pkt, pls).allowed) return false;
  return true;
}

/** `rule` allows nothing the `others` do not. */
function coveredBy(rule: SgRule, others: SgRule[], pls: Map<string, PrefixList>): boolean {
  if (rule.ipv6CidrText) return false;
  if (rule.prefixListId && !pls.get(rule.prefixListId)?.entriesKnown) return false;
  const one = [asGroup('r', [rule])];
  const rest = [asGroup('o', others)];
  const all = [rule, ...others];
  const relevant = (pkt: Packet) => rule.protocol === PROTO_ALL || rule.protocol === pkt.protocol;
  for (const peer of peers(all, pls)) {
    for (const pkt of packets(all)) {
      if (!relevant(pkt)) continue;
      if (evaluateSg(one, 'ingress', peer, pkt, pls).allowed && !evaluateSg(rest, 'ingress', peer, pkt, pls).allowed) return false;
    }
  }
  return true;
}

// ------------------------------------------------------------------ findings

export interface RedundantRule {
  ruleId: string;
  groupId: string;
  text: string;
  /** "group": the other rules in its group cover it together; "attached": groups attached alongside cover it everywhere it is used. */
  scope: 'group' | 'attached';
  /** Rules that cover it. */
  coveredBy: string[];
}

export interface ShadowedEntry {
  naclId: string;
  egress: boolean;
  ruleNumber: number;
  action: 'allow' | 'deny';
  /** Earlier entries that together decide everything it would. */
  by: number[];
  /** True when the earlier entries give the same answer everywhere, so removing it changes nothing. */
  harmless: boolean;
}

export interface Compaction {
  groupId: string;
  groupName: string;
  egress: boolean;
  before: number;
  after: number;
  changes: Change[];
  /** The new rules, as text. */
  rules: string[];
  /** Checked cell by cell against the original. */
  equivalent: boolean;
  /** Descriptions on the original rules that the merged rules do not carry. */
  droppedDescriptions: number;
}

export interface QuotaWarning {
  resourceId: string;
  what: string;
  used: number;
  limit: number;
}

export interface CleanupReport {
  redundant: RedundantRule[];
  shadowed: ShadowedEntry[];
  compactions: Compaction[];
  quotas: QuotaWarning[];
}

const pairCovers = (b: SgRule, a: SgRule) => {
  // The pairwise case is already a hygiene finding; skip it here.
  if (b.protocol !== PROTO_ALL && b.protocol !== a.protocol) return false;
  const pa = !hasPorts(a.protocol) || a.fromPort === undefined || a.fromPort < 0 ? { from: 0, to: 65535 } : { from: a.fromPort, to: a.toPort ?? a.fromPort };
  const pb = b.protocol === PROTO_ALL || !hasPorts(b.protocol) || b.fromPort === undefined || b.fromPort < 0 ? { from: 0, to: 65535 } : { from: b.fromPort, to: b.toPort ?? b.fromPort };
  if (pb.from > pa.from || pb.to < pa.to) return false;
  if (a.cidr && b.cidr) return b.cidr.start <= a.cidr.start && b.cidr.end >= a.cidr.end;
  if (a.referencedGroupId) return b.referencedGroupId === a.referencedGroupId;
  if (a.prefixListId) return b.prefixListId === a.prefixListId;
  return false;
};

function redundancies(model: NetworkModel): RedundantRule[] {
  const out: RedundantRule[] = [];
  const pls = model.prefixLists;
  const flagged = new Set<string>();
  for (const g of model.securityGroups.values()) {
    for (const dir of ['ingress', 'egress'] as const) {
      const rules = g[dir];
      for (const r of rules) {
        const others = rules.filter((x) => x.id !== r.id && !flagged.has(x.id));
        if (others.some((b) => pairCovers(b, r))) continue;
        if (others.length >= 2 && coveredBy(r, others, pls)) {
          flagged.add(r.id);
          out.push({ ruleId: r.id, groupId: g.id, text: ruleText(r), scope: 'group', coveredBy: others.filter((o) => o.protocol === PROTO_ALL || o.protocol === r.protocol).map((o) => o.id) });
        }
      }
    }
  }
  // Across groups: every place the group is attached also has groups that cover the rule.
  const attachments: string[][] = [...model.enis.values()].map((e) => e.groupIds).concat([...model.loadBalancers.values()].map((lb) => lb.securityGroupIds));
  for (const g of model.securityGroups.values()) {
    const where = attachments.filter((list) => list.includes(g.id));
    if (!where.length) continue;
    for (const dir of ['ingress', 'egress'] as const) {
      for (const r of g[dir]) {
        if (flagged.has(r.id)) continue;
        const by = new Set<string>();
        const everywhere = where.every((list) => {
          const others = list.filter((id) => id !== g.id).flatMap((id) => model.securityGroups.get(id)?.[dir] ?? []);
          if (!others.length || !coveredBy(r, others, pls)) return false;
          others.filter((o) => o.protocol === PROTO_ALL || o.protocol === r.protocol).forEach((o) => by.add(o.id));
          return true;
        });
        if (everywhere) {
          flagged.add(r.id);
          out.push({ ruleId: r.id, groupId: g.id, text: ruleText(r), scope: 'attached', coveredBy: [...by] });
        }
      }
    }
  }
  return out;
}

function shadowedEntries(model: NetworkModel): ShadowedEntry[] {
  const out: ShadowedEntry[] = [];
  for (const n of model.nacls.values()) {
    for (const egress of [false, true]) {
      const entries = n.entries.filter((e) => e.egress === egress && e.cidr).sort((a, b) => a.ruleNumber - b.ruleNumber);
      for (const [i, a] of entries.entries()) {
        if (a.ruleNumber === 32767 || i === 0) continue;
        const earlier = entries.slice(0, i);
        // Pairwise shadowing is already a hygiene finding.
        if (earlier.some((b) => pairShadows(b, a))) continue;
        const res = shadowedBy(n, a, earlier);
        if (res) out.push({ naclId: n.id, egress, ruleNumber: a.ruleNumber, action: a.action, by: res.by, harmless: res.same });
      }
    }
  }
  return out;
}

function pairShadows(b: NaclEntry, a: NaclEntry): boolean {
  if (!a.cidr || !b.cidr) return false;
  if (b.protocol !== PROTO_ALL && b.protocol !== a.protocol) return false;
  if (b.protocol !== PROTO_ALL && hasPorts(b.protocol)) {
    const pa = a.portRange ?? { from: 0, to: 65535 };
    const pb = b.portRange ?? { from: 0, to: 65535 };
    if (pb.from > pa.from || pb.to < pa.to) return false;
  }
  return b.cidr.start <= a.cidr.start && b.cidr.end >= a.cidr.end;
}

/** Every packet entry `a` matches is decided by an earlier entry. */
function shadowedBy(n: Nacl, a: NaclEntry, earlier: NaclEntry[]): { by: number[]; same: boolean } | undefined {
  const cuts = new Set([0]);
  for (const e of [a, ...earlier]) if (e.cidr) addrCuts(cuts, e.cidr.start, e.cidr.end);
  const only = (list: NaclEntry[]): Nacl => ({ ...n, entries: list });
  const just = only([a]);
  const before = only(earlier);
  const by = new Set<number>();
  let same = true;
  for (const ip of cuts) {
    if (!a.cidr || ip < a.cidr.start || ip > a.cidr.end) continue;
    for (const pkt of packets([a, ...earlier])) {
      if (a.protocol !== PROTO_ALL && a.protocol !== pkt.protocol) continue;
      if (evaluateNacl(just, a.egress, ip, pkt).entry.ruleNumber !== a.ruleNumber) continue;
      const first = evaluateNacl(before, a.egress, ip, pkt);
      if (first.entry.ruleNumber === 32767) return undefined;
      by.add(first.entry.ruleNumber);
      if (first.action !== a.action) same = false;
    }
  }
  return by.size ? { by: [...by].sort((x, y) => x - y), same } : undefined;
}

/**
 * The smallest equivalent rule set for one direction of a group: per source
 * (a CIDR block set, a referenced group or a prefix list), merge the port
 * ranges; per port range, merge the CIDRs into the fewest blocks. ICMP and
 * other protocols without ports, and IPv6 rules, are kept as they are.
 */
function compact(g: SecurityGroup, egress: boolean, pls: Map<string, PrefixList>): Compaction | undefined {
  const rules = egress ? g.egress : g.ingress;
  if (rules.length < 2) return undefined;
  const keep = rules.filter((r) => r.ipv6CidrText || (r.protocol !== PROTO_ALL && !hasPorts(r.protocol)));
  const work = rules.filter((r) => !keep.includes(r));
  type Out = { protocol: ProtocolNumber; from?: number; to?: number; cidr?: string; ref?: string; pl?: string };
  const out: Out[] = [];
  const merge = (ranges: [number, number][]): [number, number][] => {
    const s = [...ranges].sort((a, b) => a[0] - b[0]);
    const res: [number, number][] = [];
    for (const r of s) {
      const last = res[res.length - 1];
      if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
      else res.push([...r]);
    }
    return res;
  };
  // All-protocol rules first: they cover every protocol for their source.
  const allProto = work.filter((r) => r.protocol === PROTO_ALL);
  const allAddr = RangeSet.of(allProto.flatMap((r) => (r.cidr ? [r.cidr] : [])));
  for (const c of allAddr.toCidrs()) out.push({ protocol: PROTO_ALL, cidr: c });
  const allRefs = new Set(allProto.map((r) => r.referencedGroupId).filter((x): x is string => !!x));
  const allPls = new Set(allProto.map((r) => r.prefixListId).filter((x): x is string => !!x));
  allRefs.forEach((ref) => out.push({ protocol: PROTO_ALL, ref }));
  allPls.forEach((pl) => out.push({ protocol: PROTO_ALL, pl }));

  const portOf = (r: SgRule): [number, number] => (r.fromPort === undefined || r.fromPort < 0 ? [0, 65535] : [r.fromPort, r.toPort ?? r.fromPort]);
  for (const p of new Set(work.filter((r) => r.protocol !== PROTO_ALL).map((r) => r.protocol))) {
    const list = work.filter((r) => r.protocol === p);
    // Referenced groups and prefix lists: merge port ranges per source.
    for (const ref of new Set(list.map((r) => r.referencedGroupId).filter((x): x is string => !!x && !allRefs.has(x)))) {
      for (const [from, to] of merge(list.filter((r) => r.referencedGroupId === ref).map(portOf))) out.push({ protocol: p, from, to, ref });
    }
    for (const pl of new Set(list.map((r) => r.prefixListId).filter((x): x is string => !!x && !allPls.has(x)))) {
      for (const [from, to] of merge(list.filter((r) => r.prefixListId === pl).map(portOf))) out.push({ protocol: p, from, to, pl });
    }
    // CIDRs: cut ports at every boundary, take the address set per cell, merge equal neighbours.
    const cidrRules = list.filter((r) => r.cidr);
    const cuts = new Set<number>([0, 65536]);
    for (const r of cidrRules) {
      const [f, t] = portOf(r);
      cuts.add(f);
      cuts.add(t + 1);
    }
    const sorted = [...cuts].sort((a, b) => a - b);
    let cur: { from: number; to: number; set: RangeSet } | undefined;
    const flush = () => {
      if (cur && !cur.set.isEmpty()) for (const c of cur.set.toCidrs()) out.push({ protocol: p, from: cur.from, to: cur.to, cidr: c });
    };
    for (let i = 0; i + 1 < sorted.length; i++) {
      const from = sorted[i]!;
      const to = sorted[i + 1]! - 1;
      const set = RangeSet.of(cidrRules.filter((r) => portOf(r)[0] <= from && portOf(r)[1] >= to).map((r) => r.cidr!)).subtract(allAddr);
      if (cur && cur.set.equals(set) && cur.to + 1 === from) cur.to = to;
      else {
        flush();
        cur = { from, to, set };
      }
    }
    flush();
  }
  const after = out.length + keep.length;
  if (after >= rules.length) return undefined;
  const changes: Change[] = [
    ...work.map((r): Change => ({ kind: 'revoke-sg-rule', ruleId: r.id })),
    ...out.map(
      (o): Change => ({
        kind: 'add-sg-rule',
        groupId: g.id,
        egress,
        protocol: protocolName(o.protocol),
        ...(o.from !== undefined && !(o.from === 0 && o.to === 65535 && o.protocol === PROTO_ALL) ? { fromPort: o.from, toPort: o.to } : {}),
        ...(o.cidr ? { cidr: o.cidr } : {}),
        ...(o.ref ? { referencedGroupId: o.ref } : {}),
        ...(o.pl ? { prefixListId: o.pl } : {}),
      }),
    ),
  ];
  // Check: the new rules allow exactly what the old ones did.
  const synth: SgRule[] = [
    ...keep,
    ...out.map((o, i) => ({
      id: `new-${i}`,
      groupId: g.id,
      egress,
      protocol: o.protocol,
      ...(o.from !== undefined ? { fromPort: o.from, toPort: o.to } : {}),
      ...(o.cidr ? { cidr: cidrOf(o.cidr) } : {}),
      ...(o.ref ? { referencedGroupId: o.ref } : {}),
      ...(o.pl ? { prefixListId: o.pl } : {}),
    })),
  ];
  const equivalent = sameRules(rules, synth, pls);
  const label = (o: Out) => `${o.protocol === PROTO_ALL ? 'all traffic' : `${protocolName(o.protocol)}/${o.from === o.to ? o.from : `${o.from}-${o.to}`}`} ${egress ? 'to' : 'from'} ${o.cidr ?? o.ref ?? o.pl}`;
  return {
    groupId: g.id,
    groupName: g.name,
    egress,
    before: rules.length,
    after,
    changes,
    rules: [...keep.map(ruleText), ...out.map(label)],
    equivalent,
    droppedDescriptions: work.filter((r) => r.description).length,
  };
}

function cidrOf(text: string) {
  const [ip, len] = text.split('/') as [string, string];
  const parts = ip.split('.').map(Number);
  const start = ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
  const size = 2 ** (32 - Number(len));
  return { text, start, end: start + size - 1, prefixLength: Number(len) };
}

export function analyzeCleanup(model: NetworkModel): CleanupReport {
  const compactions: Compaction[] = [];
  for (const g of model.securityGroups.values()) {
    for (const egress of [false, true]) {
      const c = compact(g, egress, model.prefixLists);
      if (c?.equivalent) compactions.push(c);
    }
  }
  const quotas: QuotaWarning[] = [];
  const near = (used: number, limit: number) => used >= Math.ceil(limit * 0.8);
  for (const g of model.securityGroups.values()) {
    for (const [dir, list] of [['inbound', g.ingress], ['outbound', g.egress]] as const) {
      if (near(list.length, QUOTAS.sgRulesPerDirection)) quotas.push({ resourceId: g.id, what: `${dir} rules in ${g.id} (${g.name})`, used: list.length, limit: QUOTAS.sgRulesPerDirection });
    }
  }
  for (const n of model.nacls.values()) {
    for (const egress of [false, true]) {
      const used = n.entries.filter((e) => e.egress === egress && e.ruleNumber !== 32767).length;
      if (near(used, QUOTAS.naclRulesPerDirection)) quotas.push({ resourceId: n.id, what: `${egress ? 'outbound' : 'inbound'} rules in ${n.id}`, used, limit: QUOTAS.naclRulesPerDirection });
    }
  }
  for (const e of model.enis.values()) {
    if (e.groupIds.length >= QUOTAS.groupsPerInterface) quotas.push({ resourceId: e.id, what: `security groups on ${e.id}`, used: e.groupIds.length, limit: QUOTAS.groupsPerInterface });
  }
  return { redundant: redundancies(model), shadowed: shadowedEntries(model), compactions: compactions.sort((a, b) => b.before - b.after - (a.before - a.after)), quotas };
}

/** The cleanup report as hygiene findings, for one list. */
export function cleanupFindings(model: NetworkModel, c: CleanupReport): HygieneFinding[] {
  const out: HygieneFinding[] = [];
  for (const r of c.redundant) {
    out.push({
      code: r.scope === 'group' ? 'redundant-together' : 'redundant-attached',
      severity: r.scope === 'group' ? 'low' : 'info',
      resourceId: r.groupId,
      ruleId: r.ruleId,
      title: `${r.ruleId} adds nothing to ${r.groupId}`,
      detail:
        r.scope === 'group'
          ? `${r.text}: the group's other rules allow all of it together (${r.coveredBy.join(', ')}), though no single one does. Removing it changes nothing.`
          : `${r.text}: every interface that uses ${r.groupId} also has a group that allows all of it (${r.coveredBy.join(', ')}). It only matters if that group is detached.`,
      fix: [{ kind: 'revoke-sg-rule', ruleId: r.ruleId }],
    });
  }
  for (const x of c.shadowed) {
    out.push({
      code: 'shadowed-together',
      severity: x.harmless ? 'low' : 'medium',
      resourceId: x.naclId,
      ruleId: `${x.naclId}#${x.egress ? 'egress' : 'ingress'}#${x.ruleNumber}`,
      title: `${x.naclId} ${x.egress ? 'outbound' : 'inbound'} rule ${x.ruleNumber} can never match`,
      detail: `Rules ${x.by.join(' and ')} come first and together decide everything it would.${x.harmless ? ' Removing it changes nothing.' : ` It ${x.action === 'allow' ? 'allows' : 'denies'} traffic they ${x.action === 'allow' ? 'deny' : 'allow'}, so it does not do what it says.`}`,
      ...(x.harmless ? { fix: [{ kind: 'remove-nacl-entry', naclId: x.naclId, egress: x.egress, ruleNumber: x.ruleNumber } as Change] } : {}),
    });
  }
  for (const x of c.compactions) {
    out.push({
      code: 'compactable-group',
      severity: 'info',
      resourceId: x.groupId,
      title: `${x.groupId} (${x.groupName}): ${x.before} ${x.egress ? 'outbound' : 'inbound'} rules can be ${x.after}`,
      detail: `Exactly the same traffic, checked cell by cell: ${x.rules.join('; ')}.${x.droppedDescriptions ? ` ${x.droppedDescriptions} rule description(s) would not carry over.` : ''}`,
      fix: x.changes,
      cli: x.changes.flatMap((ch) => cliFor(model, ch)),
    });
  }
  for (const q of c.quotas) {
    out.push({ code: 'near-quota', severity: q.used >= q.limit ? 'medium' : 'low', resourceId: q.resourceId, title: `${q.used} of ${q.limit} ${q.what}`, detail: 'The default AWS quota. New rules are refused at the limit: compact the rules or request an increase.' });
  }
  return out;
}
