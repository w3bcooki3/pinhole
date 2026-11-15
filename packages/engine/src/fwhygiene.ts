/**
 * Network Firewall rule hygiene: rules that never decide anything, because
 * rules the engine applies first already decide all of their traffic.
 *
 * Order (https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-rules-engines.html,
 * https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html):
 *  - stateless: groups by priority, rules by priority; pass, drop and forward
 *    all end the evaluation, so a packet is decided by the first rule that
 *    matches;
 *  - stateful, strict order: groups by priority, rules as written; default
 *    action order: every pass rule, then drop, reject and alert. Pass, drop
 *    and reject end the evaluation; alert does not.
 *
 * A rule is covered when every packet it matches is matched by a rule before
 * it that ends the evaluation. That is decided exactly: each rule is a union
 * of boxes over protocol, source, destination, source port, destination port
 * (and direction, for stateful rules), and the covering rules' boxes are cut
 * into cells inside the rule's own box. Rules that also depend on the traffic
 * itself (TCP flags, content, host names, application protocols) can be
 * covered, but never cover others. A covered rule whose coverers decide the
 * same way is redundant; one they decide differently is shadowed, and is
 * likely a mistake.
 */
import { addrSet, flowDirection, portSet, statefulOrder, APP_TCP, APP_UDP } from './firewall.js';
import type { Stateful } from './firewall.js';
import type { HygieneFinding } from './hygiene.js';
import type { Severity } from './risk.js';
import type { Firewall, FirewallPolicy, NetworkModel, PortRange, StatelessRule } from './types.js';

type Range = [number, number];
type Box = Range[];

const ANY_ADDR: Range = [0, 0xffffffff];
const ANY_PORT: Range = [0, 65535];
const ANY_PROTO: Range = [0, 255];
const MAX_BOXES = 4096;

/** Every combination of one range per dimension. */
function product(dims: Range[][]): Box[] | undefined {
  let out: Box[] = [[]];
  for (const d of dims) {
    if (!d.length) return [];
    if (out.length * d.length > MAX_BOXES) return undefined;
    out = out.flatMap((b) => d.map((r) => [...b, r]));
  }
  return out;
}

/**
 * True when the boxes `covers` cover all of `target`; undefined when it is too
 * large to decide. Cuts each dimension at the covers' edges inside the target
 * and keeps, per interval, only the covers that hold it.
 */
function covered(target: Box, covers: Box[]): boolean {
  const live = covers.filter((c) => c.every((r, d) => r[0] <= target[d]![1] && r[1] >= target[d]![0]));
  const walk = (d: number, cs: Box[]): boolean => {
    if (!cs.length) return false;
    if (d === target.length) return true;
    const [lo, hi] = target[d]!;
    const cuts = new Set<number>([lo]);
    for (const c of cs) {
      if (c[d]![0] > lo && c[d]![0] <= hi) cuts.add(c[d]![0]);
      if (c[d]![1] + 1 > lo && c[d]![1] + 1 <= hi) cuts.add(c[d]![1] + 1);
    }
    const sorted = [...cuts].sort((a, b) => a - b);
    for (let i = 0; i < sorted.length; i++) {
      const from = sorted[i]!;
      const sub = cs.filter((c) => c[d]![0] <= from && c[d]![1] >= from);
      if (!walk(d + 1, sub)) return false;
    }
    return true;
  };
  return walk(0, live);
}

interface Item {
  id: string;
  group: string;
  action: string;
  text: string;
  boxes: Box[] | undefined;
  /** Can end the evaluation for every packet it matches. */
  decisive: boolean;
  /** Why it is not evaluated (IPv6, an unknown variable), if so. */
  skip?: string;
}

const ranges = (list: { start: number; end: number }[]): Range[] => list.map((r) => [r.start, r.end]);
const portRanges = (list: PortRange[]): Range[] => list.map((r) => [r.from, r.to]);

function statelessItems(model: NetworkModel, policy: FirewallPolicy): Item[] {
  const out: Item[] = [];
  const refs = [...policy.statelessGroups].sort((a, b) => a.priority - b.priority);
  for (const ref of refs) {
    const g = model.firewallRuleGroups.get(ref.arn);
    if (!g?.known) continue;
    for (const r of [...g.stateless].sort((a, b) => a.priority - b.priority)) {
      const dims: Range[][] = [
        r.protocols.length ? r.protocols.map((p) => [p, p] as Range) : [ANY_PROTO],
        r.sources.length ? ranges(r.sources) : [ANY_ADDR],
        r.destinations.length ? ranges(r.destinations) : [ANY_ADDR],
        r.sourcePorts.length ? portRanges(r.sourcePorts) : [ANY_PORT],
        r.destinationPorts.length ? portRanges(r.destinationPorts) : [ANY_PORT],
      ];
      out.push({ id: `${g.name}#${r.priority}`, group: g.name, action: r.action, text: statelessText(r), boxes: product(dims), decisive: !r.tcpFlags });
    }
  }
  return out;
}

function statelessText(r: StatelessRule): string {
  const list = (xs: { text: string }[]) => (xs.length ? xs.map((x) => x.text).join(',') : 'any');
  const ports = (xs: PortRange[]) => (xs.length ? xs.map((p) => (p.from === p.to ? `${p.from}` : `${p.from}-${p.to}`)).join(',') : 'any');
  const proto = r.protocols.length ? r.protocols.map((p) => (p === 6 ? 'tcp' : p === 17 ? 'udp' : p === 1 ? 'icmp' : String(p))).join(',') : 'any protocol';
  return `${r.action} ${proto} ${list(r.sources)}:${ports(r.sourcePorts)} -> ${list(r.destinations)}:${ports(r.destinationPorts)}${r.tcpFlags ? ' (TCP flags)' : ''}`;
}

function protoRange(p: string): Range[] {
  if (p === 'ip') return [ANY_PROTO];
  if (p === 'tcp' || p === 'tcp-pkt' || p === 'tcp-stream') return [[6, 6]];
  if (p === 'udp') return [[17, 17]];
  if (p === 'icmp') return [[1, 1]];
  return [...(APP_TCP.has(p) ? [[6, 6] as Range] : []), ...(APP_UDP.has(p) ? [[17, 17] as Range] : [])];
}

function statefulItems(list: Stateful[]): Item[] {
  return list.map((s) => {
    const r = s.rule;
    const id = `${s.group.name} ${r.sid ? `sid ${r.sid}` : `rule ${s.group.stateful.indexOf(r) + 1}`}`;
    const action = s.demote && (r.action === 'drop' || r.action === 'reject') ? 'alert' : r.action;
    const base = { id, group: s.group.name, action, text: r.text };
    if ([r.src, r.dst].some((x) => x.includes(':'))) return { ...base, boxes: undefined, decisive: false, skip: 'IPv6 addresses are not evaluated' };
    try {
      const dir = flowDirection(r);
      const dirs: Range[] = [dir === 'to_server' ? [0, 0] : dir === 'to_client' ? [1, 1] : [0, 1]];
      const one = (src: string, sp: string, dst: string, dp: string) => [protoRange(r.protocol), ranges(addrSet(src, s.vars).ranges as { start: number; end: number }[]), ranges(addrSet(dst, s.vars).ranges as { start: number; end: number }[]), portRanges(portSet(sp, s.vars)), portRanges(portSet(dp, s.vars)), dirs];
      const a = product(one(r.src, r.srcPort, r.dst, r.dstPort));
      const b = r.bidirectional ? product(one(r.dst, r.dstPort, r.src, r.srcPort)) : [];
      const boxes = a && b ? [...a, ...b] : undefined;
      return { ...base, boxes, decisive: action !== 'alert' && !r.conditional };
    } catch (e) {
      return { ...base, boxes: undefined, decisive: false, skip: (e as Error).message };
    }
  });
}

/** Covered, redundant and empty rules in one ordered list. */
function check(items: Item[], where: string, kind: 'stateless' | 'stateful', resourceId: string): HygieneFinding[] {
  const out: HygieneFinding[] = [];
  for (const [i, it] of items.entries()) {
    if (!it.boxes) continue;
    if (!it.boxes.length) {
      out.push({ code: 'firewall-rule-matches-nothing', severity: 'info', resourceId, ruleId: it.id, title: `${it.id} matches no traffic`, detail: `${it.id} (${it.text}) in ${where} matches no address or port: one of its fields is empty once variables and negations are resolved. It has no effect.` });
      continue;
    }
    const before = items.slice(0, i).filter((x) => x.decisive && x.boxes?.length);
    const hits = before.filter((x) => x.boxes!.some((b) => it.boxes!.some((t) => t.every((r, d) => r[0] <= b[d]![1] && r[1] >= b[d]![0]))));
    if (!hits.length) continue;
    const all = hits.flatMap((x) => x.boxes!);
    if (!it.boxes.every((t) => covered(t, all))) continue;
    const same = hits.every((x) => x.action === it.action);
    const severity: Severity = same ? 'info' : (it.action === 'drop' || it.action === 'reject') && hits.some((x) => x.action === 'pass') ? 'medium' : 'low';
    const by = hits.map((x) => `${x.id} (${x.action})`).join(', ');
    out.push({
      code: same ? 'firewall-redundant-rule' : 'firewall-shadowed-rule',
      severity,
      resourceId,
      ruleId: it.id,
      title: same ? `${it.id} adds nothing: earlier rules already ${it.action} all of its traffic` : `${it.id} never decides: earlier rules ${hits.some((x) => x.action !== it.action) ? 'decide its traffic differently' : 'decide all of its traffic'}`,
      detail: `${it.id} (${it.text}) in ${where} matches only traffic that ${by} ${hits.length === 1 ? 'matches' : 'match'} first, ${kind === 'stateful' ? 'in the order the stateful engine applies rules' : 'in priority order'}.${same ? ' Removing it changes nothing.' : ` Its ${it.action} never happens: either it is a mistake, or the earlier rule${hits.length === 1 ? ' is' : 's are'} broader than intended.`}`,
    });
  }
  return out;
}

export function firewallHygiene(model: NetworkModel): HygieneFinding[] {
  const out: HygieneFinding[] = [];
  const seen = new Set<string>();
  const add = (fs: HygieneFinding[]) => {
    for (const f of fs) {
      const k = `${f.code}|${f.resourceId}|${f.ruleId}`;
      if (!seen.has(k)) {
        seen.add(k);
        out.push(f);
      }
    }
  };
  const policies = new Map<string, { policy: FirewallPolicy; firewalls: Firewall[] }>();
  for (const fw of model.firewalls.values()) {
    const policy = model.firewallPolicies.get(fw.policyArn);
    if (!policy) continue;
    const e = policies.get(policy.arn) ?? policies.set(policy.arn, { policy, firewalls: [] }).get(policy.arn)!;
    e.firewalls.push(fw);
  }
  for (const { policy, firewalls } of policies.values()) {
    add(check(statelessItems(model, policy), `the stateless rules of policy ${policy.name}`, 'stateless', policy.name));
    // HOME_NET depends on the firewall's VPC, so stateful rules are checked per firewall.
    for (const fw of firewalls) add(check(statefulItems(statefulOrder(model, fw, policy).list), `the stateful rules of policy ${policy.name} (firewall ${fw.name})`, 'stateful', policy.name));
    for (const ref of [...policy.statelessGroups, ...policy.statefulGroups]) {
      const g = model.firewallRuleGroups.get(ref.arn);
      if (g?.known && !g.domainList && !g.stateless.length && !g.stateful.length && !g.unparsed.length) {
        add([{ code: 'firewall-empty-group', severity: 'info', resourceId: policy.name, ruleId: g.name, title: `Rule group ${g.name} has no rules`, detail: `${g.name} is in policy ${policy.name} but holds no rules, so it decides nothing. It still uses capacity in the policy.` }]);
      }
      for (const u of g?.unparsed ?? []) add([{ code: 'firewall-unreadable-rule', severity: 'info', resourceId: policy.name, ruleId: g!.name, title: `A rule in ${g!.name} could not be read`, detail: `${u.text}: ${u.reason}. Paths through the firewall do not take it into account.` }]);
    }
  }
  return out;
}
