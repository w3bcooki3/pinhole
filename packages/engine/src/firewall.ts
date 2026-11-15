/**
 * AWS Network Firewall: reading firewalls, policies and rule groups from a
 * snapshot, and deciding what a firewall does to one connection.
 *
 * Documented behaviour used here
 * (https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-rules-engines.html):
 *
 *  - Every packet goes first to the stateless engine. Stateless rule groups
 *    run in the policy's priority order, rules within a group in their own
 *    priority order, and the first rule that matches decides: pass (the packet
 *    skips the stateful engine), drop, or forward to the stateful engine.
 *    Custom actions only publish metrics. A packet no rule matches gets the
 *    policy's stateless default action.
 *  - Stateless rules see packets, not connections: the reply of an allowed
 *    connection must be passed or forwarded by stateless rules too.
 *  - The stateful engine sees the packets forwarded to it, as flows. With
 *    the default action order, pass rules are applied first, then drop, then
 *    reject, then alert, across all groups; traffic no rule matches passes.
 *    With strict order, groups run in priority order and rules in the order
 *    written, the first pass, drop or reject decides, and the policy's
 *    stateful default actions apply to traffic nothing passed:
 *    aws:drop_strict drops it; aws:drop_established drops it once the
 *    connection is set up, which leaves nothing usable; the alert actions
 *    only log.
 *  - HOME_NET defaults to the CIDRs of the firewall's VPC; a policy variable
 *    overrides it for every group. EXTERNAL_NET is everything else.
 *  - A domain list rule group generates pass (allow list) or drop (deny list)
 *    rules for TLS SNI and HTTP Host from HOME_NET outwards; an allow list also
 *    drops other TLS and HTTP traffic that way.
 *
 * A rule that also matches on something a configuration snapshot cannot know
 * (payload content, a host name, an application protocol, TCP flags) makes the
 * answer depend on the traffic. The evaluator follows both outcomes; when
 * they differ the answer is unknown, with the reason.
 *
 * Connections are evaluated per client source port: the forward packet comes
 * from an ephemeral port, the reply goes back to it, and stateless or stateful
 * rules may treat ports differently. Ports are cut at every boundary any rule
 * mentions, and one port per cell is checked, so the allowed set is exact.
 */
import { DOCS } from './docs.js';
import { formatIpv4, parseCidr, parseIpv4, RangeSet } from './ipv4.js';
import type { RawFirewallDescription, RawFirewallPolicyDescription, RawRuleGroupDescription, Snapshot } from './snapshot.js';
import { naclForSubnet, routeTableForSubnet } from './topology.js';
import type { Firewall, FirewallPolicy, FirewallRuleGroup, Nacl, NetworkModel, Warning, PortRange, StatefulAction, StatefulRule, StatelessRule } from './types.js';

// ------------------------------------------------------------------ reading the snapshot

const ALL = RangeSet.of([{ start: 0, end: 0xffffffff }]);

function cidrList(defs: { AddressDefinition?: string }[] | undefined) {
  const out = [];
  for (const d of defs ?? []) {
    const t = d.AddressDefinition ?? '';
    if (t.includes(':')) continue; // IPv6: not evaluated
    try {
      out.push(parseCidr(t));
    } catch {
      /* skipped below with a warning by the caller */
    }
  }
  return out;
}

function varsOf(sets: Record<string, { Definition?: string[] }> | undefined): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(sets ?? {})) out[k] = v.Definition ?? [];
  return out;
}

const STANDARD: Record<string, StatelessRule['action']> = { 'aws:pass': 'pass', 'aws:drop': 'drop', 'aws:forward_to_sfe': 'forward' };

function readGroup(arn: string, raw: RawRuleGroupDescription | undefined): FirewallRuleGroup {
  const managed = /:aws-managed:|:aws-managed\//.test(arn) || /^arn:aws[a-z-]*:network-firewall:[a-z0-9-]+:aws-managed:/.test(arn);
  const name = raw?.RuleGroupResponse?.RuleGroupName ?? arn.split('/').pop() ?? arn;
  const type = /stateless/i.test(raw?.RuleGroupResponse?.Type ?? '') || /:stateless-rulegroup\//.test(arn) ? 'stateless' : 'stateful';
  const g: FirewallRuleGroup = { arn, name, type, known: !!raw?.RuleGroup, managed, stateless: [], stateful: [], ipSets: {}, portSets: {}, unparsed: [] };
  const rg = raw?.RuleGroup;
  if (!rg) return g;
  g.ipSets = varsOf(rg.RuleVariables?.IPSets);
  g.portSets = varsOf(rg.RuleVariables?.PortSets);
  if (rg.StatefulRuleOptions?.RuleOrder) g.ruleOrder = rg.StatefulRuleOptions.RuleOrder;
  const src = rg.RulesSource ?? {};
  for (const r of src.StatelessRulesAndCustomActions?.StatelessRules ?? []) {
    const actions = r.RuleDefinition?.Actions ?? [];
    const std = actions.map((a) => STANDARD[a]).find((a) => a);
    const m = r.RuleDefinition?.MatchAttributes ?? {};
    if (!std) {
      g.unparsed.push({ text: `priority ${r.Priority}`, reason: 'no standard action (pass, drop or forward)' });
      continue;
    }
    const ports = (list: { FromPort?: number; ToPort?: number }[] | undefined): PortRange[] => (list ?? []).map((p) => ({ from: p.FromPort ?? 0, to: p.ToPort ?? p.FromPort ?? 65535 }));
    g.stateless.push({
      priority: r.Priority ?? 0,
      action: std,
      customActions: actions.filter((a) => !STANDARD[a]),
      sources: cidrList(m.Sources),
      destinations: cidrList(m.Destinations),
      sourcePorts: ports(m.SourcePorts),
      destinationPorts: ports(m.DestinationPorts),
      protocols: (m.Protocols ?? []).map(Number),
      tcpFlags: !!m.TCPFlags?.length,
    });
  }
  g.stateless.sort((a, b) => a.priority - b.priority);
  for (const r of src.StatefulRules ?? []) {
    const h = r.Header ?? {};
    const opts = r.RuleOptions ?? [];
    const sid = opts.find((o) => o.Keyword === 'sid')?.Settings?.[0];
    const act = (r.Action ?? '').toLowerCase() as StatefulAction;
    if (!['pass', 'drop', 'reject', 'alert'].includes(act)) {
      g.unparsed.push({ text: JSON.stringify(h), reason: `action ${r.Action} is not pass, drop, reject or alert` });
      continue;
    }
    const proto = (h.Protocol ?? 'IP').toLowerCase();
    const conditional = conditionOf(opts.map((o) => ({ key: (o.Keyword ?? '').toLowerCase(), value: (o.Settings ?? []).join(',') })), proto);
    const text = `${act} ${proto} ${h.Source ?? 'any'} ${h.SourcePort ?? 'any'} ${h.Direction === 'ANY' ? '<>' : '->'} ${h.Destination ?? 'any'} ${h.DestinationPort ?? 'any'}`;
    g.stateful.push({ action: act, protocol: proto, src: h.Source ?? 'any', srcPort: h.SourcePort ?? 'any', dst: h.Destination ?? 'any', dstPort: h.DestinationPort ?? 'any', bidirectional: h.Direction === 'ANY', ...(conditional ? { conditional } : {}), ...(sid ? { sid } : {}), text });
  }
  if (src.RulesString) {
    const parsed = parseSuricata(src.RulesString);
    g.stateful.push(...parsed.rules);
    g.unparsed.push(...parsed.unparsed);
  }
  const list = src.RulesSourceList;
  if (list) {
    const types = (list.TargetTypes ?? []).map((t) => t.toUpperCase());
    const allow = (list.GeneratedRulesType ?? '').toUpperCase() === 'ALLOWLIST';
    g.domainList = { targets: list.Targets ?? [], types, allow };
    const protos = types.map((t) => (t === 'TLS_SNI' ? 'tls' : t === 'HTTP_HOST' ? 'http' : '')).filter(Boolean);
    const hosts = (list.Targets ?? []).slice(0, 5).join(', ') + ((list.Targets?.length ?? 0) > 5 ? ', ...' : '');
    for (const p of protos) {
      const base = { protocol: p, src: '$HOME_NET', srcPort: 'any', dst: '$EXTERNAL_NET', dstPort: 'any', bidirectional: false };
      // Generated rules apply to the client's side of connections from HOME_NET (flow:to_server).
      g.stateful.push({ ...base, action: allow ? 'pass' : 'drop', conditional: `the ${p === 'tls' ? 'TLS server name' : 'HTTP host'} is one of ${hosts}`, text: `${allow ? 'pass' : 'drop'} ${p} to ${hosts} (flow:to_server)` });
      if (allow) g.stateful.push({ ...base, action: 'drop', conditional: `the traffic is ${p.toUpperCase()}`, text: `drop other ${p} traffic (allow list) (flow:to_server)` });
    }
  }
  return g;
}

/** Suricata keywords that only label or count a rule, or state the flow direction; anything else matches on content. */
const NEUTRAL = new Set(['msg', 'sid', 'rev', 'gid', 'classtype', 'priority', 'metadata', 'reference', 'target', 'noalert', 'flow']);
export const APP_TCP = new Set(['http', 'http2', 'tls', 'ssh', 'smtp', 'ftp', 'ftp-data', 'imap', 'smb', 'dcerpc', 'krb5', 'dns', 'nfs', 'msn', 'rdp', 'pop3', 'mqtt', 'quic']);
export const APP_UDP = new Set(['dns', 'dhcp', 'ntp', 'tftp', 'ikev2', 'snmp', 'sip', 'krb5', 'nfs', 'quic', 'dcerpc']);
const KNOWN_PROTO = new Set(['ip', 'tcp', 'udp', 'icmp', 'tcp-pkt', 'tcp-stream', ...APP_TCP, ...APP_UDP]);

/** Why a rule depends on more than addresses and ports, or undefined. */
function conditionOf(opts: { key: string; value: string }[], proto: string): string | undefined {
  const other = opts.filter((o) => !NEUTRAL.has(o.key) && o.key !== 'flowbits');
  const bits = opts.filter((o) => o.key === 'flowbits' && /^(isset|isnotset)\b/.test(o.value));
  const flow = opts.find((o) => o.key === 'flow')?.value ?? '';
  const parts: string[] = [];
  if (APP_TCP.has(proto) || APP_UDP.has(proto)) parts.push(`the traffic is ${proto.toUpperCase()}`);
  if (other.length) parts.push(`it matches ${[...new Set(other.map((o) => o.key))].slice(0, 4).join(', ')}`);
  if (bits.length) parts.push('it depends on other rules having matched (flowbits)');
  if (/\b(only_stream|no_stream)\b/.test(flow)) parts.push('it depends on stream reassembly');
  return parts.length ? parts.join(' and ') : undefined;
}

/** The flow direction a rule is limited to, from its flow keyword. */
export function flowDirection(rule: StatefulRule): 'to_server' | 'to_client' | undefined {
  const m = /flow:\s*([^;)]*)/i.exec(rule.text);
  if (!m) return undefined;
  if (/\b(to_server|from_client)\b/.test(m[1]!)) return 'to_server';
  if (/\b(to_client|from_server)\b/.test(m[1]!)) return 'to_client';
  return undefined;
}

/** Splits Suricata options on unquoted, unescaped semicolons. */
function splitOptions(body: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (c === '\\' && i + 1 < body.length) {
      cur += c + body[++i];
      continue;
    }
    if (c === '"') quoted = !quoted;
    if (c === ';' && !quoted) {
      if (cur.trim()) out.push(split(cur));
      cur = '';
    } else cur += c;
  }
  if (cur.trim()) out.push(split(cur));
  return out;
  function split(t: string) {
    const k = t.indexOf(':');
    return k < 0 ? { key: t.trim().toLowerCase(), value: '' } : { key: t.slice(0, k).trim().toLowerCase(), value: t.slice(k + 1).trim() };
  }
}

/** Reads Suricata rules: one per line, `\` continues a line, `#` starts a comment. */
export function parseSuricata(text: string): { rules: StatefulRule[]; unparsed: { text: string; reason: string }[] } {
  const rules: StatefulRule[] = [];
  const unparsed: { text: string; reason: string }[] = [];
  const lines = text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(\w+)\s+(\S+)\s+(\[[^\]]*\]|\S+)\s+(\[[^\]]*\]|\S+)\s+(->|<>)\s+(\[[^\]]*\]|\S+)\s+(\[[^\]]*\]|\S+)\s*(?:\((.*)\))?\s*$/.exec(line);
    if (!m) {
      unparsed.push({ text: line.slice(0, 200), reason: 'not a rule Pinhole can read' });
      continue;
    }
    const action = m[1]!.toLowerCase();
    const proto = m[2]!.toLowerCase();
    if (!['pass', 'drop', 'reject', 'alert', 'rejectsrc', 'rejectdst', 'rejectboth'].includes(action)) {
      unparsed.push({ text: line.slice(0, 200), reason: `action "${m[1]}" is not pass, drop, reject or alert` });
      continue;
    }
    if (!KNOWN_PROTO.has(proto)) {
      unparsed.push({ text: line.slice(0, 200), reason: `protocol "${m[2]}" is not one Pinhole knows` });
      continue;
    }
    const opts = m[8] ? splitOptions(m[8]) : [];
    const conditional = conditionOf(opts, proto);
    const sid = opts.find((o) => o.key === 'sid')?.value;
    rules.push({
      action: (action.startsWith('reject') ? 'reject' : action) as StatefulAction,
      protocol: proto === 'tcp-pkt' || proto === 'tcp-stream' ? 'tcp' : proto,
      src: m[3]!,
      srcPort: m[4]!,
      bidirectional: m[5] === '<>',
      dst: m[6]!,
      dstPort: m[7]!,
      ...(conditional ? { conditional } : {}),
      ...(sid ? { sid } : {}),
      text: line.length > 300 ? `${line.slice(0, 297)}...` : line,
    });
  }
  return { rules, unparsed };
}

function readPolicy(arn: string, raw: RawFirewallPolicyDescription | undefined): FirewallPolicy | undefined {
  const p = raw?.FirewallPolicy;
  if (!p) return undefined;
  return {
    arn,
    name: raw?.FirewallPolicyResponse?.FirewallPolicyName ?? arn.split('/').pop() ?? arn,
    statelessGroups: (p.StatelessRuleGroupReferences ?? []).map((r) => ({ arn: r.ResourceArn ?? '', priority: r.Priority ?? 0 })).sort((a, b) => a.priority - b.priority),
    statelessDefault: p.StatelessDefaultActions ?? ['aws:forward_to_sfe'],
    statelessFragmentDefault: p.StatelessFragmentDefaultActions ?? [],
    statefulGroups: (p.StatefulRuleGroupReferences ?? []).map((r) => ({ arn: r.ResourceArn ?? '', ...(r.Priority !== undefined ? { priority: r.Priority } : {}), ...(r.Override?.Action ? { override: r.Override.Action } : {}) })),
    statefulDefault: p.StatefulDefaultActions ?? [],
    ruleOrder: p.StatefulEngineOptions?.RuleOrder === 'STRICT_ORDER' ? 'STRICT_ORDER' : 'DEFAULT_ACTION_ORDER',
    ipSets: varsOf(p.PolicyVariables?.RuleVariables),
  };
}

function readFirewall(raw: RawFirewallDescription): Firewall | undefined {
  const f = raw.Firewall;
  if (!f?.FirewallArn || !f.VpcId) return undefined;
  const endpoints: Firewall['endpoints'] = [];
  for (const [az, st] of Object.entries(raw.FirewallStatus?.SyncStates ?? {})) {
    const a = st.Attachment;
    if (a?.EndpointId && a.SubnetId) endpoints.push({ az, endpointId: a.EndpointId, subnetId: a.SubnetId, ...(a.Status ? { status: a.Status } : {}) });
  }
  return { arn: f.FirewallArn, name: f.FirewallName ?? f.FirewallArn.split('/').pop()!, vpcId: f.VpcId, policyArn: f.FirewallPolicyArn ?? '', endpoints };
}

/** Fills the model's firewall maps from the snapshot. */
export function normalizeFirewalls(snap: Snapshot, model: NetworkModel, warnings: Warning[]): void {
  const nf = snap.networkFirewall;
  if (!nf) return;
  for (const raw of nf.Firewalls ?? []) {
    const fw = readFirewall(raw);
    if (fw) model.firewalls.set(fw.arn, fw);
  }
  for (const [arn, raw] of Object.entries(nf.FirewallPolicies ?? {})) {
    const p = readPolicy(arn, raw);
    if (p) model.firewallPolicies.set(arn, p);
  }
  const groupArns = new Set<string>([...Object.keys(nf.RuleGroups ?? {})]);
  for (const p of model.firewallPolicies.values()) for (const g of [...p.statelessGroups, ...p.statefulGroups]) groupArns.add(g.arn);
  for (const arn of groupArns) {
    const g = readGroup(arn, nf.RuleGroups?.[arn]);
    model.firewallRuleGroups.set(arn, g);
    if (!g.known && !g.managed) warnings.push({ code: 'firewall-rule-group-missing', message: `Rules of firewall rule group ${g.name} are not in the snapshot; traffic it could decide is unknown.`, resourceIds: [arn], docUrl: DOCS.networkFirewall });
    for (const u of g.unparsed.slice(0, 5)) warnings.push({ code: 'firewall-rule-unparsed', message: `Firewall rule group ${g.name}: ${u.reason}: ${u.text}`, resourceIds: [arn], docUrl: DOCS.networkFirewall });
  }
  for (const fw of model.firewalls.values()) {
    if (!model.firewallPolicies.has(fw.policyArn)) warnings.push({ code: 'firewall-policy-missing', message: `The policy of firewall ${fw.name} is not in the snapshot; traffic through it is unknown.`, resourceIds: [fw.arn], docUrl: DOCS.networkFirewall });
  }
}

// ------------------------------------------------------------------ evaluation

export type Verdict = 'pass' | 'block' | 'unknown';

/** One packet of a connection, as the firewall sees it. */
interface FwPacket {
  src: number;
  dst: number;
  protocol: number;
  srcPort?: number;
  dstPort?: number;
  /** Client to server (the packet that opens the connection), or the reply. */
  toServer: boolean;
}

/** Variables for one rule group under one firewall: HOME_NET and friends, as address sets; port sets. */
export interface Vars {
  ip: Map<string, RangeSet>;
  port: Map<string, PortRange[]>;
}

export function addrSet(spec: string, vars: Vars, depth = 0): RangeSet {
  const s = spec.trim();
  if (depth > 10) throw new Error('variables refer to each other in a loop');
  if (s === 'any' || s === '') return ALL;
  if (s.startsWith('!')) return ALL.subtract(addrSet(s.slice(1), vars, depth + 1));
  if (s.startsWith('[') && s.endsWith(']')) {
    let inc = RangeSet.empty();
    let exc = RangeSet.empty();
    let any = false;
    for (const part of splitList(s.slice(1, -1))) {
      if (part.startsWith('!')) exc = exc.union(addrSet(part.slice(1), vars, depth + 1));
      else {
        inc = inc.union(addrSet(part, vars, depth + 1));
        any = true;
      }
    }
    return (any ? inc : ALL).subtract(exc);
  }
  if (s.startsWith('$')) {
    const v = vars.ip.get(s.slice(1));
    if (!v) throw new Error(`variable ${s} is not defined`);
    return v;
  }
  if (s.includes(':')) return RangeSet.empty(); // IPv6: not evaluated
  return RangeSet.of([s.includes('/') ? parseCidr(s) : { start: parseIpv4(s), end: parseIpv4(s) }]);
}

function splitList(body: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (const c of body) {
    if (c === '[') depth++;
    if (c === ']') depth--;
    if (c === ',' && depth === 0) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
    } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

export function portSet(spec: string, vars: Vars, depth = 0): PortRange[] {
  const s = spec.trim();
  if (depth > 10) throw new Error('port variables refer to each other in a loop');
  if (s === 'any' || s === '') return [{ from: 0, to: 65535 }];
  if (s.startsWith('!')) return invert(portSet(s.slice(1), vars, depth + 1));
  if (s.startsWith('[') && s.endsWith(']')) {
    let inc: PortRange[] = [];
    let exc: PortRange[] = [];
    let any = false;
    for (const part of splitList(s.slice(1, -1))) {
      if (part.startsWith('!')) exc = exc.concat(portSet(part.slice(1), vars, depth + 1));
      else {
        inc = inc.concat(portSet(part, vars, depth + 1));
        any = true;
      }
    }
    return minus(any ? inc : [{ from: 0, to: 65535 }], exc);
  }
  if (s.startsWith('$')) {
    const v = vars.port.get(s.slice(1));
    if (!v) throw new Error(`port variable ${s} is not defined`);
    return v;
  }
  const m = /^(\d*)(:?)(\d*)$/.exec(s);
  if (!m || (!m[1] && !m[3])) throw new Error(`"${s}" is not a port`);
  const from = m[1] ? Number(m[1]) : 0;
  const to = m[2] ? (m[3] ? Number(m[3]) : 65535) : from;
  return [{ from, to }];
}

function invert(list: PortRange[]): PortRange[] {
  return minus([{ from: 0, to: 65535 }], list);
}

function minus(list: PortRange[], cut: PortRange[]): PortRange[] {
  let out = list.map((r) => ({ ...r }));
  for (const c of cut) {
    const next: PortRange[] = [];
    for (const r of out) {
      if (c.to < r.from || c.from > r.to) next.push(r);
      else {
        if (c.from > r.from) next.push({ from: r.from, to: c.from - 1 });
        if (c.to < r.to) next.push({ from: c.to + 1, to: r.to });
      }
    }
    out = next;
  }
  return out;
}

const inPorts = (p: number | undefined, list: PortRange[]) => p === undefined || list.some((r) => p >= r.from && p <= r.to);

/** Variables for a rule group running under a firewall. */
export function varsFor(model: NetworkModel, fw: Firewall, policy: FirewallPolicy, g: FirewallRuleGroup): Vars {
  const ip = new Map<string, RangeSet>();
  const port = new Map<string, PortRange[]>();
  const vpc = model.vpcs.get(fw.vpcId);
  const home = vpc ? RangeSet.of(vpc.cidrs) : RangeSet.empty();
  ip.set('HOME_NET', home);
  const tmp: Vars = { ip, port };
  for (const [k, v] of Object.entries(g.portSets)) port.set(k, v.flatMap((x) => portSet(x, tmp)));
  // A group's own variables, then the policy's, which take precedence.
  for (const sets of [g.ipSets, policy.ipSets]) {
    for (const [k, v] of Object.entries(sets)) ip.set(k, v.reduce((acc, x) => acc.union(addrSet(x, tmp)), RangeSet.empty()));
  }
  if (!g.ipSets.EXTERNAL_NET && !policy.ipSets.EXTERNAL_NET) ip.set('EXTERNAL_NET', ALL.subtract(ip.get('HOME_NET')!));
  return { ip, port };
}

const PROTO_NUM: Record<string, number> = { tcp: 6, udp: 17, icmp: 1 };

/** Does the rule's header match the packet? 'maybe' when it depends on something the snapshot cannot decide. */
function headerMatches(r: StatefulRule, pkt: FwPacket, vars: Vars): boolean {
  if (r.protocol !== 'ip') {
    const n = PROTO_NUM[r.protocol];
    if (n !== undefined) {
      if (n !== pkt.protocol) return false;
    } else if (!((APP_TCP.has(r.protocol) && pkt.protocol === 6) || (APP_UDP.has(r.protocol) && pkt.protocol === 17))) return false;
  }
  const dir = flowDirection(r);
  if (dir === 'to_server' && !pkt.toServer) return false;
  if (dir === 'to_client' && pkt.toServer) return false;
  const one = (s: string, sp: string, d: string, dp: string) =>
    addrSet(s, vars).containsIp(pkt.src) && addrSet(d, vars).containsIp(pkt.dst) && inPorts(pkt.srcPort, portSet(sp, vars)) && inPorts(pkt.dstPort, portSet(dp, vars));
  return one(r.src, r.srcPort, r.dst, r.dstPort) || (r.bidirectional && one(r.dst, r.dstPort, r.src, r.srcPort));
}

function statelessMatches(r: StatelessRule, pkt: FwPacket): boolean {
  if (r.protocols.length && !r.protocols.includes(pkt.protocol)) return false;
  const inCidrs = (ip: number, list: StatelessRule['sources']) => !list.length || list.some((c) => ip >= c.start && ip <= c.end);
  if (!inCidrs(pkt.src, r.sources) || !inCidrs(pkt.dst, r.destinations)) return false;
  if (r.sourcePorts.length && !inPorts(pkt.srcPort, r.sourcePorts)) return false;
  if (r.destinationPorts.length && !inPorts(pkt.dstPort, r.destinationPorts)) return false;
  return true;
}

interface Outcome {
  verdict: Verdict;
  why: string;
  rules: string[];
}

/** The stateless engine on one packet: pass, drop or forward, and why. */
function stateless(model: NetworkModel, policy: FirewallPolicy, pkt: FwPacket): { action: 'pass' | 'drop' | 'forward' | 'unknown'; why: string; rule?: string } {
  for (const ref of policy.statelessGroups) {
    const g = model.firewallRuleGroups.get(ref.arn);
    if (!g?.known) return { action: 'unknown', why: `rules of stateless group ${g?.name ?? ref.arn} are not in the snapshot` };
    for (const r of g.stateless) {
      if (!statelessMatches(r, pkt)) continue;
      const id = `${g.name}#${r.priority}`;
      if (r.tcpFlags) return { action: 'unknown', why: `stateless rule ${id} matches on TCP flags, so it decides some packets of the connection and not others`, rule: id };
      return { action: r.action, why: `stateless rule ${id} ${r.action === 'forward' ? 'forwards it to the stateful engine' : r.action === 'pass' ? 'passes it' : 'drops it'}`, rule: id };
    }
  }
  const d = policy.statelessDefault.map((a) => STANDARD[a]).find((a) => a) ?? 'forward';
  return { action: d, why: `no stateless rule matches; the default action ${d === 'forward' ? 'forwards it to the stateful engine' : d === 'pass' ? 'passes it' : 'drops it'}` };
}

export type Stateful = { rule: StatefulRule; group: FirewallRuleGroup; vars: Vars; demote: boolean };

/** The stateful rules in the order the engine applies them. */
export function statefulOrder(model: NetworkModel, fw: Firewall, policy: FirewallPolicy): { list: Stateful[]; missing?: string } {
  const refs = [...policy.statefulGroups];
  if (policy.ruleOrder === 'STRICT_ORDER') refs.sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0));
  const list: Stateful[] = [];
  let missing: string | undefined;
  for (const ref of refs) {
    const g = model.firewallRuleGroups.get(ref.arn);
    if (!g || (!g.known && !g.managed)) {
      missing ??= `rules of stateful group ${g?.name ?? ref.arn} are not in the snapshot`;
      continue;
    }
    if (!g.known) continue; // AWS managed: drops known-bad traffic only
    const vars = varsFor(model, fw, policy, g);
    for (const rule of g.stateful) list.push({ rule, group: g, vars, demote: ref.override === 'DROP_TO_ALERT' });
  }
  if (policy.ruleOrder !== 'STRICT_ORDER') {
    const rank: Record<StatefulAction, number> = { pass: 0, drop: 1, reject: 2, alert: 3 };
    list.sort((a, b) => rank[a.rule.action] - rank[b.rule.action]);
  }
  return { list, ...(missing ? { missing } : {}) };
}

const label = (s: Stateful) => `${s.group.name}${s.rule.sid ? ` sid ${s.rule.sid}` : ''}`;

/**
 * The stateful engine on a flow (the forwarded packets, in order). Rules
 * that depend on things the snapshot cannot know are followed both ways.
 */
function statefulFlow(rules: Stateful[], packets: FwPacket[], policy: FirewallPolicy, missing: string | undefined): Outcome[] {
  const results: Outcome[] = [];
  let branches = 0;
  const walk = (pi: number, ri: number, assumed: string[], trail: string[]) => {
    if (pi >= packets.length) {
      // Nothing passed the flow explicitly.
      if (policy.ruleOrder === 'STRICT_ORDER' && policy.statefulDefault.some((a) => a === 'aws:drop_strict' || a === 'aws:drop_established')) {
        const d = policy.statefulDefault.find((a) => a.startsWith('aws:drop'))!;
        results.push({ verdict: 'block', why: `no stateful rule passes it, and the default action ${d} drops it${assumed.length ? `, if ${assumed.join(' and ')}` : ''}`, rules: [...trail, `default ${d}`] });
      } else if (missing) {
        results.push({ verdict: 'unknown', why: missing, rules: trail });
      } else {
        results.push({ verdict: 'pass', why: `no stateful rule drops it${assumed.length ? `, if ${assumed.join(' and ')}` : ''}`, rules: trail });
      }
      return;
    }
    const pkt = packets[pi]!;
    for (let i = ri; i < rules.length; i++) {
      const s = rules[i]!;
      let hit: boolean;
      try {
        hit = headerMatches(s.rule, pkt, s.vars);
      } catch (e) {
        results.push({ verdict: 'unknown', why: `rule ${label(s)} cannot be read: ${(e as Error).message}`, rules: [...trail, label(s)] });
        return;
      }
      if (!hit) continue;
      const action = s.demote && (s.rule.action === 'drop' || s.rule.action === 'reject') ? 'alert' : s.rule.action;
      if (action === 'alert') continue;
      const decide = () => {
        if (action === 'pass') results.push({ verdict: 'pass', why: `stateful rule ${label(s)} passes it (${s.rule.text})${assumed.length || s.rule.conditional ? `, if ${[...assumed, ...(s.rule.conditional ? [s.rule.conditional] : [])].join(' and ')}` : ''}`, rules: [...trail, label(s)] });
        else results.push({ verdict: 'block', why: `stateful rule ${label(s)} ${action === 'reject' ? 'rejects' : 'drops'} it (${s.rule.text})${assumed.length || s.rule.conditional ? `, if ${[...assumed, ...(s.rule.conditional ? [s.rule.conditional] : [])].join(' and ')}` : ''}`, rules: [...trail, label(s)] });
      };
      if (!s.rule.conditional) return decide();
      // Both ways: the condition holds, and it does not.
      if (++branches > 64) {
        results.push({ verdict: 'unknown', why: 'too many rules depend on the traffic itself to follow every case', rules: trail });
        return;
      }
      decide();
      walk(pi, i + 1, [...assumed, `not (${s.rule.conditional})`], trail);
      return;
    }
    walk(pi + 1, 0, assumed, trail);
  };
  walk(0, 0, [], []);
  return results;
}

/** What a firewall does to one connection with the client on one source port. */
function connection(model: NetworkModel, fw: Firewall, policy: FirewallPolicy, client: number, server: number, protocol: number, port: number | undefined, clientPort: number | undefined): Outcome {
  const fwd: FwPacket = { src: client, dst: server, protocol, ...(clientPort !== undefined ? { srcPort: clientPort } : {}), ...(port !== undefined ? { dstPort: port } : {}), toServer: true };
  const rev: FwPacket = { src: server, dst: client, protocol, ...(port !== undefined ? { srcPort: port } : {}), ...(clientPort !== undefined ? { dstPort: clientPort } : {}), toServer: false };
  const forwarded: FwPacket[] = [];
  const steps: string[] = [];
  const rules: string[] = [];
  for (const [p, name] of [[fwd, 'request'], [rev, 'reply']] as const) {
    const s = stateless(model, policy, p);
    if (s.rule) rules.push(s.rule);
    if (s.action === 'unknown') return { verdict: 'unknown', why: `${name}: ${s.why}`, rules };
    if (s.action === 'drop') return { verdict: 'block', why: `${name}: ${s.why}`, rules };
    steps.push(`${name}: ${s.why}`);
    if (s.action === 'forward') forwarded.push(p);
  }
  // "request: X; reply: X" reads better as one step.
  const same = steps.length === 2 && steps[0]!.slice('request: '.length) === steps[1]!.slice('reply: '.length);
  if (same) steps.splice(0, 2, `request and reply: ${steps[0]!.slice('request: '.length)}`);
  if (!forwarded.length) return { verdict: 'pass', why: steps.join('; '), rules };
  const { list, missing } = statefulOrder(model, fw, policy);
  // A group whose rules are not known could hold the pass or the drop that decides.
  if (missing) return { verdict: 'unknown', why: [...steps, missing].join('; '), rules };
  const outs = statefulFlow(list, forwarded, policy, missing);
  const verdicts = new Set(outs.map((o) => o.verdict));
  const first = outs[0]!;
  if (verdicts.size === 1) return { verdict: first.verdict, why: [...steps, first.why].join('; '), rules: [...rules, ...first.rules] };
  const pass = outs.find((o) => o.verdict === 'pass');
  const block = outs.find((o) => o.verdict === 'block');
  return {
    verdict: 'unknown',
    why: [...steps, `it depends on the traffic: ${pass ? pass.why : ''}${pass && block ? '; otherwise ' : ''}${block ? block.why : ''}`].join('; '),
    rules: [...rules, ...new Set(outs.flatMap((o) => o.rules))],
  };
}

/** Every port boundary any rule of the policy mentions, for cutting the client's ephemeral range. */
function portCuts(model: NetworkModel, fw: Firewall, policy: FirewallPolicy, span: PortRange): number[] {
  const cuts = new Set<number>([span.from]);
  const add = (r: PortRange) => {
    if (r.from > span.from && r.from <= span.to) cuts.add(r.from);
    if (r.to + 1 > span.from && r.to + 1 <= span.to) cuts.add(r.to + 1);
  };
  for (const ref of policy.statelessGroups) for (const r of model.firewallRuleGroups.get(ref.arn)?.stateless ?? []) [...r.sourcePorts, ...r.destinationPorts].forEach(add);
  for (const s of statefulOrder(model, fw, policy).list) {
    for (const spec of [s.rule.srcPort, s.rule.dstPort]) {
      try {
        portSet(spec, s.vars).forEach(add);
      } catch {
        /* an unreadable rule is reported when it is evaluated */
      }
    }
  }
  return [...cuts].sort((a, b) => a - b);
}

export interface FirewallResult {
  verdict: Verdict;
  /** For TCP and UDP: client source ports (within `span`) whose connection passes. */
  allowed: PortRange[];
  /** Client source ports whose fate depends on the traffic. */
  unknownPorts: PortRange[];
  detail: string;
  ruleIds: string[];
}

/**
 * What `fw` does to a connection from `client` to `server` on `protocol` and
 * `port`, for client source ports in `span` (the ephemeral range).
 */
export function evaluateFirewall(model: NetworkModel, fw: Firewall, client: number, server: number, protocol: number, port: number | undefined, span: PortRange): FirewallResult {
  const policy = model.firewallPolicies.get(fw.policyArn);
  const head = `${fw.name}: ${formatIpv4(client)} to ${formatIpv4(server)}`;
  if (!policy) return { verdict: 'unknown', allowed: [], unknownPorts: [span], detail: `${fw.name}: the firewall policy is not in the snapshot`, ruleIds: [] };
  const ported = protocol === 6 || protocol === 17;
  if (!ported) {
    const o = connection(model, fw, policy, client, server, protocol, undefined, undefined);
    return { verdict: o.verdict, allowed: o.verdict === 'pass' ? [span] : [], unknownPorts: o.verdict === 'unknown' ? [span] : [], detail: `${head}: ${o.why}`, ruleIds: o.rules };
  }
  const cuts = portCuts(model, fw, policy, span);
  const allowed: PortRange[] = [];
  const unknownPorts: PortRange[] = [];
  const seen = new Map<string, { o: Outcome; ranges: PortRange[] }>();
  for (let i = 0; i < cuts.length; i++) {
    const from = cuts[i]!;
    const to = i + 1 < cuts.length ? cuts[i + 1]! - 1 : span.to;
    const o = connection(model, fw, policy, client, server, protocol, port, from);
    const key = `${o.verdict}|${o.why}`;
    const entry = seen.get(key) ?? seen.set(key, { o, ranges: [] }).get(key)!;
    entry.ranges.push({ from, to });
    if (o.verdict === 'pass') allowed.push({ from, to });
    if (o.verdict === 'unknown') unknownPorts.push({ from, to });
  }
  const groups = [...seen.values()];
  const verdict: Verdict = allowed.length ? 'pass' : unknownPorts.length ? 'unknown' : 'block';
  const fmt = (rs: PortRange[]) => rs.map((r) => (r.from === r.to ? `${r.from}` : `${r.from}-${r.to}`)).join(', ');
  const detail =
    groups.length === 1
      ? `${head}: ${groups[0]!.o.why}`
      : `${head}: ${groups.map((g) => `client ports ${fmt(g.ranges)}: ${g.o.why}`).join(' | ')}`;
  return { verdict, allowed: merge(allowed), unknownPorts: merge(unknownPorts), detail, ruleIds: [...new Set(groups.flatMap((g) => g.o.rules))] };
}

function merge(list: PortRange[]): PortRange[] {
  const out: PortRange[] = [];
  for (const r of [...list].sort((a, b) => a.from - b.from)) {
    const last = out[out.length - 1];
    if (last && r.from <= last.to + 1) last.to = Math.max(last.to, r.to);
    else out.push({ ...r });
  }
  return out;
}

/** The firewall an endpoint belongs to, if it is a Network Firewall endpoint. */
export function firewallOfEndpoint(model: NetworkModel, endpointId: string): { fw: Firewall; endpoint: Firewall['endpoints'][number] } | undefined {
  for (const fw of model.firewalls.values()) {
    const endpoint = fw.endpoints.find((e) => e.endpointId === endpointId);
    if (endpoint) return { fw, endpoint };
  }
  return undefined;
}

/** Address boundaries in a firewall's rules, so exposure cells can be cut where a firewall decides differently. */
export function firewallAddressCuts(model: NetworkModel): { start: number; end: number }[] {
  const out: { start: number; end: number }[] = [];
  for (const fw of model.firewalls.values()) {
    const policy = model.firewallPolicies.get(fw.policyArn);
    if (!policy) continue;
    for (const ref of policy.statelessGroups) for (const r of model.firewallRuleGroups.get(ref.arn)?.stateless ?? []) out.push(...r.sources, ...r.destinations);
    for (const s of statefulOrder(model, fw, policy).list) {
      for (const spec of [s.rule.src, s.rule.dst]) {
        try {
          for (const c of addrSet(spec, s.vars).toCidrs()) out.push(parseCidr(c));
        } catch {
          /* reported when evaluated */
        }
      }
    }
  }
  return out;
}

/** Port boundaries in firewall rules for the destination port, for exposure cells. */
export function firewallPortCuts(model: NetworkModel): PortRange[] {
  const out: PortRange[] = [];
  for (const fw of model.firewalls.values()) {
    const policy = model.firewallPolicies.get(fw.policyArn);
    if (!policy) continue;
    for (const ref of policy.statelessGroups) for (const r of model.firewallRuleGroups.get(ref.arn)?.stateless ?? []) out.push(...r.destinationPorts, ...r.sourcePorts);
    for (const s of statefulOrder(model, fw, policy).list) {
      for (const spec of [s.rule.srcPort, s.rule.dstPort]) {
        try {
          out.push(...portSet(spec, s.vars));
        } catch {
          /* reported when evaluated */
        }
      }
    }
  }
  return out;
}

/**
 * Everything on an inspection path that can split traffic: firewall rule
 * addresses and ports, and the network ACLs and route tables of every
 * appliance endpoint's subnet. Exposure and service reachability cut their
 * cells at these too, so a cell is decided the same way throughout.
 */
const boundaryCache = new WeakMap<NetworkModel, { addrs: { start: number; end: number }[]; ports: PortRange[]; acls: Nacl[]; routes: { start: number; end: number }[] }>();
export function inspectionBoundaries(model: NetworkModel) {
  let b = boundaryCache.get(model);
  if (b) return b;
  const subnets = new Set<string>();
  for (const fw of model.firewalls.values()) for (const e of fw.endpoints) subnets.add(e.subnetId);
  for (const e of model.vpcEndpoints.values()) if (e.type === 'GatewayLoadBalancer') for (const id of e.subnetIds ?? []) subnets.add(id);
  const acls = new Set<Nacl>();
  const routes: { start: number; end: number }[] = [];
  for (const id of subnets) {
    const sub = model.subnets.get(id);
    if (!sub) continue;
    const acl = naclForSubnet(model, sub);
    if (acl) acls.add(acl);
    for (const r of routeTableForSubnet(model, sub)?.routes ?? []) if (r.destination) routes.push(r.destination);
  }
  b = subnets.size ? { addrs: firewallAddressCuts(model), ports: firewallPortCuts(model), acls: [...acls], routes } : { addrs: [], ports: [], acls: [], routes: [] };
  boundaryCache.set(model, b);
  return b;
}
