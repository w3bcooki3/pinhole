/**
 * Network policies: statements about what must never be reachable, and what
 * must always be, checked exactly against a snapshot.
 *
 *   {
 *     "groups": {
 *       "prod-db":  { "tags": { "env": "prod", "role": "db" } },
 *       "bastions": { "securityGroups": ["sg-0bastion"] },
 *       "dev":      { "tags": { "env": "dev" } },
 *       "prod":     { "tags": { "env": "prod" } }
 *     },
 *     "rules": [
 *       { "id": "no-public-db", "deny": { "from": "internet", "to": "prod-db", "indirect": true } },
 *       { "id": "dev-not-prod", "deny": { "from": "dev", "to": "prod" } },
 *       { "id": "ssh-via-bastion", "deny": { "from": "internet", "to": { "not": "bastions" }, "ports": "tcp/22" } },
 *       { "id": "site-up", "require": { "from": "internet", "to": { "names": ["web-*"] }, "ports": "tcp/443" } }
 *     ]
 *   }
 *
 * A deny rule fails with every connection that breaks it, each with the
 * rules that let it through. With "indirect": true, attack chains count too:
 * an internet-facing server that is taken over and reaches the target. A
 * require rule fails with every pair that cannot connect, each with the hop
 * that blocks it. Every check uses the same exact analysis as the rest of
 * Pinhole: exposure for the internet, service reachability between
 * interfaces, and attack chains.
 *
 * "onprem" is everything AWS routes to Site-to-Site VPN and Direct Connect
 * (onprem.ts). It can be the "from" of a rule:
 *   { "id": "no-onprem-db", "deny": { "from": "onprem", "to": "prod-db", "ports": "tcp/5432" } }
 */
import type { ExposureFinding, ExposureReport } from './exposure.js';
import type { BlastReport } from './blast.js';
import { formatIpv4 } from './ipv4.js';
import { evaluatePath } from './path.js';
import { analyzeOnPrem } from './hybrid.js';
import { onPremNetworks } from './onprem.js';
import { analyzeEgress } from './egress.js';
import { pairReach } from './internal.js';
import { serviceLabel } from './reach.js';
import { compareSeverity } from './risk.js';
import type { Severity } from './risk.js';
import { displayName, isElbNode } from './topology.js';
import type { Hop } from './walk.js';
import type { Eni, NetworkModel, PortRange } from './types.js';

export interface Selector {
  /** Every tag must match; a list matches any of its values. Tags are read from the instance, then the subnet, then the VPC. */
  tags?: Record<string, string | string[]>;
  securityGroups?: string[];
  subnets?: string[];
  vpcs?: string[];
  /** Interface, instance or load balancer IDs, ARNs or load balancer names. */
  ids?: string[];
  /** Instance or load balancer names; `*` matches anything. */
  names?: string[];
  /** Any of these groups or selectors. */
  any?: Target[];
  /** Everything except this. */
  not?: Target;
}

/** "internet", the name of a group, "*" for everything, or a selector. */
export type Target = string | Selector;

export interface PolicyRule {
  id: string;
  description?: string;
  severity?: Severity;
  deny?: { from: Target; to: Target; ports?: string | string[]; indirect?: boolean };
  require?: { from: Target; to: Target; ports: string | string[] };
}

export interface PolicyFile {
  version?: 1;
  groups?: Record<string, Selector>;
  rules: PolicyRule[];
}

export interface Violation {
  from: string;
  fromName: string;
  to: string;
  toName: string;
  protocol: string;
  ports?: PortRange;
  /** One line: what gets through, or what is blocked. */
  detail: string;
  /** The path, one line per hop, with the rules that decided it. */
  path: string[];
  /** For deny rules: the rule IDs that let the traffic through, so they can be fixed. */
  ruleIds: string[];
}

export interface PolicyResult {
  id: string;
  description?: string;
  severity: Severity;
  kind: 'deny' | 'require';
  status: 'pass' | 'fail';
  /** Connections, chains or pairs checked that involve a resource the rule names. */
  checked: number;
  /** Resources the rule's "to" matches in this snapshot: 0 means the rule does not apply here. */
  matched: number;
  violations: Violation[];
}

export interface PolicyReport {
  results: PolicyResult[];
  passed: number;
  failed: number;
}

export class PolicyError extends Error {}

// ------------------------------------------------------------------ parsing

type Ports = { protocol: string; ports?: PortRange };

function parsePorts(spec: string | string[] | undefined, where: string): Ports[] | undefined {
  if (spec === undefined) return undefined;
  const list = Array.isArray(spec) ? spec : [spec];
  return list.map((t) => {
    const s = String(t).trim().toLowerCase();
    if (s === '*' || s === 'all') return { protocol: 'all' };
    if (s === 'icmp') return { protocol: 'icmp' };
    const m = /^(tcp|udp)(?:\/(\d{1,5})(?:-(\d{1,5}))?)?$/.exec(s);
    if (!m) throw new PolicyError(`${where}: "${t}" is not a port spec; use tcp/22, udp/53, tcp/1024-65535, icmp or all.`);
    if (!m[2]) return { protocol: m[1]! };
    const from = Number(m[2]);
    const to = Number(m[3] ?? m[2]);
    if (from > 65535 || to > 65535 || from > to) throw new PolicyError(`${where}: "${t}" is not a valid port range.`);
    return { protocol: m[1]!, ports: { from, to } };
  });
}

const SELECTOR_KEYS = new Set(['tags', 'securityGroups', 'subnets', 'vpcs', 'ids', 'names', 'any', 'not']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const strList = (v: unknown, where: string): string[] => {
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string' || x.length > 512)) throw new PolicyError(`${where} must be a list of strings.`);
  return v as string[];
};

function checkTarget(t: unknown, where: string, groups: Set<string>): void {
  if (typeof t === 'string') {
    if (t !== 'internet' && t !== 'onprem' && t !== '*' && !groups.has(t)) throw new PolicyError(`${where}: "${t}" is not "internet", "onprem", "*" or a group defined under "groups".`);
    return;
  }
  if (!isObj(t)) throw new PolicyError(`${where} must be "internet", a group name or a selector.`);
  for (const k of Object.keys(t)) if (!SELECTOR_KEYS.has(k)) throw new PolicyError(`${where}: unknown selector key "${k}".`);
  if (t.tags !== undefined) {
    if (!isObj(t.tags)) throw new PolicyError(`${where}.tags must be an object.`);
    for (const [k, v] of Object.entries(t.tags)) if (typeof v !== 'string' && !(Array.isArray(v) && v.every((x) => typeof x === 'string'))) throw new PolicyError(`${where}.tags.${k} must be a string or a list of strings.`);
  }
  for (const k of ['securityGroups', 'subnets', 'vpcs', 'ids', 'names'] as const) if (t[k] !== undefined) strList(t[k], `${where}.${k}`);
  if (t.any !== undefined) {
    if (!Array.isArray(t.any)) throw new PolicyError(`${where}.any must be a list.`);
    t.any.forEach((x, i) => checkTarget(x, `${where}.any[${i}]`, groups));
  }
  if (t.not !== undefined) checkTarget(t.not, `${where}.not`, groups);
}

/** Validates a policy file field by field; throws PolicyError naming the field. */
export function parsePolicy(input: unknown): PolicyFile {
  if (!isObj(input)) throw new PolicyError('A policy file is a JSON object with "rules".');
  for (const k of Object.keys(input)) if (!['version', 'groups', 'rules', '$schema'].includes(k)) throw new PolicyError(`Unknown top-level key "${k}".`);
  if (input.version !== undefined && input.version !== 1) throw new PolicyError('"version" must be 1.');
  const groups = input.groups ?? {};
  if (!isObj(groups)) throw new PolicyError('"groups" must be an object of named selectors.');
  const names = new Set(Object.keys(groups));
  for (const n of names) if (n === 'internet' || n === 'onprem' || n === '*') throw new PolicyError(`"${n}" is reserved and cannot be a group name.`);
  for (const [n, sel] of Object.entries(groups)) {
    if (!isObj(sel)) throw new PolicyError(`groups.${n} must be a selector object.`);
    checkTarget(sel, `groups.${n}`, names);
  }
  if (!Array.isArray(input.rules) || !input.rules.length) throw new PolicyError('"rules" must be a non-empty list.');
  const ids = new Set<string>();
  input.rules.forEach((r, i) => {
    const w = `rules[${i}]`;
    if (!isObj(r)) throw new PolicyError(`${w} must be an object.`);
    for (const k of Object.keys(r)) if (!['id', 'description', 'severity', 'deny', 'require'].includes(k)) throw new PolicyError(`${w}: unknown key "${k}".`);
    if (typeof r.id !== 'string' || !/^[A-Za-z0-9._:-]{1,64}$/.test(r.id)) throw new PolicyError(`${w}.id must be 1-64 letters, digits, dots, colons, dashes or underscores.`);
    if (ids.has(r.id)) throw new PolicyError(`${w}: duplicate id "${r.id}".`);
    ids.add(r.id);
    if (r.description !== undefined && (typeof r.description !== 'string' || r.description.length > 1000)) throw new PolicyError(`${w}.description must be a string.`);
    if (r.severity !== undefined && !SEVERITIES.has(String(r.severity))) throw new PolicyError(`${w}.severity must be critical, high, medium, low or info.`);
    const body = r.deny ?? r.require;
    if ((r.deny === undefined) === (r.require === undefined)) throw new PolicyError(`${w} needs exactly one of "deny" or "require".`);
    const kind = r.deny !== undefined ? 'deny' : 'require';
    if (!isObj(body)) throw new PolicyError(`${w}.${kind} must be an object.`);
    for (const k of Object.keys(body)) if (!['from', 'to', 'ports', ...(kind === 'deny' ? ['indirect'] : [])].includes(k)) throw new PolicyError(`${w}.${kind}: unknown key "${k}".`);
    checkTarget(body.from, `${w}.${kind}.from`, names);
    checkTarget(body.to, `${w}.${kind}.to`, names);
    if (body.to === 'internet' && body.from === 'internet') throw new PolicyError(`${w}.${kind}: "from" and "to" cannot both be "internet".`);
    if (body.to === 'onprem') throw new PolicyError(`${w}.${kind}.to: "onprem" can only be the "from" of a rule.`);
    if (body.from === 'onprem' && (body.to === 'internet' || body.indirect)) throw new PolicyError(`${w}.${kind}: with "from": "onprem", "to" must be resources and "indirect" is not used.`);
    if (body.to === 'internet' && body.indirect) throw new PolicyError(`${w}.deny.indirect applies to "from": "internet" only.`);
    if (kind === 'require' && body.ports === undefined) throw new PolicyError(`${w}.require.ports is required: say which service must get through.`);
    parsePorts(body.ports as string | string[] | undefined, `${w}.${kind}.ports`);
    if (body.indirect !== undefined && typeof body.indirect !== 'boolean') throw new PolicyError(`${w}.deny.indirect must be true or false.`);
    if (body.indirect && body.from !== 'internet') throw new PolicyError(`${w}.deny.indirect applies to "from": "internet" only.`);
  });
  return input as unknown as PolicyFile;
}

// ------------------------------------------------------------------ selection

const glob = (pattern: string, text: string) => new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`, 'i').test(text);

/** A resource a selector can match: an interface, or a load balancer. */
type Res = { kind: 'eni'; eni: Eni } | { kind: 'lb'; arn: string };

function tagsOf(model: NetworkModel, r: Res): Record<string, string> {
  if (r.kind === 'lb') return {};
  const e = r.eni;
  const sub = model.subnets.get(e.subnetId);
  return { ...(model.vpcs.get(e.vpcId)?.tags ?? {}), ...(sub?.tags ?? {}), ...(e.instanceId ? model.instances.get(e.instanceId)?.tags ?? {} : {}) };
}

function matches(model: NetworkModel, policy: PolicyFile, t: Target, r: Res, depth = 0): boolean {
  if (depth > 20) throw new PolicyError('Groups refer to each other in a loop.');
  if (t === '*') return true;
  if (t === 'internet' || t === 'onprem') return false;
  if (typeof t === 'string') return matches(model, policy, policy.groups![t]!, r, depth + 1);
  const lb = r.kind === 'lb' ? model.loadBalancers.get(r.arn) : undefined;
  const eni = r.kind === 'eni' ? r.eni : undefined;
  if (t.tags) {
    const tags = tagsOf(model, r);
    for (const [k, v] of Object.entries(t.tags)) if (!(k in tags) || !(Array.isArray(v) ? v : [v]).some((x) => glob(x, tags[k]!))) return false;
  }
  if (t.securityGroups && !(eni?.groupIds ?? lb?.securityGroupIds ?? []).some((g) => t.securityGroups!.includes(g))) return false;
  if (t.subnets && !(eni ? [eni.subnetId] : lb?.subnetIds ?? []).some((s) => t.subnets!.includes(s))) return false;
  if (t.vpcs && !t.vpcs.includes(eni?.vpcId ?? lb?.vpcId ?? '')) return false;
  if (t.ids) {
    const own = eni ? [eni.id, ...(eni.instanceId ? [eni.instanceId] : [])] : lb ? [lb.arn, lb.name] : [];
    if (!own.some((x) => t.ids!.includes(x))) return false;
  }
  if (t.names) {
    const name = eni ? (eni.instanceId ? model.instances.get(eni.instanceId)?.name : undefined) : lb?.name;
    if (!name || !t.names.some((p) => glob(p, name))) return false;
  }
  if (t.any && !t.any.some((x) => matches(model, policy, x, r, depth + 1))) return false;
  if (t.not !== undefined && matches(model, policy, t.not, r, depth + 1)) return false;
  return true;
}

/** Interfaces that can take part in a check: not load balancer nodes (load balancers are matched as themselves). */
const members = (model: NetworkModel, policy: PolicyFile, t: Target): Eni[] =>
  [...model.enis.values()].filter((e) => !isElbNode(e) && e.privateIps.length && matches(model, policy, t, { kind: 'eni', eni: e }));

// ------------------------------------------------------------------ checking

const hopLine = (h: Hop) => `${h.decision === 'pass' ? '✓' : h.decision === 'block' ? '✗' : h.decision === 'unknown' ? '?' : '·'} ${h.stage} ${h.resourceId}${h.ruleIds?.length ? ` [${h.ruleIds.join(', ')}]` : ''}: ${h.detail}`;
const allowedBy = (hops: Hop[]) => [...new Set(hops.filter((h) => h.decision === 'pass' && (h.stage === 'dest-sg-ingress' || h.stage === 'dest-nacl-ingress')).flatMap((h) => h.ruleIds ?? []))];

function overlap(want: Ports[] | undefined, protocol: string, ports: PortRange | undefined): PortRange | undefined | false {
  if (!want) return ports;
  for (const w of want) {
    if (w.protocol === 'all') return ports;
    if (w.protocol !== protocol) continue;
    if (!w.ports || !ports) return ports ?? w.ports;
    const from = Math.max(w.ports.from, ports.from);
    const to = Math.min(w.ports.to, ports.to);
    if (from <= to) return { from, to };
  }
  return false;
}

/** Checks every rule of a policy. */
export function checkPolicy(model: NetworkModel, exposure: ExposureReport, blast: BlastReport | undefined, policy: PolicyFile): PolicyReport {
  const results: PolicyResult[] = [];
  for (const rule of policy.rules) {
    const kind = rule.deny ? 'deny' : 'require';
    const body = (rule.deny ?? rule.require)!;
    const want = parsePorts(body.ports, rule.id);
    const matched = body.to === 'internet' ? members(model, policy, body.from).length : members(model, policy, body.to).length + [...model.loadBalancers.values()].filter((lb) => matches(model, policy, body.to, { kind: 'lb', arn: lb.arn })).length;
    const out: PolicyResult = { id: rule.id, ...(rule.description ? { description: rule.description } : {}), severity: rule.severity ?? (kind === 'deny' ? 'high' : 'medium'), kind, status: 'pass', checked: 0, matched, violations: [] };
    const toEni = (e: Eni) => ({ id: e.id, name: displayName(model, e) });

    if (body.to === 'internet') {
      // Outbound: what the interfaces in "from" can open to the internet (egress.ts).
      const froms = members(model, policy, body.from);
      const report = analyzeEgress(model, { only: new Set(froms.map((e) => e.id)) });
      out.checked = froms.length;
      if (kind === 'deny') {
        for (const f of report.findings) {
          const ports = overlap(want, f.protocol, f.ports);
          if (ports === false) continue;
          const label = serviceLabel({ protocol: f.protocol, ...(ports ? { ports } : {}) });
          out.violations.push({ from: f.resourceId, fromName: f.resourceName, to: 'internet', toName: 'the internet', protocol: f.protocol, ...(ports ? { ports } : {}), detail: `${f.resourceName} can open ${label} to ${f.destinations.slice(0, 2).join(', ')}${f.destinations.length > 2 ? ', ...' : ''} through ${f.via.gateway}`, path: f.trace.map(hopLine), ruleIds: [...new Set(f.trace.filter((h) => h.decision === 'pass' && h.stage === 'source-sg-egress').flatMap((h) => h.ruleIds ?? []))] });
        }
      } else {
        for (const e of froms) {
          for (const w2 of want!) {
            const range = w2.ports ?? { from: 0, to: 65535 };
            const ok = report.findings.some((f) => f.resourceId === e.id && (w2.protocol === 'all' || f.protocol === w2.protocol) && f.ports.from <= range.from && f.ports.to >= range.to && f.destinations[0]?.startsWith('0.0.0.0/0 '));
            if (ok) continue;
            const probe = evaluatePath(model, { from: { eni: e.id }, to: { internet: '198.51.100.7' }, protocol: w2.protocol === 'all' ? 'tcp' : w2.protocol, ...(w2.ports ? { port: w2.ports.from } : { port: 443 }) });
            const label = serviceLabel(w2);
            out.violations.push({ from: e.id, fromName: toEni(e).name, to: 'internet', toName: 'the internet', protocol: w2.protocol, ...(w2.ports ? { ports: w2.ports } : {}), detail: probe.blockedAt ? `${toEni(e).name} cannot open ${label} to the internet: blocked at ${probe.blockedAt.resourceId} (${probe.blockedAt.detail})` : `${toEni(e).name} cannot open all of ${label} to every internet address`, path: probe.hops.map(hopLine), ruleIds: [] });
          }
        }
      }
    } else if (body.from === 'onprem') {
      // From on-premises, over VPN and Direct Connect (hybrid.ts).
      const tos = members(model, policy, body.to);
      const report = analyzeOnPrem(model, { only: new Set(tos.map((e) => e.id)) });
      out.checked = tos.length;
      if (kind === 'deny') {
        for (const f of report.findings) {
          const ports = overlap(want, f.protocol, f.ports);
          if (ports === false) continue;
          const label = serviceLabel({ protocol: f.protocol, ...(ports ? { ports } : {}) });
          out.violations.push({ from: 'onprem', fromName: 'on-premises', to: f.resourceId, toName: f.resourceName, protocol: f.protocol, ...(ports ? { ports } : {}), detail: `${f.sources.slice(0, 3).join(', ')}${f.sources.length > 3 ? ', ...' : ''} on-premises can open ${label} on ${f.resourceName} over ${f.via}`, path: f.trace.map(hopLine), ruleIds: allowedBy(f.trace) });
        }
      } else {
        const space = onPremNetworks(model);
        for (const e of tos) {
          for (const w2 of want!) {
            const range = w2.ports ?? { from: 0, to: 65535 };
            if (report.findings.some((f) => f.resourceId === e.id && (w2.protocol === 'all' || f.protocol === w2.protocol) && f.ports.from <= range.from && f.ports.to >= range.to)) continue;
            const label = serviceLabel(w2);
            // The network that gets furthest explains best why none gets through.
            const probes = space.map((n) => evaluatePath(model, { from: { ip: formatIpv4(n.range.start) }, to: { eni: e.id }, protocol: w2.protocol === 'all' ? 'tcp' : w2.protocol, ...(w2.ports ? { port: w2.ports.from } : { port: 443 }) }));
            const probe = probes.sort((x, y) => y.hops.length - x.hops.length)[0];
            out.violations.push({ from: 'onprem', fromName: 'on-premises', to: e.id, toName: toEni(e).name, protocol: w2.protocol, ...(w2.ports ? { ports: w2.ports } : {}), detail: !probe ? `nothing on-premises can reach ${toEni(e).name}: the snapshot has no VPN or Direct Connect link` : probe?.blockedAt ? `on-premises cannot open ${label} on ${toEni(e).name}: blocked at ${probe.blockedAt.resourceId} (${probe.blockedAt.detail})` : `no on-premises address can open ${label} on ${toEni(e).name}`, path: probe ? probe.hops.map(hopLine) : [], ruleIds: [] });
          }
        }
      }
    } else if (kind === 'deny' && body.from === 'internet') {
      const matchF = (f: ExposureFinding) => (f.kind === 'interface' ? (() => {
        const e = model.enis.get(f.resourceId);
        return !!e && matches(model, policy, body.to, { kind: 'eni', eni: e });
      })() : matches(model, policy, body.to, { kind: 'lb', arn: f.resourceId }));
      for (const f of exposure.findings) {
        const ports = overlap(want, f.protocol, f.ports);
        const label = serviceLabel({ protocol: f.protocol, ports: ports || f.ports });
        const hit = matchF(f);
        if (hit) out.checked += 1;
        if (ports !== false && hit) {
          out.violations.push({ from: 'internet', fromName: 'the internet', to: f.resourceId, toName: f.resourceName, protocol: f.protocol, ...(ports ? { ports } : {}), detail: `${f.sources.slice(0, 3).join(', ')}${f.sources.length > 3 ? ', ...' : ''} can open ${label} on ${f.resourceName}${f.family === 'ipv6' ? ' over IPv6' : ''}`, path: f.trace.map(hopLine), ruleIds: allowedBy(f.trace) });
        }
        // The internet also reaches what is behind a load balancer.
        for (const t of f.targets ?? []) {
          const e = t.eniId ? model.enis.get(t.eniId) : undefined;
          if (!e || (t.verdict !== 'reachable' && t.verdict !== 'partial') || !matches(model, policy, body.to, { kind: 'eni', eni: e })) continue;
          out.checked += 1;
          // Ports in the rule are the ports traffic arrives on at the target.
          if (overlap(want, f.protocol, { from: t.port, to: t.port }) === false) continue;
          out.violations.push({ from: 'internet', fromName: 'the internet', to: e.id, toName: displayName(model, e), protocol: f.protocol, ports: { from: t.port, to: t.port }, detail: `the internet reaches ${displayName(model, e)} on ${t.port} through ${f.resourceName} (listener ${label})`, path: [...f.trace.map(hopLine), `→ target ${t.targetId}:${t.port} (${t.verdict})`, ...t.hops.map(hopLine)], ruleIds: [...allowedBy(f.trace), ...allowedBy(t.hops)] });
        }
      }
      if (rule.deny?.indirect && blast) {
        for (const c of blast.chains) {
          const e = model.enis.get(c.targetId);
          if (!e || !matches(model, policy, body.to, { kind: 'eni', eni: e })) continue;
          out.checked += 1;
          const last = c.steps[c.steps.length - 1]!;
          const m = /^([a-z0-9]+)(?:\/(\d+)(?:-(\d+))?)?$/.exec(last.service ?? '');
          const ports = m?.[2] ? { from: Number(m[2]), to: Number(m[3] ?? m[2]) } : undefined;
          if (want && overlap(want, m?.[1] ?? '', ports) === false) continue;
          out.violations.push({ from: c.entry.eniId, fromName: c.entry.name, to: e.id, toName: displayName(model, e), protocol: m?.[1] ?? 'all', ...(ports ? { ports } : {}), detail: `attack chain from the internet: ${c.steps.map((s) => `${s.name}${s.service ? ` (${s.service})` : ''}`).join(' → ')}`, path: [`entry: ${c.entry.how}`, ...c.steps.slice(1).map((s) => `→ ${s.name} on ${s.service}`)], ruleIds: [] });
        }
      }
    } else if (kind === 'deny') {
      const froms = members(model, policy, body.from);
      const tos = members(model, policy, body.to);
      for (const a of froms) {
        for (const b of tos) {
          if (a.id === b.id) continue;
          out.checked += 1;
          for (const s of pairReach(model, a.id, b.id).services) {
            if (s.verdict !== 'reachable') continue;
            const ports = overlap(want, s.protocol, s.ports);
            if (ports === false) continue;
            const label = serviceLabel({ protocol: s.protocol, ...(ports ? { ports } : {}) });
            out.violations.push({ from: a.id, fromName: toEni(a).name, to: b.id, toName: toEni(b).name, protocol: s.protocol, ...(ports ? { ports } : {}), detail: `${toEni(a).name} can open ${label} on ${toEni(b).name}`, path: s.trace.map(hopLine), ruleIds: allowedBy(s.trace) });
          }
        }
      }
    } else {
      // require: every pair must get every listed service through, fully.
      const tos = members(model, policy, body.to);
      const lbs = [...model.loadBalancers.values()].filter((lb) => matches(model, policy, body.to, { kind: 'lb', arn: lb.arn }));
      if (body.from === 'internet') {
        for (const w of want!) {
          for (const dst of [...tos.map((e) => ({ id: e.id, name: toEni(e).name, lb: false })), ...lbs.map((lb) => ({ id: lb.arn, name: lb.name, lb: true }))]) {
            out.checked += 1;
            const range = w.ports ?? { from: 0, to: 65535 };
            const have = exposure.findings.filter((f) => f.resourceId === dst.id && (w.protocol === 'all' || f.protocol === w.protocol) && f.ports.from <= range.from && f.ports.to >= range.to);
            if (have.length) continue;
            const port = w.ports?.from;
            const probe = dst.lb ? undefined : evaluatePath(model, { from: { internet: '198.51.100.7' }, to: { eni: dst.id }, protocol: w.protocol === 'all' ? 'tcp' : w.protocol, ...(port !== undefined ? { port } : {}) });
            const label = serviceLabel(w);
            out.violations.push({ from: 'internet', fromName: 'the internet', to: dst.id, toName: dst.name, protocol: w.protocol, ...(w.ports ? { ports: w.ports } : {}), detail: probe?.blockedAt ? `the internet cannot open ${label} on ${dst.name}: blocked at ${probe.blockedAt.resourceId} (${probe.blockedAt.detail})` : `the internet cannot open all of ${label} on ${dst.name}`, path: probe ? probe.hops.map(hopLine) : [], ruleIds: [] });
          }
        }
      } else {
        const froms = members(model, policy, body.from);
        for (const a of froms) {
          for (const b of tos) {
            if (a.id === b.id) continue;
            out.checked += 1;
            const svcs = pairReach(model, a.id, b.id).services.filter((s) => s.verdict === 'reachable');
            for (const w of want!) {
              const range = w.ports;
              const ok = svcs.some((s) => (w.protocol === 'all' || s.protocol === w.protocol) && (!range || !s.ports || (s.ports.from <= range.from && s.ports.to >= range.to)));
              if (ok) continue;
              const probe = evaluatePath(model, { from: { eni: a.id }, to: { eni: b.id }, protocol: w.protocol === 'all' ? 'tcp' : w.protocol, ...(range ? { port: range.from } : {}) });
              const label = serviceLabel(w);
              out.violations.push({ from: a.id, fromName: toEni(a).name, to: b.id, toName: toEni(b).name, protocol: w.protocol, ...(range ? { ports: range } : {}), detail: probe.blockedAt ? `${toEni(a).name} cannot open ${label} on ${toEni(b).name}: blocked at ${probe.blockedAt.resourceId} (${probe.blockedAt.detail})` : `${toEni(a).name} cannot open all of ${label} on ${toEni(b).name}`, path: probe.hops.map(hopLine), ruleIds: [] });
            }
          }
        }
      }
    }
    if (out.violations.length) out.status = 'fail';
    results.push(out);
  }
  results.sort((x, y) => (x.status === y.status ? compareSeverity(x.severity, y.severity) : x.status === 'fail' ? -1 : 1));
  return { results, passed: results.filter((r) => r.status === 'pass').length, failed: results.filter((r) => r.status === 'fail').length };
}

/** Violations in `after` that are not in `before`, per rule: what a change would break. */
export function diffPolicy(before: PolicyReport, after: PolicyReport): { id: string; severity: Severity; kind: 'deny' | 'require'; added: Violation[]; resolved: Violation[] }[] {
  const key = (v: Violation) => `${v.from}>${v.to}|${v.protocol}|${v.ports?.from ?? ''}-${v.ports?.to ?? ''}`;
  const out: ReturnType<typeof diffPolicy> = [];
  for (const a of after.results) {
    const b = before.results.find((x) => x.id === a.id);
    const bk = new Set((b?.violations ?? []).map(key));
    const ak = new Set(a.violations.map(key));
    const added = a.violations.filter((v) => !bk.has(key(v)));
    const resolved = (b?.violations ?? []).filter((v) => !ak.has(key(v)));
    if (added.length || resolved.length) out.push({ id: a.id, severity: a.severity, kind: a.kind, added, resolved });
  }
  return out;
}
