/**
 * Terraform plan check: turn the network-relevant resource changes in
 * `terraform show -json PLAN` output into Pinhole changes against a snapshot,
 * so the exposure a plan would create is known before it is applied.
 *
 * Only what can be placed exactly is mapped. Anything that depends on values
 * known only after apply, on resources the snapshot does not contain, or on
 * resource types Pinhole does not model is listed as skipped with the reason,
 * never guessed. A clean result therefore means "nothing mapped opens
 * exposure", and the skipped list says what was not checked.
 *
 * Plan format: https://developer.hashicorp.com/terraform/internals/json-format
 */
import { parseCidr } from './ipv4.js';
import { hasPorts, normalizeProtocol } from './packet.js';
import type { NetworkModel, SgRule } from './types.js';
import { assertChanges, ChangeError } from './whatif.js';
import type { Change } from './whatif.js';

export class PlanError extends Error {}

export interface PlanResourceResult {
  address: string;
  type: string;
  actions: string[];
  changes: Change[];
  /** Why part or all of this resource change was not analysed. */
  skipped: string[];
}

export interface PlanMapping {
  changes: Change[];
  resources: PlanResourceResult[];
  /** Network-relevant resource changes that were not analysed at all. */
  skipped: { address: string; type: string; reason: string }[];
  /** Resource changes outside networking, counted but not listed. */
  ignored: number;
}

type Obj = Record<string, unknown>;
interface RawChange {
  address?: unknown;
  type?: unknown;
  mode?: unknown;
  change?: { actions?: unknown; before?: unknown; after?: unknown; after_unknown?: unknown };
}

/** Types that change who can reach what. Anything else in a plan is ignored. */
const NETWORK_TYPES = new Set([
  'aws_security_group', 'aws_default_security_group', 'aws_security_group_rule', 'aws_vpc_security_group_ingress_rule', 'aws_vpc_security_group_egress_rule',
  'aws_network_acl', 'aws_default_network_acl', 'aws_network_acl_rule', 'aws_network_acl_association',
  'aws_route', 'aws_route_table', 'aws_default_route_table', 'aws_route_table_association', 'aws_main_route_table_association',
  'aws_network_interface', 'aws_network_interface_sg_attachment', 'aws_instance', 'aws_eip', 'aws_eip_association',
  'aws_internet_gateway', 'aws_internet_gateway_attachment', 'aws_egress_only_internet_gateway', 'aws_nat_gateway',
  'aws_vpc_peering_connection', 'aws_vpc_peering_connection_accepter', 'aws_ec2_transit_gateway_route', 'aws_ec2_transit_gateway_vpc_attachment',
  'aws_subnet', 'aws_vpc', 'aws_lb', 'aws_alb', 'aws_lb_listener', 'aws_alb_listener', 'aws_lb_target_group', 'aws_lb_target_group_attachment',
  'aws_vpc_endpoint', 'aws_networkfirewall_firewall', 'aws_ec2_managed_prefix_list', 'aws_ec2_managed_prefix_list_entry',
]);

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isInteger(v) ? v : undefined);
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strs = (v: unknown): string[] => list(v).filter((x): x is string => typeof x === 'string' && x !== '');
/** True when any of `keys` (or the whole object) is unknown until apply. */
const unknown = (u: unknown, ...keys: string[]) => u === true || (isObj(u) && keys.some((k) => u[k] === true || (Array.isArray(u[k]) && (u[k] as unknown[]).some((x) => x === true || (isObj(x) && Object.values(x).includes(true))))));

/** A security group rule as Terraform describes it, one source per rule. */
interface TfRule {
  groupId: string;
  egress: boolean;
  protocol: string;
  fromPort?: number;
  toPort?: number;
  cidr?: string;
  ipv6?: string;
  prefixListId?: string;
  referencedGroupId?: string;
  description?: string;
}

function tfProtocol(p: unknown): string {
  const s = typeof p === 'number' ? String(p) : str(p) ?? '-1';
  return normalizeProtocol(s === 'all' ? '-1' : s);
}

/** Expands one Terraform rule shape into one rule per source, as AWS stores them. */
function expand(groupId: string, egress: boolean, r: Obj, shape: 'inline' | 'legacy' | 'vpc'): TfRule[] {
  const protocol = tfProtocol(shape === 'vpc' ? r.ip_protocol : r.protocol);
  const ports = hasPorts(protocol) ? { fromPort: num(r.from_port) ?? 0, toPort: num(r.to_port) ?? num(r.from_port) ?? 65535 } : {};
  const base = { groupId, egress, protocol, ...ports, ...(str(r.description) ? { description: str(r.description)! } : {}) };
  if (shape === 'vpc') {
    const one = { ...base } as TfRule;
    if (str(r.cidr_ipv4)) one.cidr = str(r.cidr_ipv4)!;
    else if (str(r.cidr_ipv6)) one.ipv6 = str(r.cidr_ipv6)!;
    else if (str(r.prefix_list_id)) one.prefixListId = str(r.prefix_list_id)!;
    else if (str(r.referenced_security_group_id)) one.referencedGroupId = str(r.referenced_security_group_id)!.split('/').pop()!;
    return [one];
  }
  const out: TfRule[] = [];
  for (const c of strs(r.cidr_blocks)) out.push({ ...base, cidr: c });
  for (const c of strs(r.ipv6_cidr_blocks)) out.push({ ...base, ipv6: c });
  for (const p of strs(r.prefix_list_ids)) out.push({ ...base, prefixListId: p });
  for (const g of [...strs(shape === 'inline' ? r.security_groups : []), ...(str(r.source_security_group_id) ? [str(r.source_security_group_id)!] : [])]) out.push({ ...base, referencedGroupId: g.split('/').pop()! });
  if (r.self === true) out.push({ ...base, referencedGroupId: groupId });
  return out;
}

const sameRule = (m: SgRule, t: TfRule) =>
  m.groupId === t.groupId &&
  m.egress === t.egress &&
  m.protocol === t.protocol &&
  (!hasPorts(t.protocol) || ((m.fromPort ?? 0) === t.fromPort && (m.toPort ?? 65535) === t.toPort)) &&
  (t.cidr ? m.cidr?.text === parseCidr(t.cidr).text : t.prefixListId ? m.prefixListId === t.prefixListId : t.referencedGroupId ? m.referencedGroupId === t.referencedGroupId : t.ipv6 ? m.ipv6CidrText === t.ipv6 : false);
const ruleKey = (t: TfRule) => JSON.stringify([t.egress, t.protocol, t.fromPort, t.toPort, t.cidr, t.ipv6, t.prefixListId, t.referencedGroupId]);

/** Strip instance keys: aws_security_group.web[0] and aws_security_group.web["a"] -> aws_security_group.web */
const baseAddress = (a: string) => a.replace(/\[[^\]]*\]/g, '');

/**
 * What the plan's "configuration" block says about references: for each
 * resource (module path included, no instance keys), its attribute
 * expressions; for each module output, what it refers to. Used when a value is
 * unknown until apply, to find which resource it comes from.
 */
interface ConfigIndex {
  resources: Map<string, Obj>;
  /** "module.net.sg_id" -> absolute references of that output's expression. */
  outputs: Map<string, string[]>;
}

function configIndex(plan: Obj): ConfigIndex {
  const resources = new Map<string, Obj>();
  const outputs = new Map<string, string[]>();
  const walk = (mod: unknown, prefix: string, depth: number) => {
    if (!isObj(mod) || depth > 20) return;
    for (const r of list(mod.resources).filter(isObj)) {
      const addr = str(r.address);
      if (addr && isObj(r.expressions)) resources.set(prefix + addr, r.expressions);
    }
    if (isObj(mod.module_calls)) {
      for (const [name, call] of Object.entries(mod.module_calls)) {
        if (!isObj(call)) continue;
        const inner = `${prefix}module.${name}.`;
        const m = call.module;
        if (isObj(m) && isObj(m.outputs)) {
          for (const [out, def] of Object.entries(m.outputs)) {
            const refs = isObj(def) && isObj(def.expression) ? strs(def.expression.references) : [];
            outputs.set(`${prefix}module.${name}.${out}`, refs.map((r) => inner + r));
          }
        }
        walk(m, inner, depth + 1);
      }
    }
  };
  if (isObj(plan.configuration)) walk(plan.configuration.root_module, '', 0);
  return { resources, outputs };
}

/** The resource addresses an attribute's expression refers to, made absolute, through module outputs. */
function refsOf(config: ConfigIndex, address: string, attr: string): string[] {
  const base = baseAddress(address);
  const expr = config.resources.get(base)?.[attr];
  const modulePrefix = base.match(/^((?:module\.[^.]+\.)*)/)?.[1] ?? '';
  const out = new Set<string>();
  const follow = (ref: string, depth: number) => {
    if (depth > 10) return;
    if (/^(?:module\.[^.]+\.)*aws_/.test(ref)) out.add(ref);
    else if (config.outputs.has(ref)) for (const r of config.outputs.get(ref)!) follow(r, depth + 1);
  };
  for (const r of isObj(expr) ? strs(expr.references) : []) follow(modulePrefix + r, 0);
  return [...out];
}

export function mapTerraformPlan(model: NetworkModel, plan: unknown): PlanMapping {
  if (!isObj(plan)) throw new PlanError('The plan must be the JSON from `terraform show -json PLANFILE`.');
  const rcs = plan.resource_changes;
  if (rcs === undefined) throw new PlanError('The plan has no "resource_changes". Use `terraform show -json PLANFILE`, not `terraform show -json` without a plan file.');
  if (!Array.isArray(rcs)) throw new PlanError('"resource_changes" must be a list.');
  if (rcs.length > 100_000) throw new PlanError('The plan has more than 100000 resource changes.');

  const result: PlanMapping = { changes: [], resources: [], skipped: [], ignored: 0 };
  const groupIn = (id: string | undefined) => !!id && model.securityGroups.has(id);
  const rulesOf = (groupId: string) => {
    const g = model.securityGroups.get(groupId);
    return g ? [...g.ingress, ...g.egress] : [];
  };
  const eniOfInstance = (instanceId: string) => model.instances.get(instanceId)?.primaryEniId ?? model.instances.get(instanceId)?.eniIds[0];

  // Security groups this plan creates get a placeholder ID ("sg-plan1"), so
  // rules and attachments that refer to them in the same plan can be checked.
  const config = configIndex(plan);
  const created = new Map<string, string>(); // address -> placeholder
  const createdBase = new Map<string, string[]>(); // base address -> placeholders
  let n = 0;
  for (const raw of rcs as RawChange[]) {
    if (!isObj(raw) || str(raw.mode) === 'data' || str(raw.type) !== 'aws_security_group') continue;
    const ch = isObj(raw.change) ? raw.change : {};
    const acts = strs(ch.actions);
    if (!acts.includes('create') || acts.includes('delete') || !unknown(ch.after_unknown, 'id')) continue;
    const address = str(raw.address) ?? '';
    const id = `sg-plan${++n}`;
    created.set(address, id);
    createdBase.set(baseAddress(address), [...(createdBase.get(baseAddress(address)) ?? []), id]);
  }
  const placeholderFor = (ref: string): string | undefined => {
    const r = ref.replace(/\.(id|arn|name)$/, '');
    if (created.has(r)) return created.get(r);
    const many = createdBase.get(baseAddress(r));
    return many?.length === 1 ? many[0] : undefined;
  };
  /** A security group ID that is known, or a placeholder for one this plan creates. */
  const groupRef = (address: string, value: unknown, unk: boolean, attr: string): string | undefined => {
    if (!unk) return str(value)?.split('/').pop();
    const ids = [...new Set(refsOf(config, address, attr).map(placeholderFor).filter((x): x is string => !!x))];
    return ids.length === 1 ? ids[0] : undefined;
  };
  const knownGroup = (id: string | undefined) => !!id && (model.securityGroups.has(id) || [...created.values()].includes(id));

  for (const raw of rcs as RawChange[]) {
    if (!isObj(raw)) continue;
    const address = str(raw.address) ?? '(unnamed)';
    const type = str(raw.type) ?? '';
    const mode = str(raw.mode) ?? 'managed';
    const ch = isObj(raw.change) ? raw.change : {};
    const actions = strs(ch.actions);
    if (mode !== 'managed' || !NETWORK_TYPES.has(type)) {
      if (actions.some((a) => a !== 'no-op' && a !== 'read')) result.ignored++;
      continue;
    }
    if (actions.every((a) => a === 'no-op' || a === 'read')) continue;
    const before = isObj(ch.before) ? ch.before : undefined;
    const after = isObj(ch.after) ? ch.after : undefined;
    const u = ch.after_unknown;
    const removing = actions.includes('delete');
    const creating = actions.includes('create');
    const updating = actions.includes('update');
    const res: PlanResourceResult = { address, type, actions, changes: [], skipped: [] };
    const skip = (reason: string) => res.skipped.push(reason);
    const revokeRule = (t: TfRule) => {
      const hits = rulesOf(t.groupId).filter((m) => sameRule(m, t));
      if (!hits.length) skip(`no rule in ${t.groupId} matches ${t.egress ? 'outbound' : 'inbound'} ${t.protocol} ${t.cidr ?? t.prefixListId ?? t.referencedGroupId ?? t.ipv6}; it may already be gone`);
      for (const m of hits) if (!res.changes.some((c) => c.kind === 'revoke-sg-rule' && c.ruleId === m.id)) res.changes.push({ kind: 'revoke-sg-rule', ruleId: m.id });
    };
    const addRule = (t: TfRule) => {
      if (t.ipv6) return skip(`IPv6 source ${t.ipv6} is not analysed`);
      res.changes.push({ kind: 'add-sg-rule', groupId: t.groupId, egress: t.egress, protocol: t.protocol, ...(t.fromPort !== undefined ? { fromPort: t.fromPort, toPort: t.toPort! } : {}), ...(t.cidr ? { cidr: t.cidr } : {}), ...(t.prefixListId ? { prefixListId: t.prefixListId } : {}), ...(t.referencedGroupId ? { referencedGroupId: t.referencedGroupId } : {}) });
    };

    try {
      switch (type) {
        case 'aws_vpc_security_group_ingress_rule':
        case 'aws_vpc_security_group_egress_rule': {
          const egress = type.endsWith('egress_rule');
          if (before && (removing || updating)) {
            const id = str(before.security_group_rule_id);
            if (id && rulesOf(str(before.security_group_id) ?? '').some((r) => r.id === id)) res.changes.push({ kind: 'revoke-sg-rule', ruleId: id });
            else if (groupIn(str(before.security_group_id))) for (const t of expand(str(before.security_group_id)!, egress, before, 'vpc')) revokeRule(t);
            else skip(`security group ${str(before.security_group_id) ?? '?'} is not in the snapshot`);
          }
          if (after && (creating || updating)) {
            const gid = groupRef(address, after.security_group_id, unknown(u, 'security_group_id'), 'security_group_id');
            const ref = after.referenced_security_group_id !== undefined || unknown(u, 'referenced_security_group_id') ? groupRef(address, after.referenced_security_group_id, unknown(u, 'referenced_security_group_id'), 'referenced_security_group_id') : undefined;
            if (unknown(u, 'cidr_ipv4', 'prefix_list_id', 'from_port', 'to_port', 'ip_protocol')) skip('depends on values known only after apply');
            else if (!gid) skip(unknown(u, 'security_group_id') ? 'the security group is known only after apply and is not one this plan creates' : `security group ${str(after.security_group_id) ?? '?'} is not in the snapshot`);
            else if (!knownGroup(gid)) skip(`security group ${gid} is not in the snapshot`);
            else if (unknown(u, 'referenced_security_group_id') && !ref) skip('the source security group is known only after apply');
            else for (const t of expand(gid, egress, { ...after, ...(ref ? { referenced_security_group_id: ref } : {}) }, 'vpc')) addRule(t);
          }
          break;
        }
        case 'aws_security_group_rule': {
          const egressOf = (o: Obj) => str(o.type) === 'egress';
          if (before && (removing || updating)) {
            if (groupIn(str(before.security_group_id))) for (const t of expand(str(before.security_group_id)!, egressOf(before), before, 'legacy')) revokeRule(t);
            else skip(`security group ${str(before.security_group_id) ?? '?'} is not in the snapshot`);
          }
          if (after && (creating || updating)) {
            const gid = groupRef(address, after.security_group_id, unknown(u, 'security_group_id'), 'security_group_id');
            const src = unknown(u, 'source_security_group_id') ? groupRef(address, undefined, true, 'source_security_group_id') : undefined;
            if (unknown(u, 'cidr_blocks', 'prefix_list_ids', 'from_port', 'to_port', 'protocol')) skip('depends on values known only after apply');
            else if (!gid) skip(unknown(u, 'security_group_id') ? 'the security group is known only after apply and is not one this plan creates' : `security group ${str(after.security_group_id) ?? '?'} is not in the snapshot`);
            else if (!knownGroup(gid)) skip(`security group ${gid} is not in the snapshot`);
            else if (unknown(u, 'source_security_group_id') && !src) skip('the source security group is known only after apply');
            else for (const t of expand(gid, egressOf(after), { ...after, ...(src ? { source_security_group_id: src } : {}) }, 'legacy')) addRule(t);
          }
          break;
        }
        case 'aws_security_group':
        case 'aws_default_security_group': {
          const placeholder = created.get(address);
          if (placeholder && after) {
            res.changes.push({ kind: 'create-sg', groupId: placeholder, name: str(after.name) && !unknown(u, 'name') ? str(after.name)! : address, ...(str(after.vpc_id) && !unknown(u, 'vpc_id') ? { vpcId: str(after.vpc_id)! } : {}) });
            const blocks = (k: 'ingress' | 'egress') => list(after[k]).filter(isObj);
            const unk = isObj(u) ? u : {};
            for (const k of ['ingress', 'egress'] as const) {
              blocks(k).forEach((r, i) => {
                const ru = Array.isArray(unk[k]) ? (unk[k] as unknown[])[i] : unk[k];
                if (unknown(ru, 'cidr_blocks', 'security_groups', 'prefix_list_ids', 'from_port', 'to_port', 'protocol')) skip(`${k} rule ${i + 1} depends on values known only after apply`);
                else for (const t of expand(placeholder, k === 'egress', r, 'inline')) addRule(t);
              });
            }
            if (unknown(u, 'ingress', 'egress') && !blocks('ingress').length && !blocks('egress').length) skip('inline rules depend on values known only after apply');
            break;
          }
          const id = str(before?.id) ?? str(after?.id);
          if (!id || unknown(u, 'id') || !groupIn(id)) {
            skip(`security group ${id ?? '?'} is not in the snapshot`);
            break;
          }
          const rules = (o: Obj | undefined) => (o ? [...list(o.ingress).filter(isObj).flatMap((r) => expand(id, false, r, 'inline')), ...list(o.egress).filter(isObj).flatMap((r) => expand(id, true, r, 'inline'))] : []);
          if (removing && !creating) {
            for (const r of rulesOf(id)) res.changes.push({ kind: 'revoke-sg-rule', ruleId: r.id });
            break;
          }
          if (unknown(u, 'ingress', 'egress')) {
            skip('inline rules depend on values known only after apply');
            break;
          }
          // Inline blocks are only authoritative when the configuration sets them.
          const b = rules(before);
          const a = rules(after);
          const bk = new Map(b.map((t) => [ruleKey(t), t]));
          const ak = new Map(a.map((t) => [ruleKey(t), t]));
          for (const [k, t] of bk) if (!ak.has(k)) revokeRule(t);
          for (const [k, t] of ak) if (!bk.has(k)) addRule(t);
          break;
        }
        case 'aws_network_acl_rule': {
          const entry = (o: Obj) => ({ naclId: str(o.network_acl_id), egress: o.egress === true, ruleNumber: num(o.rule_number) });
          if (before && (removing || updating)) {
            const e = entry(before);
            if (e.naclId && model.nacls.has(e.naclId) && e.ruleNumber !== undefined) res.changes.push({ kind: 'remove-nacl-entry', naclId: e.naclId, egress: e.egress, ruleNumber: e.ruleNumber });
            else skip(`network ACL ${e.naclId ?? '?'} is not in the snapshot`);
          }
          if (after && (creating || updating)) {
            const e = entry(after);
            if (unknown(u, 'network_acl_id', 'cidr_block', 'rule_number')) skip('depends on values known only after apply');
            else if (!e.naclId || !model.nacls.has(e.naclId)) skip(`network ACL ${e.naclId ?? '?'} is not in the snapshot`);
            else if (!str(after.cidr_block)) skip('IPv6 network ACL rules are not analysed');
            else {
              const protocol = tfProtocol(after.protocol);
              res.changes.push({ kind: 'add-nacl-entry', naclId: e.naclId, egress: e.egress, ruleNumber: e.ruleNumber!, action: str(after.rule_action) === 'deny' ? 'deny' : 'allow', protocol, cidr: str(after.cidr_block)!, ...(hasPorts(protocol) ? { fromPort: num(after.from_port) ?? 0, toPort: num(after.to_port) ?? 65535 } : {}) });
            }
          }
          break;
        }
        case 'aws_network_acl':
        case 'aws_default_network_acl': {
          const id = str(before?.id) ?? str(after?.id);
          if (!id || !model.nacls.has(id)) {
            skip(creating && !before ? 'new network ACL: checked once it is associated with a subnet in the snapshot' : `network ACL ${id ?? '?'} is not in the snapshot`);
            break;
          }
          if (removing && !creating) {
            skip('deleting a network ACL moves its subnets to the default ACL, which is not modelled here');
            break;
          }
          if (unknown(u, 'ingress', 'egress')) {
            skip('inline rules depend on values known only after apply');
            break;
          }
          const entries = (o: Obj | undefined) => {
            const m = new Map<string, Obj & { egress: boolean }>();
            for (const [k, eg] of [['ingress', false], ['egress', true]] as const) for (const r of list(o?.[k]).filter(isObj)) m.set(`${eg}|${num(r.rule_no)}`, { ...r, egress: eg });
            return m;
          };
          const b = entries(before);
          const a = entries(after);
          for (const [k, r] of b) if (!a.has(k) || JSON.stringify(a.get(k)) !== JSON.stringify(r)) res.changes.push({ kind: 'remove-nacl-entry', naclId: id, egress: r.egress, ruleNumber: num(r.rule_no)! });
          for (const [k, r] of a) {
            if (b.has(k) && JSON.stringify(b.get(k)) === JSON.stringify(r)) continue;
            if (!str(r.cidr_block)) {
              skip(`IPv6 rule ${num(r.rule_no)} is not analysed`);
              continue;
            }
            const protocol = tfProtocol(r.protocol);
            res.changes.push({ kind: 'add-nacl-entry', naclId: id, egress: r.egress, ruleNumber: num(r.rule_no)!, action: str(r.action) === 'deny' ? 'deny' : 'allow', protocol, cidr: str(r.cidr_block)!, ...(hasPorts(protocol) ? { fromPort: num(r.from_port) ?? 0, toPort: num(r.to_port) ?? 65535 } : {}) });
          }
          break;
        }
        case 'aws_route': {
          const dest = (o: Obj) => str(o.destination_cidr_block) ?? str(o.destination_prefix_list_id);
          const target = (o: Obj) => str(o.gateway_id) ?? str(o.nat_gateway_id) ?? str(o.transit_gateway_id) ?? str(o.vpc_peering_connection_id) ?? str(o.network_interface_id) ?? str(o.vpc_endpoint_id) ?? str(o.egress_only_gateway_id);
          if (before && (removing || updating)) {
            const rt = str(before.route_table_id);
            if (rt && model.routeTables.has(rt) && dest(before)) res.changes.push({ kind: 'remove-route', routeTableId: rt, destination: dest(before)! });
            else if (str(before.destination_ipv6_cidr_block)) skip('IPv6 routes are not analysed');
            else skip(`route table ${rt ?? '?'} is not in the snapshot`);
          }
          if (after && (creating || updating)) {
            const rt = str(after.route_table_id);
            if (unknown(u, 'route_table_id', 'destination_cidr_block', 'gateway_id', 'nat_gateway_id', 'transit_gateway_id', 'vpc_peering_connection_id', 'network_interface_id', 'vpc_endpoint_id')) skip('depends on values known only after apply, such as a gateway created in this plan');
            else if (!rt || !model.routeTables.has(rt)) skip(`route table ${rt ?? '?'} is not in the snapshot`);
            else if (!dest(after)) skip('IPv6 routes are not analysed');
            else if (!target(after)) skip('the route target is not one Pinhole models');
            else res.changes.push({ kind: 'add-route', routeTableId: rt, destination: dest(after)!, targetId: target(after)! });
          }
          break;
        }
        case 'aws_route_table':
        case 'aws_default_route_table': {
          const id = str(before?.id) ?? str(after?.id);
          if (!id || !model.routeTables.has(id)) {
            skip(creating && !before ? 'new route table: checked once it is associated with a subnet in the snapshot' : `route table ${id ?? '?'} is not in the snapshot`);
            break;
          }
          if (removing && !creating) break;
          if (unknown(u, 'route')) {
            skip('inline routes depend on values known only after apply');
            break;
          }
          const routes = (o: Obj | undefined) => {
            const m = new Map<string, string>();
            for (const r of list(o?.route).filter(isObj)) {
              const d = str(r.cidr_block) ?? str(r.destination_prefix_list_id);
              const t = str(r.gateway_id) ?? str(r.nat_gateway_id) ?? str(r.transit_gateway_id) ?? str(r.vpc_peering_connection_id) ?? str(r.network_interface_id) ?? str(r.vpc_endpoint_id) ?? str(r.egress_only_gateway_id);
              if (d && t) m.set(d, t);
            }
            return m;
          };
          const b = routes(before);
          const a = routes(after);
          for (const [d, t] of b) if (a.get(d) !== t) res.changes.push({ kind: 'remove-route', routeTableId: id, destination: d });
          for (const [d, t] of a) if (b.get(d) !== t) res.changes.push({ kind: 'add-route', routeTableId: id, destination: d, targetId: t });
          break;
        }
        case 'aws_network_interface_sg_attachment': {
          const eni = str((after ?? before)?.network_interface_id);
          const sg = creating ? groupRef(address, after?.security_group_id, unknown(u, 'security_group_id'), 'security_group_id') : str(before?.security_group_id);
          if (unknown(u, 'network_interface_id')) skip('the interface is known only after apply');
          else if (!eni || !model.enis.has(eni)) skip(`interface ${eni ?? '?'} is not in the snapshot`);
          else if (!sg || !knownGroup(sg)) skip(sg ? `security group ${sg} is not in the snapshot` : 'the security group is known only after apply and is not one this plan creates');
          else res.changes.push({ kind: creating ? 'attach-sg' : 'detach-sg', eniId: eni, groupId: sg });
          break;
        }
        case 'aws_network_interface':
        case 'aws_instance': {
          const id = str(before?.id);
          const eni = type === 'aws_instance' ? (id ? eniOfInstance(id) : undefined) : id;
          if (!before || !after || !updating || !eni || !model.enis.has(eni)) {
            skip(creating ? `new ${type === 'aws_instance' ? 'instance' : 'interface'}: its address and security groups are known only after apply` : removing ? 'removal is not analysed; exposure through it ends' : `${id ?? '?'} is not in the snapshot`);
            break;
          }
          const key = type === 'aws_instance' ? 'vpc_security_group_ids' : 'security_groups';
          const b = new Set(strs(before[key]));
          let a = new Set(strs(after[key]));
          if (unknown(u, key)) {
            // Known elements stay; unknown ones must be groups this plan creates.
            const refs = [...new Set(refsOf(config, address, key).map(placeholderFor).filter((x): x is string => !!x))];
            const unknownCount = isObj(u) && Array.isArray(u[key]) ? (u[key] as unknown[]).filter((x) => x === true).length : -1;
            if (!refs.length || (unknownCount >= 0 && refs.length !== unknownCount)) {
              skip('security groups depend on values known only after apply');
              break;
            }
            a = new Set([...a, ...refs]);
          }
          for (const g of a) if (!b.has(g)) (knownGroup(g) ? res.changes.push({ kind: 'attach-sg', eniId: eni, groupId: g }) : skip(`security group ${g} is not in the snapshot`));
          for (const g of b) if (!a.has(g)) res.changes.push({ kind: 'detach-sg', eniId: eni, groupId: g });
          if (type === 'aws_instance' && before.associate_public_ip_address !== after.associate_public_ip_address) skip('changing associate_public_ip_address replaces the instance; check the new one after apply');
          break;
        }
        case 'aws_eip_association': {
          if (!after || !creating) {
            if (before && removing) {
              const eni = str(before.network_interface_id) ?? (str(before.instance_id) ? eniOfInstance(str(before.instance_id)!) : undefined);
              const ip = str(before.public_ip);
              if (eni && ip && model.enis.get(eni)?.publicAddresses.some((p) => p.publicIp === ip)) res.changes.push({ kind: 'remove-public-ip', eniId: eni, publicIp: ip });
              else skip('the Elastic IP or interface is not in the snapshot');
            }
            break;
          }
          if (unknown(u, 'network_interface_id', 'instance_id')) {
            skip('the interface is known only after apply');
            break;
          }
          const eni = str(after.network_interface_id) ?? (str(after.instance_id) ? eniOfInstance(str(after.instance_id)!) : undefined);
          if (!eni || !model.enis.has(eni)) skip('the interface or instance is not in the snapshot');
          else res.changes.push({ kind: 'add-public-ip', eniId: eni, publicIp: str(after.public_ip) && !unknown(u, 'public_ip') ? str(after.public_ip)! : 'new Elastic IP', elastic: true });
          break;
        }
        default:
          skip(`${type} changes are not analysed`);
      }
    } catch (e) {
      // Plans are input from outside: a malformed value skips this resource, with the reason.
      skip(e instanceof ChangeError || e instanceof Error ? e.message : String(e));
      res.changes = [];
    }

    // Everything mapped must pass the same checks as a hand-written change list.
    try {
      assertChanges(res.changes);
    } catch (e) {
      res.skipped.push(`not analysed: ${(e as Error).message}`);
      res.changes = [];
    }
    if (!res.changes.length && res.skipped.length) result.skipped.push(...res.skipped.map((reason) => ({ address, type, reason })));
    else if (res.changes.length || res.skipped.length) {
      result.resources.push(res);
      result.changes.push(...res.changes);
      result.skipped.push(...res.skipped.map((reason) => ({ address, type, reason })));
    }
  }
  return result;
}
