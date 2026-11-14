/**
 * What-if: apply proposed changes to a model, compare analyses before and
 * after, and print the AWS CLI commands that would make the same changes.
 *
 * Changes never touch the original model. applyChanges copies only the
 * containers it modifies, so the rest of the model is shared and cheap.
 * The CLI commands are text for a person to review and run; Pinhole never
 * runs them and never calls a write API.
 */
import type { ExposureFinding, ExposureReport } from './exposure.js';
import type { AttackChain, BlastReport } from './blast.js';
import { INTERNET, parseCidr, RangeSet } from './ipv4.js';
import { hasPorts, normalizeProtocol, protocolName } from './packet.js';
import { assessPorts, compareSeverity } from './risk.js';
import type { Severity } from './risk.js';
import type { Eni, Nacl, NaclEntry, NetworkModel, PortRange, RouteTable, SecurityGroup, SgRule } from './types.js';

export type Change =
  | { kind: 'revoke-sg-rule'; ruleId: string }
  | { kind: 'edit-sg-rule'; ruleId: string; cidr?: string; fromPort?: number; toPort?: number }
  | { kind: 'add-sg-rule'; groupId: string; egress: boolean; protocol: string; fromPort?: number; toPort?: number; cidr?: string; referencedGroupId?: string; description?: string }
  | { kind: 'add-nacl-entry'; naclId: string; egress: boolean; ruleNumber: number; action: 'allow' | 'deny'; protocol: string; cidr: string; fromPort?: number; toPort?: number }
  | { kind: 'remove-nacl-entry'; naclId: string; egress: boolean; ruleNumber: number }
  | { kind: 'remove-route'; routeTableId: string; destination: string }
  | { kind: 'remove-public-ip'; eniId: string; publicIp: string }
  | { kind: 'detach-sg'; eniId: string; groupId: string };

export class ChangeError extends Error {}

function findRule(model: NetworkModel, ruleId: string): { group: SecurityGroup; rule: SgRule } {
  for (const group of model.securityGroups.values()) {
    const rule = group.ingress.find((r) => r.id === ruleId) ?? group.egress.find((r) => r.id === ruleId);
    if (rule) return { group, rule };
  }
  throw new ChangeError(`Security group rule ${ruleId} is not in the snapshot.`);
}

let added = 0;

/** A new model with the changes applied, in order. The input is not modified. */
export function applyChanges(model: NetworkModel, changes: Change[]): NetworkModel {
  const out: NetworkModel = { ...model };
  const owned = new Set<string>();
  const groups = () => (owned.has('sg') ? out.securityGroups : (owned.add('sg'), (out.securityGroups = new Map(out.securityGroups))));
  const nacls = () => (owned.has('nacl') ? out.nacls : (owned.add('nacl'), (out.nacls = new Map(out.nacls))));
  const tables = () => (owned.has('rt') ? out.routeTables : (owned.add('rt'), (out.routeTables = new Map(out.routeTables))));
  const enis = () => (owned.has('eni') ? out.enis : (owned.add('eni'), (out.enis = new Map(out.enis))));
  const setGroup = (g: SecurityGroup) => groups().set(g.id, g);

  for (const c of changes) {
    switch (c.kind) {
      case 'revoke-sg-rule': {
        const { group } = findRule(out, c.ruleId);
        setGroup({ ...group, ingress: group.ingress.filter((r) => r.id !== c.ruleId), egress: group.egress.filter((r) => r.id !== c.ruleId) });
        break;
      }
      case 'edit-sg-rule': {
        const { group, rule } = findRule(out, c.ruleId);
        const next: SgRule = { ...rule };
        if (c.cidr !== undefined) {
          delete next.prefixListId;
          delete next.referencedGroupId;
          next.cidr = parseCidr(c.cidr);
        }
        if (c.fromPort !== undefined) next.fromPort = c.fromPort;
        if (c.toPort !== undefined) next.toPort = c.toPort;
        if (next.fromPort !== undefined && next.toPort !== undefined && next.fromPort > next.toPort) throw new ChangeError(`Port range ${next.fromPort}-${next.toPort} is empty.`);
        const swap = (list: SgRule[]) => list.map((r) => (r.id === rule.id ? next : r));
        setGroup({ ...group, ingress: swap(group.ingress), egress: swap(group.egress) });
        break;
      }
      case 'add-sg-rule': {
        const group = out.securityGroups.get(c.groupId);
        if (!group) throw new ChangeError(`Security group ${c.groupId} is not in the snapshot.`);
        if (!c.cidr && !c.referencedGroupId) throw new ChangeError('A new rule needs a CIDR or a referenced security group.');
        const protocol = normalizeProtocol(c.protocol);
        const rule: SgRule = {
          id: `sgr-new-${++added}`,
          groupId: c.groupId,
          egress: c.egress,
          protocol,
          ...(hasPorts(protocol) ? { fromPort: c.fromPort ?? 0, toPort: c.toPort ?? c.fromPort ?? 65535 } : {}),
          ...(c.cidr ? { cidr: parseCidr(c.cidr) } : {}),
          ...(c.referencedGroupId ? { referencedGroupId: c.referencedGroupId } : {}),
          ...(c.description ? { description: c.description } : {}),
        };
        setGroup(c.egress ? { ...group, egress: [...group.egress, rule] } : { ...group, ingress: [...group.ingress, rule] });
        break;
      }
      case 'add-nacl-entry':
      case 'remove-nacl-entry': {
        const nacl = out.nacls.get(c.naclId);
        if (!nacl) throw new ChangeError(`Network ACL ${c.naclId} is not in the snapshot.`);
        let entries = nacl.entries.filter((e) => !(e.egress === c.egress && e.ruleNumber === c.ruleNumber));
        if (c.kind === 'remove-nacl-entry') {
          if (entries.length === nacl.entries.length) throw new ChangeError(`${c.naclId} has no ${c.egress ? 'outbound' : 'inbound'} rule ${c.ruleNumber}.`);
        } else {
          if (entries.length !== nacl.entries.length) throw new ChangeError(`${c.naclId} already has ${c.egress ? 'outbound' : 'inbound'} rule ${c.ruleNumber}.`);
          const protocol = normalizeProtocol(c.protocol);
          const entry: NaclEntry = {
            ruleNumber: c.ruleNumber,
            egress: c.egress,
            action: c.action,
            protocol,
            cidr: parseCidr(c.cidr),
            ...(hasPorts(protocol) ? { portRange: { from: c.fromPort ?? 0, to: c.toPort ?? c.fromPort ?? 65535 } } : {}),
          };
          entries = [...entries, entry];
        }
        entries.sort((a, b) => a.ruleNumber - b.ruleNumber);
        nacls().set(nacl.id, { ...nacl, entries } satisfies Nacl);
        break;
      }
      case 'remove-route': {
        const rt = out.routeTables.get(c.routeTableId);
        if (!rt) throw new ChangeError(`Route table ${c.routeTableId} is not in the snapshot.`);
        const routes = rt.routes.filter((r) => (r.destination?.text ?? r.destinationPrefixListId) !== c.destination);
        if (routes.length === rt.routes.length) throw new ChangeError(`${c.routeTableId} has no route to ${c.destination}.`);
        tables().set(rt.id, { ...rt, routes } satisfies RouteTable);
        break;
      }
      case 'remove-public-ip':
      case 'detach-sg': {
        const eni = out.enis.get(c.eniId);
        if (!eni) throw new ChangeError(`Interface ${c.eniId} is not in the snapshot.`);
        const next: Eni =
          c.kind === 'remove-public-ip'
            ? { ...eni, publicAddresses: eni.publicAddresses.filter((p) => p.publicIp !== c.publicIp) }
            : { ...eni, groupIds: eni.groupIds.filter((g) => g !== c.groupId) };
        enis().set(eni.id, next);
        break;
      }
    }
  }
  return out;
}

// ------------------------------------------------------------------ text

const portsText = (p: string, from?: number, to?: number) => (hasPorts(normalizeProtocol(p)) ? ` ${from === to ? from : `${from}-${to}`}` : '');

export function describeChange(model: NetworkModel, c: Change): string {
  switch (c.kind) {
    case 'revoke-sg-rule': {
      const { group, rule } = findRule(model, c.ruleId);
      return `Remove ${rule.egress ? 'outbound' : 'inbound'} rule ${rule.id} (${ruleText(rule)}) from ${group.id} (${group.name})`;
    }
    case 'edit-sg-rule': {
      const { group, rule } = findRule(model, c.ruleId);
      const what = [c.cidr !== undefined ? `source ${c.cidr}` : '', c.fromPort !== undefined || c.toPort !== undefined ? `ports ${c.fromPort ?? rule.fromPort}-${c.toPort ?? rule.toPort}` : ''].filter(Boolean).join(', ');
      return `Change rule ${rule.id} in ${group.id} (${group.name}) to ${what}`;
    }
    case 'add-sg-rule':
      return `Add ${c.egress ? 'outbound' : 'inbound'} rule to ${c.groupId}: ${c.protocol}${portsText(c.protocol, c.fromPort, c.toPort ?? c.fromPort)} ${c.egress ? 'to' : 'from'} ${c.cidr ?? c.referencedGroupId}`;
    case 'add-nacl-entry':
      return `Add ${c.egress ? 'outbound' : 'inbound'} rule ${c.ruleNumber} to ${c.naclId}: ${c.action} ${c.protocol}${portsText(c.protocol, c.fromPort, c.toPort ?? c.fromPort)} ${c.egress ? 'to' : 'from'} ${c.cidr}`;
    case 'remove-nacl-entry':
      return `Remove ${c.egress ? 'outbound' : 'inbound'} rule ${c.ruleNumber} from ${c.naclId}`;
    case 'remove-route':
      return `Remove the route to ${c.destination} from ${c.routeTableId}`;
    case 'remove-public-ip':
      return `Remove public IP ${c.publicIp} from ${c.eniId}`;
    case 'detach-sg':
      return `Remove security group ${c.groupId} from ${c.eniId}`;
  }
}

export function ruleText(r: SgRule): string {
  const proto = protocolName(r.protocol);
  const ports = hasPorts(r.protocol) && r.fromPort !== undefined && r.fromPort !== -1 ? (r.fromPort === r.toPort ? `/${r.fromPort}` : `/${r.fromPort}-${r.toPort}`) : '';
  const peer = r.cidr?.text ?? r.prefixListId ?? r.referencedGroupId ?? r.ipv6CidrText ?? '?';
  return `${proto === 'all' ? 'all traffic' : proto}${ports} ${r.egress ? 'to' : 'from'} ${peer}`;
}

const q = (s: string) => (/^[A-Za-z0-9_./:@=,+-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);
const protoArg = (p: string) => (p === 'all' || p === '-1' ? '-1' : p);

/**
 * AWS CLI commands for a change. Every command is printed for review; none is
 * run. Removing a public IP needs an association ID that the snapshot does not
 * carry for auto-assigned addresses, so that one points at the console.
 */
export function cliFor(model: NetworkModel, c: Change): string[] {
  const region = model.region ? ` --region ${q(model.region)}` : '';
  switch (c.kind) {
    case 'revoke-sg-rule': {
      const { group, rule } = findRule(model, c.ruleId);
      return [`aws ec2 revoke-security-group-${rule.egress ? 'egress' : 'ingress'}${region} --group-id ${q(group.id)} --security-group-rule-ids ${q(rule.id)}`];
    }
    case 'edit-sg-rule': {
      const { group, rule } = findRule(model, c.ruleId);
      const proto = protocolName(rule.protocol);
      const cidr = c.cidr ?? rule.cidr?.text;
      const from = c.fromPort ?? rule.fromPort ?? -1;
      const to = c.toPort ?? rule.toPort ?? -1;
      const spec = [`IpProtocol=${protoArg(proto)}`, ...(hasPorts(rule.protocol) ? [`FromPort=${from}`, `ToPort=${to}`] : []), ...(cidr ? [`CidrIpv4=${cidr}`] : []), ...(!cidr && rule.referencedGroupId ? [`ReferencedGroupId=${rule.referencedGroupId}`] : []), ...(!cidr && rule.prefixListId ? [`PrefixListId=${rule.prefixListId}`] : []), ...(rule.description ? [`Description=${rule.description}`] : [])].join(',');
      return [`aws ec2 modify-security-group-rules${region} --group-id ${q(group.id)} --security-group-rules ${q(`SecurityGroupRuleId=${rule.id},SecurityGroupRule={${spec}}`)}`];
    }
    case 'add-sg-rule': {
      const proto = protoArg(c.protocol);
      const ports = hasPorts(normalizeProtocol(c.protocol)) ? `,FromPort=${c.fromPort ?? 0},ToPort=${c.toPort ?? c.fromPort ?? 65535}` : '';
      const peer = c.cidr ? `,IpRanges=[{CidrIp=${c.cidr}${c.description ? `,Description=${c.description}` : ''}}]` : `,UserIdGroupPairs=[{GroupId=${c.referencedGroupId}}]`;
      return [`aws ec2 authorize-security-group-${c.egress ? 'egress' : 'ingress'}${region} --group-id ${q(c.groupId)} --ip-permissions ${q(`IpProtocol=${proto}${ports}${peer}`)}`];
    }
    case 'add-nacl-entry': {
      const proto = protoArg(String(normalizeProtocol(c.protocol)));
      const ports = hasPorts(normalizeProtocol(c.protocol)) ? ` --port-range From=${c.fromPort ?? 0},To=${c.toPort ?? c.fromPort ?? 65535}` : '';
      return [`aws ec2 create-network-acl-entry${region} --network-acl-id ${q(c.naclId)} ${c.egress ? '--egress' : '--ingress'} --rule-number ${c.ruleNumber} --protocol ${proto}${ports} --cidr-block ${q(c.cidr)} --rule-action ${c.action}`];
    }
    case 'remove-nacl-entry':
      return [`aws ec2 delete-network-acl-entry${region} --network-acl-id ${q(c.naclId)} ${c.egress ? '--egress' : '--ingress'} --rule-number ${c.ruleNumber}`];
    case 'remove-route': {
      const flag = c.destination.startsWith('pl-') ? '--destination-prefix-list-id' : '--destination-cidr-block';
      return [`aws ec2 delete-route${region} --route-table-id ${q(c.routeTableId)} ${flag} ${q(c.destination)}`];
    }
    case 'remove-public-ip': {
      const eni = model.enis.get(c.eniId);
      const pub = eni?.publicAddresses.find((p) => p.publicIp === c.publicIp);
      return pub?.elastic
        ? [`# Find the association ID, then disassociate the Elastic IP:`, `aws ec2 describe-addresses${region} --public-ips ${q(c.publicIp)} --query 'Addresses[0].AssociationId' --output text`, `aws ec2 disassociate-address${region} --association-id <association-id>`]
        : [`# ${c.publicIp} is an auto-assigned public IP. It is released when the instance stops, or by replacing the interface; there is no single CLI call to remove it.`];
    }
    case 'detach-sg': {
      const eni = model.enis.get(c.eniId);
      const keep = (eni?.groupIds ?? []).filter((g) => g !== c.groupId);
      return keep.length
        ? [`aws ec2 modify-network-interface-attribute${region} --network-interface-id ${q(c.eniId)} --groups ${keep.map(q).join(' ')}`]
        : [`# ${c.eniId} must keep at least one security group; attach a replacement in the same command.`];
    }
  }
}

// ------------------------------------------------------------------ diff

export type DiffStatus = 'closed' | 'opened' | 'narrowed' | 'widened' | 'changed';

export interface ExposureDelta {
  status: DiffStatus;
  resourceId: string;
  resourceName: string;
  protocol: string;
  ports?: PortRange;
  listenerPort?: number;
  severity: Severity;
  /** Internet sources before and after, as CIDRs ("0.0.0.0/0 (every internet address)" for all). */
  before: string[];
  after: string[];
}

export interface ExposureDiff {
  deltas: ExposureDelta[];
  closed: number;
  opened: number;
  /** Chains that exist only before (closed) or only after (opened). */
  chainsClosed: AttackChain[];
  chainsOpened: AttackChain[];
  /**
   * Chains that existed before but were not reported because the internet
   * reached the target directly. The change closed that direct exposure, so
   * the internal route is now the one that matters. Not new access.
   */
  chainsRevealed: AttackChain[];
}

const toSet = (labels: string[]) => (labels.some((l) => l.startsWith('0.0.0.0/0 (')) ? INTERNET : RangeSet.fromCidrs(labels));

interface Seg {
  ports?: PortRange;
  set: RangeSet;
  labels: string[];
  name: string;
}

function index(report: ExposureReport): Map<string, Seg[]> {
  const m = new Map<string, Seg[]>();
  const add = (key: string, s: Seg) => (m.get(key) ?? m.set(key, []).get(key)!).push(s);
  for (const f of report.findings) {
    const key = `${f.resourceId}|${f.protocol}|${f.listener ? f.listener.port : ''}`;
    add(key, { ...(hasPorts(normalizeProtocol(f.protocol)) || f.protocol === 'icmp' ? { ports: f.ports } : {}), set: toSet(f.sourceRanges), labels: f.sourceRanges, name: f.resourceName });
  }
  return m;
}

function bounds(segs: Seg[]): number[] {
  const b = new Set<number>();
  for (const s of segs) if (s.ports) b.add(s.ports.from).add(s.ports.to + 1);
  return [...b].sort((x, y) => x - y);
}

/** What changed between two exposure reports (and, optionally, blast radius reports). */
export function diffExposure(before: ExposureReport, after: ExposureReport, blast?: { before: BlastReport; after: BlastReport }): ExposureDiff {
  const a = index(before);
  const b = index(after);
  const deltas: ExposureDelta[] = [];
  for (const key of new Set([...a.keys(), ...b.keys()])) {
    const [resourceId, protocol, listener] = key.split('|') as [string, string, string];
    const sa = a.get(key) ?? [];
    const sb = b.get(key) ?? [];
    const name = (sa[0] ?? sb[0])!.name;
    const pts = bounds([...sa, ...sb]);
    const segments: { ports?: PortRange }[] = pts.length ? pts.slice(0, -1).map((p, i) => ({ ports: { from: p, to: pts[i + 1]! - 1 } })) : [{}];
    let last: ExposureDelta | undefined;
    for (const seg of segments) {
      const pick = (list: Seg[]) => list.find((s) => !seg.ports || (s.ports && s.ports.from <= seg.ports.from && s.ports.to >= seg.ports.to));
      const x = pick(sa);
      const y = pick(sb);
      let status: DiffStatus | undefined;
      if (x && !y) status = 'closed';
      else if (!x && y) status = 'opened';
      else if (x && y && !x.set.equals(y.set)) {
        const lost = !x.set.subtract(y.set).isEmpty();
        const gained = !y.set.subtract(x.set).isEmpty();
        status = lost && !gained ? 'narrowed' : gained && !lost ? 'widened' : 'changed';
      }
      if (!status) {
        last = undefined;
        continue;
      }
      const beforeLabels = x?.labels ?? [];
      const afterLabels = y?.labels ?? [];
      if (last && last.status === status && last.ports && seg.ports && last.ports.to + 1 === seg.ports.from && last.before.join() === beforeLabels.join() && last.after.join() === afterLabels.join()) {
        last.ports = { from: last.ports.from, to: seg.ports.to };
        last.severity = assessPorts(protocol, last.ports).severity;
        continue;
      }
      last = {
        status,
        resourceId,
        resourceName: name,
        protocol,
        ...(seg.ports ? { ports: seg.ports } : {}),
        ...(listener ? { listenerPort: Number(listener) } : {}),
        severity: assessPorts(protocol, seg.ports).severity,
        before: beforeLabels,
        after: afterLabels,
      };
      deltas.push(last);
    }
  }
  deltas.sort((x, y) => compareSeverity(x.severity, y.severity) || x.resourceName.localeCompare(y.resourceName));
  const ids = (r: BlastReport) => new Set(r.chains.map((c) => c.id));
  const chainsClosed = blast ? blast.before.chains.filter((c) => !ids(blast.after).has(c.id)) : [];
  const hiddenBefore = new Set(blast?.before.hidden ?? []);
  const fresh = blast ? blast.after.chains.filter((c) => !ids(blast.before).has(c.id)) : [];
  const chainsOpened = fresh.filter((c) => !hiddenBefore.has(c.id));
  const chainsRevealed = fresh.filter((c) => hiddenBefore.has(c.id));
  return { deltas, closed: deltas.filter((d) => d.status === 'closed').length, opened: deltas.filter((d) => d.status === 'opened').length, chainsClosed, chainsOpened, chainsRevealed };
}

