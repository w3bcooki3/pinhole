/**
 * Rule hygiene: security group and network ACL rules that are unused, can
 * never take effect, or allow far more than they need to. These are
 * configuration findings: they say nothing about whether the internet can
 * reach anything today (that is the exposure report), but they are what turns
 * a small mistake elsewhere into a large one.
 */
import { hasPorts, protocolName } from './packet.js';
import { assessPorts, categorize, compareSeverity } from './risk.js';
import type { Severity } from './risk.js';
import { ruleText, shellQuote } from './whatif.js';
import type { Change } from './whatif.js';
import type { ExposureReport } from './exposure.js';
import { PROTO_ALL } from './types.js';
import type { Cidr, NaclEntry, NetworkModel, SgRule } from './types.js';

export type HygieneCode =
  | 'unused-security-group'
  | 'redundant-sg-rule'
  | 'shadowed-nacl-entry'
  | 'open-to-world'
  | 'broad-internal-source'
  | 'all-ports'
  | 'stale-group-reference';

export interface HygieneFinding {
  code: HygieneCode;
  severity: Severity;
  resourceId: string;
  /** The rule this is about: sgr- ID, or "acl-x#ingress#120". */
  ruleId?: string;
  title: string;
  detail: string;
  /** Changes that would resolve it, when there is an obvious one. */
  fix?: Change[];
  /** Commands for fixes that are not modelled changes (deleting a group). */
  cli?: string[];
  /** The rule already lets the internet in: it is behind a finding in the exposure report. */
  inExposure?: boolean;
}

const containsCidr = (outer: Cidr, inner: Cidr) => outer.start <= inner.start && outer.end >= inner.end;
const portsOf = (r: { protocol: string; fromPort?: number; toPort?: number }) =>
  r.protocol === PROTO_ALL || !hasPorts(r.protocol) || r.fromPort === undefined || r.fromPort === -1 ? { from: 0, to: 65535 } : { from: r.fromPort, to: r.toPort ?? r.fromPort };

/** True when rule `b` allows everything rule `a` allows. */
function sgCovers(b: SgRule, a: SgRule): boolean {
  if (b.protocol !== PROTO_ALL && b.protocol !== a.protocol) return false;
  const pa = portsOf(a);
  const pb = portsOf(b);
  if (pb.from > pa.from || pb.to < pa.to) return false;
  if (a.cidr && b.cidr) return containsCidr(b.cidr, a.cidr);
  if (a.referencedGroupId) return b.referencedGroupId === a.referencedGroupId;
  if (a.prefixListId) return b.prefixListId === a.prefixListId;
  return false;
}

function naclCovers(b: NaclEntry, a: NaclEntry): boolean {
  if (!a.cidr || !b.cidr) return false;
  if (b.protocol !== PROTO_ALL && b.protocol !== a.protocol) return false;
  if (b.protocol !== PROTO_ALL && hasPorts(b.protocol)) {
    const pa = a.portRange ?? { from: 0, to: 65535 };
    const pb = b.portRange ?? { from: 0, to: 65535 };
    if (pb.from > pa.from || pb.to < pa.to) return false;
  }
  return containsCidr(b.cidr, a.cidr);
}

const WORLD = (c?: Cidr) => !!c && c.start === 0 && c.end === 0xffffffff;
const PRIVATE = [
  { start: 0x0a000000, end: 0x0affffff },
  { start: 0xac100000, end: 0xac1fffff },
  { start: 0xc0a80000, end: 0xc0a8ffff },
];

export function analyzeHygiene(model: NetworkModel, exposure?: ExposureReport): HygieneFinding[] {
  const out: HygieneFinding[] = [];
  const exposing = new Set(exposure?.findings.flatMap((f) => f.trace.filter((h) => h.stage === 'dest-sg-ingress').flatMap((h) => h.ruleIds ?? [])) ?? []);
  const region = model.region ? ` --region ${shellQuote(model.region)}` : '';

  const used = new Set<string>();
  for (const e of model.enis.values()) e.groupIds.forEach((g) => used.add(g));
  for (const lb of model.loadBalancers.values()) lb.securityGroupIds.forEach((g) => used.add(g));
  // A group referenced by another group's rule is in use as a label even if nothing is attached.
  const referenced = new Set<string>();
  for (const g of model.securityGroups.values()) for (const r of [...g.ingress, ...g.egress]) if (r.referencedGroupId) referenced.add(r.referencedGroupId);

  for (const g of model.securityGroups.values()) {
    if (!used.has(g.id) && g.name !== 'default') {
      out.push({
        code: 'unused-security-group',
        severity: 'info',
        resourceId: g.id,
        title: `${g.id} (${g.name}) is not attached to anything`,
        detail: `No interface or load balancer in this snapshot uses it${referenced.has(g.id) ? ', although another group\'s rules refer to it' : ''}. Unused groups with open rules are a trap: attaching one by mistake opens everything it allows.`,
        ...(referenced.has(g.id) ? {} : { cli: [`aws ec2 delete-security-group${region} --group-id ${shellQuote(g.id)}`] }),
      });
    }

    for (const dir of ['ingress', 'egress'] as const) {
      const rules = g[dir];
      for (const [i, a] of rules.entries()) {
        const by = rules.find((b, j) => j !== i && sgCovers(b, a) && (!sgCovers(a, b) || j < i));
        if (by) {
          out.push({
            code: 'redundant-sg-rule',
            severity: 'low',
            resourceId: g.id,
            ruleId: a.id,
            title: `${a.id} adds nothing to ${g.id}`,
            detail: `${a.id} (${ruleText(a)}) is fully covered by ${by.id} (${ruleText(by)}). Removing it changes nothing today, and keeps the group readable.`,
            fix: [{ kind: 'revoke-sg-rule', ruleId: a.id }],
          });
        }
      }
    }

    for (const r of [...g.ingress, ...g.egress]) {
      if (r.referencedGroupId && !model.securityGroups.has(r.referencedGroupId) && !r.referencedPeeringConnectionId) {
        out.push({
          code: 'stale-group-reference',
          severity: 'low',
          resourceId: g.id,
          ruleId: r.id,
          title: `${r.id} refers to ${r.referencedGroupId}, which is not in this snapshot`,
          detail: `The referenced group was deleted, or is in another VPC or account. A rule to a deleted group matches nothing; if that is the case, remove it.`,
          fix: [{ kind: 'revoke-sg-rule', ruleId: r.id }],
        });
      }
    }

    if (!used.has(g.id) && g.name !== 'default') continue;
    for (const r of g.ingress) {
      const ports = portsOf(r);
      const risk = assessPorts(protocolName(r.protocol), r.protocol === PROTO_ALL ? undefined : ports);
      const cat = categorize(protocolName(r.protocol), r.protocol === PROTO_ALL ? undefined : ports);
      const allPorts = r.protocol === PROTO_ALL || (hasPorts(r.protocol) && ports.from === 0 && ports.to === 65535);
      if (allPorts && r.cidr && !r.referencedGroupId) {
        const world = WORLD(r.cidr);
        out.push({
          code: 'all-ports',
          severity: world ? 'critical' : r.cidr.prefixLength <= 16 ? 'high' : 'medium',
          resourceId: g.id,
          ruleId: r.id,
          title: `${r.id} allows every port from ${r.cidr.text}`,
          detail: `${ruleText(r)} in ${g.id} (${g.name}). Allow only the ports the service listens on.`,
        });
        continue;
      }
      if (WORLD(r.cidr) && cat !== 'web') {
        out.push({
          code: 'open-to-world',
          severity: risk.severity === 'critical' ? 'high' : 'medium',
          resourceId: g.id,
          ruleId: r.id,
          title: `${r.id} allows ${protocolName(r.protocol)}/${ports.from === ports.to ? ports.from : `${ports.from}-${ports.to}`} from 0.0.0.0/0`,
          detail: `${ruleText(r)} in ${g.id} (${g.name}). Whether the internet reaches it today depends on public IPs and routes; the rule itself allows any address.${risk.reasons.length ? ` Covers ${risk.reasons.join(', ')}.` : ''}`,
        });
        continue;
      }
      const internal = r.cidr && !WORLD(r.cidr) && PRIVATE.some((p) => r.cidr!.start <= p.end && r.cidr!.end >= p.start) && r.cidr.prefixLength <= 16;
      if (internal && (cat === 'admin' || cat === 'data' || cat === 'control')) {
        out.push({
          code: 'broad-internal-source',
          severity: cat === 'data' || cat === 'admin' ? 'medium' : 'low',
          resourceId: g.id,
          ruleId: r.id,
          title: `${r.id} lets all of ${r.cidr!.text} reach ${cat === 'data' ? 'a data store' : cat === 'admin' ? 'remote administration' : 'a control plane'}`,
          detail: `${ruleText(r)} in ${g.id} (${g.name}). Any compromised host in that range can connect. Reference the security group of the clients that need it instead of a CIDR.`,
        });
      }
    }

  }

  for (const n of model.nacls.values()) {
    for (const egress of [false, true]) {
      const entries = n.entries.filter((e) => e.egress === egress && e.ruleNumber !== 32767).sort((a, b) => a.ruleNumber - b.ruleNumber);
      for (const [i, a] of entries.entries()) {
        const by = entries.slice(0, i).find((b) => naclCovers(b, a));
        if (!by) continue;
        const same = by.action === a.action;
        out.push({
          code: 'shadowed-nacl-entry',
          severity: same ? 'low' : 'medium',
          resourceId: n.id,
          ruleId: `${n.id}#${egress ? 'egress' : 'ingress'}#${a.ruleNumber}`,
          title: `${n.id} ${egress ? 'outbound' : 'inbound'} rule ${a.ruleNumber} can never match`,
          detail: `Rule ${by.ruleNumber} (${by.action}) comes first and covers everything rule ${a.ruleNumber} (${a.action}) does.${same ? ' Removing it changes nothing.' : ` Rule ${a.ruleNumber} looks like it was meant to ${a.action} this traffic, but it is ${by.action === 'allow' ? 'allowed' : 'denied'} by rule ${by.ruleNumber} first.`}`,
          ...(same ? { fix: [{ kind: 'remove-nacl-entry', naclId: n.id, egress, ruleNumber: a.ruleNumber }] } : {}),
        });
      }
    }
  }

  for (const f of out) if (f.ruleId && exposing.has(f.ruleId) && (f.code === 'open-to-world' || f.code === 'all-ports')) f.inExposure = true;
  return out.sort((a, b) => compareSeverity(a.severity, b.severity) || a.resourceId.localeCompare(b.resourceId) || (a.ruleId ?? '').localeCompare(b.ruleId ?? ''));
}
