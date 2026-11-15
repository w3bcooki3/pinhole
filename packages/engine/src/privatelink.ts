/**
 * AWS PrivateLink: who can reach this account's services through endpoint
 * services, and what this account's own VPC endpoints let through.
 *
 * Provider side (https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-share-your-services.html):
 *  - who may connect: the service's allowed principals. "*" is every AWS
 *    account; without acceptance required, any of them connects at once
 *    (https://docs.aws.amazon.com/vpc/latest/privatelink/configure-endpoint-service.html);
 *  - who has connected: endpoint connections, by owner account and state;
 *  - what they reach: each listener of the Network Load Balancer behind the
 *    service. The load balancer's security groups apply to PrivateLink
 *    traffic unless "Enforce inbound rules on PrivateLink traffic" is off,
 *    and then the source is the consumer's private address, which can be any
 *    address (https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html).
 *    Targets see the load balancer's private address whatever the client IP
 *    preservation setting, so they are evaluated from its nodes
 *    (https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html).
 *
 * Consumer side: each interface endpoint's security group (who in the network
 * can use it), whether its service belongs to another account, and gateway
 * and interface endpoint policies that allow everything: with S3 or DynamoDB,
 * that lets data be copied to resources in any account
 * (https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html).
 */
import { evaluateTargets, listenerProtocols } from './exposure.js';
import type { LbTargetResult } from './exposure.js';
import { protocolName } from './packet.js';
import { assessPorts, compareSeverity, SEVERITY_ORDER } from './risk.js';
import type { Severity } from './risk.js';
import { ruleText } from './whatif.js';
import { PROTO_TCP } from './types.js';
import type { EndpointService, LoadBalancer, NetworkModel, ProtocolNumber } from './types.js';

export interface PrivateLinkListener {
  loadBalancer: string;
  port: number;
  protocol: string;
  /** Consumer addresses the load balancer's security groups let in on this port: "any address", ranges, or none. */
  consumers: string[];
  /** Why consumers are or are not filtered. */
  filter: 'no-security-groups' | 'rules-off-for-privatelink' | 'security-groups';
  targets: LbTargetResult[];
}

export interface PrivateLinkService {
  id: string;
  name: string;
  state: string;
  kind: 'network-load-balancer' | 'gateway-load-balancer';
  acceptanceRequired: boolean;
  /** Every AWS account may connect. */
  open: boolean;
  principals: string[] | undefined;
  /** Allowed principals outside this account. */
  external: string[];
  consumers: { endpointId: string; owner: string; state: string; region?: string; external: boolean }[];
  remoteRegions: string[];
  listeners: PrivateLinkListener[];
  severity: Severity;
  reasons: string[];
}

export interface PrivateLinkEndpoint {
  id: string;
  type: string;
  serviceName: string;
  vpcId: string;
  /** The service is one of this account's own, in the snapshot. */
  ownService?: string;
  /** The service is provided by another AWS account (not an AWS service). */
  otherAccount: boolean;
  /** Inbound rules of the endpoint's security groups. */
  inbound: string[];
  /** "full": the policy allows every principal every action on every resource. */
  policy: 'full' | 'restricted' | 'unknown';
  severity: Severity;
  reasons: string[];
}

export interface PrivateLinkReport {
  services: PrivateLinkService[];
  endpoints: PrivateLinkEndpoint[];
}

const accountOf = (arn: string) => /^arn:aws[a-z-]*:iam::(\d{12}):/.exec(arn)?.[1];
const live = (state: string) => !/^(deleted|deleting|rejected|failed|expired)$/i.test(state);
const raise = (s: Severity): Severity => SEVERITY_ORDER[Math.max(0, SEVERITY_ORDER.indexOf(s) - 1)]!;
const atLeast = (a: Severity, b: Severity): Severity => (compareSeverity(a, b) <= 0 ? a : b);

/** Consumer addresses the security groups of `lb` let in on `port`. */
function consumerFilter(model: NetworkModel, lb: LoadBalancer, protocol: ProtocolNumber, port: number): Pick<PrivateLinkListener, 'consumers' | 'filter'> {
  if (!lb.securityGroupIds.length) return { consumers: ['any address'], filter: 'no-security-groups' };
  if (lb.privateLinkRules === false) return { consumers: ['any address'], filter: 'rules-off-for-privatelink' };
  const out = new Set<string>();
  for (const gid of lb.securityGroupIds) {
    for (const r of model.securityGroups.get(gid)?.ingress ?? []) {
      if (r.protocol !== '-1' && r.protocol !== protocol) continue;
      if (r.fromPort !== undefined && r.fromPort !== -1 && (port < r.fromPort || port > (r.toPort ?? r.fromPort))) continue;
      if (r.cidr) out.add(r.cidr.start === 0 && r.cidr.end === 0xffffffff ? 'any address' : r.cidr.text);
      if (r.prefixListId) for (const e of model.prefixLists.get(r.prefixListId)?.entries ?? []) out.add(e.text);
    }
  }
  // A rule that names a security group cannot match a consumer in another VPC.
  return { consumers: out.has('any address') ? ['any address'] : [...out].sort(), filter: 'security-groups' };
}

function analyseService(model: NetworkModel, s: EndpointService): PrivateLinkService {
  const principals = s.principals?.map((p) => p.principal);
  const open = !!s.principals?.some((p) => p.principal === '*' || p.type === 'All');
  const external = (principals ?? []).filter((p) => p !== '*' && accountOf(p) !== model.accountId);
  const consumers = s.connections.filter((c) => live(c.state)).map((c) => ({ ...c, external: !!model.accountId && c.owner !== model.accountId }));
  const listeners: PrivateLinkListener[] = [];
  for (const arn of s.nlbArns) {
    const lb = model.loadBalancers.get(arn);
    if (!lb) continue;
    for (const l of model.listeners.filter((x) => x.loadBalancerArn === arn)) {
      for (const proto of listenerProtocols(lb, l.protocol)) {
        const f = consumerFilter(model, lb, proto, l.port);
        // PrivateLink traffic reaches targets from the load balancer's own address.
        const targets = f.consumers.length ? evaluateTargets(model, lb, l.port, proto, undefined, l.targetGroupArns).map((t) => ({ ...t, clientIpPreserved: false })) : [];
        listeners.push({ loadBalancer: lb.name, port: l.port, protocol: protocolName(proto), ...f, targets });
      }
    }
  }

  const reasons: string[] = [];
  let severity: Severity = 'info';
  if (open) {
    severity = s.acceptanceRequired ? 'medium' : 'high';
    reasons.push(s.acceptanceRequired ? 'every AWS account may ask to connect; each request needs your approval' : 'every AWS account may connect, without approval');
  } else if (external.length) {
    severity = 'low';
    reasons.push(`${external.length} principal${external.length === 1 ? '' : 's'} outside this account may connect`);
  }
  const ext = consumers.filter((c) => c.external);
  if (ext.length) reasons.push(`${ext.length} endpoint${ext.length === 1 ? '' : 's'} in other accounts connected or waiting (${[...new Set(ext.map((c) => c.owner))].join(', ')})`);
  if (s.remoteRegions.length) reasons.push(`consumers may also connect from ${s.remoteRegions.join(', ')}`);
  const reached = listeners.filter((l) => l.targets.some((t) => t.verdict === 'reachable' || t.verdict === 'partial'));
  if (listeners.some((l) => l.filter === 'rules-off-for-privatelink')) reasons.push("the load balancer's security groups do not filter PrivateLink traffic");
  if (listeners.some((l) => l.filter === 'no-security-groups')) reasons.push('the load balancer has no security groups, so consumers are not filtered by address');
  // An open service in front of remote administration or a database is worse.
  const risky = reached.filter((l) => compareSeverity(assessPorts(l.protocol, { from: l.targets[0]?.port ?? l.port, to: l.targets[0]?.port ?? l.port }).severity, 'high') <= 0);
  if (risky.length && compareSeverity(severity, 'medium') <= 0) {
    severity = raise(severity);
    reasons.push(`reaches ${risky.map((l) => `${l.protocol}/${l.targets[0]?.port ?? l.port}`).join(', ')} on its targets`);
  }
  if (!reasons.length) reasons.push(principals ? 'only principals in this account may connect' : 'allowed principals were not collected');
  return {
    id: s.id,
    name: s.name,
    state: s.state,
    kind: s.gwlbArns.length && !s.nlbArns.length ? 'gateway-load-balancer' : 'network-load-balancer',
    acceptanceRequired: s.acceptanceRequired,
    open,
    principals,
    external,
    consumers,
    remoteRegions: s.remoteRegions,
    listeners,
    severity,
    reasons,
  };
}

/** True when a policy has an unconditional statement allowing every principal every action on every resource. */
export function fullAccessPolicy(text: string): boolean | undefined {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return undefined;
  }
  const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]);
  const stmts = list((doc as { Statement?: unknown })?.Statement) as Record<string, unknown>[];
  return stmts.some((st) => {
    if (st?.Effect !== 'Allow' || st.Condition || st.NotAction || st.NotResource || st.NotPrincipal) return false;
    const p = st.Principal;
    const anyone = p === '*' || (typeof p === 'object' && p !== null && list((p as Record<string, unknown>).AWS).includes('*'));
    const every = list(st.Action).some((a) => a === '*' || (typeof a === 'string' && /^[a-z0-9-]+:\*$/.test(a)));
    return anyone && every && list(st.Resource).includes('*');
  });
}

function analyseEndpoint(model: NetworkModel, e: NonNullable<ReturnType<NetworkModel['vpcEndpoints']['get']>>): PrivateLinkEndpoint {
  const own = [...model.endpointServices.values()].find((s) => s.name === e.serviceName);
  const otherAccount = !own && /\.vpce-svc-[0-9a-f]+$/.test(e.serviceName);
  const inbound = (e.groupIds ?? []).flatMap((g) => (model.securityGroups.get(g)?.ingress ?? []).map((r) => `${ruleText(r)} (${g})`));
  const full = e.policy === undefined ? undefined : fullAccessPolicy(e.policy);
  const policy: PrivateLinkEndpoint['policy'] = full === undefined ? 'unknown' : full ? 'full' : 'restricted';
  const reasons: string[] = [];
  let severity: Severity = 'info';
  const data = /\.(s3|dynamodb)$/.test(e.serviceName);
  if (policy === 'full' && data) {
    severity = 'low';
    reasons.push('the endpoint policy allows any action on any resource, so data can be copied to buckets or tables in any account through it; limit it to your own resources (aws:ResourceOrgID or aws:ResourceAccount)');
  } else if (policy === 'full') reasons.push('the endpoint policy allows any action on any resource (the default)');
  if (otherAccount) reasons.push('the service is provided by another AWS account');
  if (own) reasons.push(`the service is ${own.id}, provided by this account`);
  if (inbound.some((r) => / from 0\.0\.0\.0\/0 /.test(`${r} `))) reasons.push('its security group lets in any address');
  if (!reasons.length) reasons.push(e.type === 'Interface' ? 'interface endpoint' : `${e.type.toLowerCase()} endpoint`);
  return { id: e.id, type: e.type, serviceName: e.serviceName, vpcId: e.vpcId, ...(own ? { ownService: own.id } : {}), otherAccount, inbound, policy, severity, reasons };
}

export function analyzePrivateLink(model: NetworkModel): PrivateLinkReport {
  const services = [...model.endpointServices.values()].filter((s) => live(s.state)).map((s) => analyseService(model, s));
  const endpoints = [...model.vpcEndpoints.values()].filter((e) => (e.type === 'Interface' || e.type === 'Gateway') && live(e.state ?? 'available')).map((e) => analyseEndpoint(model, e));
  services.sort((a, b) => compareSeverity(a.severity, b.severity) || a.name.localeCompare(b.name));
  endpoints.sort((a, b) => compareSeverity(a.severity, b.severity) || a.serviceName.localeCompare(b.serviceName));
  return { services, endpoints };
}

export const privateLinkWorst = (r: PrivateLinkReport): Severity => [...r.services, ...r.endpoints].reduce<Severity>((w, x) => atLeast(w, x.severity), 'info');
