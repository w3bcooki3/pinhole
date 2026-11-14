/**
 * Read-only snapshot collection.
 *
 * Every call goes through a `Send` function. In production it is backed by
 * the AWS SDK (sdk.ts); in tests by a fake. The collector refuses to send any
 * operation whose name does not start with Describe, Get or Search, so a
 * mutating call cannot slip in through a future edit.
 *
 * Failures of individual calls (typically AccessDenied for one API) do not
 * abort collection: they are recorded in `errors` and the analysis marks the
 * affected results as incomplete.
 */
import { SNAPSHOT_SCHEMA_VERSION } from '@pinhole/engine';
import type { Snapshot } from '@pinhole/engine';

export type Service = 'ec2' | 'elbv2' | 'sts';
export type Send = (service: Service, operation: string, input: Record<string, unknown>) => Promise<Record<string, unknown>>;

export const READ_ONLY_OPERATION = /^(Describe|Get|Search)[A-Z]/;

export interface CollectOptions {
  region: string;
  /** Called with a short message as each API is read. */
  onProgress?: (message: string) => void;
  toolVersion?: string;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
type Json = any;

class Collector {
  readonly errors: { api: string; message: string }[] = [];

  constructor(
    private readonly send: Send,
    private readonly progress: (m: string) => void,
  ) {}

  private async call(service: Service, op: string, input: Record<string, unknown>): Promise<Json> {
    if (!READ_ONLY_OPERATION.test(op)) throw new Error(`Refusing to call non-read-only operation ${service}:${op}`);
    return this.send(service, op, input);
  }

  /** Follows NextToken (EC2) or NextMarker/Marker (ELBv2) until exhausted. */
  async all(service: Service, op: string, key: string, input: Record<string, unknown> = {}): Promise<Json[] | undefined> {
    this.progress(`${service}:${op}`);
    const out: Json[] = [];
    let token: string | undefined;
    try {
      do {
        const page = token === undefined ? input : service === 'elbv2' ? { ...input, Marker: token } : { ...input, NextToken: token };
        const res = await this.call(service, op, page);
        out.push(...((res[key] as Json[] | undefined) ?? []));
        token = (service === 'elbv2' ? res.NextMarker : res.NextToken) as string | undefined;
      } while (token);
      return out;
    } catch (e) {
      this.errors.push({ api: `${service}:${op}`, message: errorMessage(e) });
      return undefined;
    }
  }

  async one(service: Service, op: string, input: Record<string, unknown>): Promise<Json | undefined> {
    try {
      return await this.call(service, op, input);
    } catch (e) {
      this.errors.push({ api: `${service}:${op}`, message: errorMessage(e) });
      return undefined;
    }
  }
}

function errorMessage(e: unknown): string {
  let text = String(e);
  if (e && typeof e === 'object') {
    const name = (e as { name?: string }).name;
    const msg = (e as { message?: string }).message;
    text = [name, msg].filter(Boolean).join(': ') || text;
  }
  // One line, no control characters, bounded: it ends up in a file people read in a terminal.
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\r\n\t]+/g, ' ').replace(/[\u0000-\u001f\u007f-\u009f]/g, '').slice(0, 4000);
}

/** Removes SDK response metadata and turns Dates into ISO strings. */
function clean<T>(value: T): T {
  return JSON.parse(JSON.stringify(value, (k, v) => (k === '$metadata' ? undefined : v))) as T;
}

function set<T extends object, K extends keyof T>(obj: T, key: K, value: T[K] | undefined) {
  if (value !== undefined) obj[key] = value;
}

export async function collectSnapshot(send: Send, opts: CollectOptions): Promise<Snapshot> {
  const c = new Collector(send, opts.onProgress ?? (() => {}));
  const ec2: NonNullable<Snapshot['ec2']> = {};
  const elbv2: NonNullable<Snapshot['elbv2']> = {};

  const identity = await c.one('sts', 'GetCallerIdentity', {});

  // Independent describe calls. Kept sequential: accounts with many resources
  // hit EC2 API rate limits quickly, and the SDK already retries throttling.
  set(ec2, 'Vpcs', await c.all('ec2', 'DescribeVpcs', 'Vpcs'));
  set(ec2, 'Subnets', await c.all('ec2', 'DescribeSubnets', 'Subnets'));
  set(ec2, 'RouteTables', await c.all('ec2', 'DescribeRouteTables', 'RouteTables'));
  set(ec2, 'InternetGateways', await c.all('ec2', 'DescribeInternetGateways', 'InternetGateways'));
  set(ec2, 'EgressOnlyInternetGateways', await c.all('ec2', 'DescribeEgressOnlyInternetGateways', 'EgressOnlyInternetGateways'));
  set(ec2, 'NatGateways', await c.all('ec2', 'DescribeNatGateways', 'NatGateways'));
  set(ec2, 'VpcPeeringConnections', await c.all('ec2', 'DescribeVpcPeeringConnections', 'VpcPeeringConnections'));
  set(ec2, 'TransitGateways', await c.all('ec2', 'DescribeTransitGateways', 'TransitGateways'));
  set(ec2, 'TransitGatewayAttachments', await c.all('ec2', 'DescribeTransitGatewayAttachments', 'TransitGatewayAttachments'));
  set(ec2, 'TransitGatewayVpcAttachments', await c.all('ec2', 'DescribeTransitGatewayVpcAttachments', 'TransitGatewayVpcAttachments'));
  set(ec2, 'TransitGatewayRouteTables', await c.all('ec2', 'DescribeTransitGatewayRouteTables', 'TransitGatewayRouteTables'));
  set(ec2, 'NetworkAcls', await c.all('ec2', 'DescribeNetworkAcls', 'NetworkAcls'));
  set(ec2, 'SecurityGroups', await c.all('ec2', 'DescribeSecurityGroups', 'SecurityGroups'));
  set(ec2, 'SecurityGroupRules', await c.all('ec2', 'DescribeSecurityGroupRules', 'SecurityGroupRules'));
  set(ec2, 'ManagedPrefixLists', await c.all('ec2', 'DescribeManagedPrefixLists', 'PrefixLists'));
  set(ec2, 'NetworkInterfaces', await c.all('ec2', 'DescribeNetworkInterfaces', 'NetworkInterfaces'));
  const reservations = await c.all('ec2', 'DescribeInstances', 'Reservations');
  set(ec2, 'Instances', reservations?.flatMap((r: Json) => r.Instances ?? []));
  set(ec2, 'VpcEndpoints', await c.all('ec2', 'DescribeVpcEndpoints', 'VpcEndpoints'));

  // Transit gateway routes, per route table. Only route tables owned by this
  // account can be searched; others are recorded as errors.
  const tgwRoutes: Record<string, Json[]> = {};
  for (const t of ec2.TransitGatewayRouteTables ?? []) {
    // Not paginated: at most MaxResults (1000) routes, with a flag when more exist.
    const res = await c.one('ec2', 'SearchTransitGatewayRoutes', {
      TransitGatewayRouteTableId: t.TransitGatewayRouteTableId,
      Filters: [{ Name: 'state', Values: ['active', 'blackhole'] }],
      MaxResults: 1000,
    });
    if (res?.AdditionalRoutesAvailable) {
      // A partial route table could make a path look blocked; leave it out so
      // paths through it are reported as unknown instead.
      c.errors.push({ api: 'ec2:SearchTransitGatewayRoutes', message: `${t.TransitGatewayRouteTableId} has more than 1000 routes; its routes were not used.` });
    } else if (res) tgwRoutes[t.TransitGatewayRouteTableId] = (res.Routes as Json[] | undefined) ?? [];
  }
  ec2.TransitGatewayRoutes = tgwRoutes;

  // Prefix list entries, only for lists that rules or routes actually use.
  const used = new Set<string>();
  for (const r of ec2.SecurityGroupRules ?? []) if (r.PrefixListId) used.add(r.PrefixListId);
  for (const rt of ec2.RouteTables ?? []) for (const r of rt.Routes ?? []) if (r.DestinationPrefixListId) used.add(r.DestinationPrefixListId);
  const entries: Record<string, Json[]> = {};
  for (const id of [...used].sort()) {
    const e = await c.all('ec2', 'GetManagedPrefixListEntries', 'Entries', { PrefixListId: id });
    if (e) entries[id] = e;
  }
  ec2.PrefixListEntries = entries;

  // Elastic Load Balancing v2.
  const lbs = await c.all('elbv2', 'DescribeLoadBalancers', 'LoadBalancers');
  set(elbv2, 'LoadBalancers', lbs);
  const listeners: Json[] = [];
  const rules: Json[] = [];
  for (const lb of lbs ?? []) {
    const ls = await c.all('elbv2', 'DescribeListeners', 'Listeners', { LoadBalancerArn: lb.LoadBalancerArn });
    for (const l of ls ?? []) {
      listeners.push(l);
      // Only application load balancers have listener rules beyond the default.
      if (lb.Type === 'application') {
        const rs = await c.all('elbv2', 'DescribeRules', 'Rules', { ListenerArn: l.ListenerArn });
        for (const r of rs ?? []) rules.push({ ...r, ListenerArn: l.ListenerArn });
      }
    }
  }
  elbv2.Listeners = listeners;
  elbv2.Rules = rules;
  const tgs = await c.all('elbv2', 'DescribeTargetGroups', 'TargetGroups');
  set(elbv2, 'TargetGroups', tgs);
  const health: Record<string, Json[]> = {};
  const attrs: Record<string, Json[]> = {};
  for (const tg of tgs ?? []) {
    const h = await c.one('elbv2', 'DescribeTargetHealth', { TargetGroupArn: tg.TargetGroupArn });
    if (h) health[tg.TargetGroupArn] = h.TargetHealthDescriptions ?? [];
    const a = await c.one('elbv2', 'DescribeTargetGroupAttributes', { TargetGroupArn: tg.TargetGroupArn });
    if (a) attrs[tg.TargetGroupArn] = a.Attributes ?? [];
  }
  elbv2.TargetHealth = health;
  elbv2.TargetGroupAttributes = attrs;

  const snapshot: Snapshot = {
    schemaVersion: SNAPSHOT_SCHEMA_VERSION,
    source: 'aws-sdk',
    tool: { name: 'pinhole', ...(opts.toolVersion ? { version: opts.toolVersion } : {}) },
    collectedAt: new Date().toISOString(),
    ...(identity?.Account ? { accountId: identity.Account } : {}),
    region: opts.region,
    ec2,
    elbv2,
    ...(c.errors.length ? { errors: c.errors } : {}),
  };
  return clean(snapshot);
}
