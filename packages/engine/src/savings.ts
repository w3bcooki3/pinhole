/**
 * Money the network spends on things nothing uses, read from the same
 * snapshot as the exposure analysis, without traffic data or billing access.
 *
 * Two kinds of finding:
 *  - unused: nothing can use the resource, so removing it changes nothing but
 *    the bill. Each says why, from the analysis (no route points to it, no
 *    internet address reaches it and it sends nothing out, and so on).
 *  - check: the layout costs per gigabyte (S3 through a NAT gateway, a NAT
 *    gateway in another zone). The snapshot has no traffic volumes, so these
 *    give the rate and the free alternative, not an amount.
 *
 * Prices are AWS list prices for us-east-1 (see PRICES); most other regions
 * charge the same or a little more.
 */
import { analyzeEgress } from './egress.js';
import type { EgressReport } from './egress.js';
import { analyzeExposure } from './exposure.js';
import type { ExposureReport } from './exposure.js';
import { displayName, isElbNode, routeTableForSubnet } from './topology.js';
import type { Eni, LoadBalancer, NetworkModel, RouteTable } from './types.js';

/** us-east-1 list prices in USD, checked November 2026 on aws.amazon.com/vpc/pricing and aws.amazon.com/elasticloadbalancing/pricing. */
export const PRICES = {
  publicIpv4Hour: 0.005,
  natGatewayHour: 0.045,
  natGatewayGb: 0.045,
  albHour: 0.0225,
  nlbHour: 0.0225,
  gwlbHour: 0.0125,
  crossAzGb: 0.01,
  hoursPerMonth: 730,
  region: 'us-east-1',
} as const;

const monthly = (perHour: number) => Math.round(perHour * PRICES.hoursPerMonth * 100) / 100;

export type SavingsCode = 'idle-elastic-ip' | 'unused-public-ip' | 'unused-nat-gateway' | 'idle-load-balancer' | 's3-through-nat' | 'nat-in-other-zone';

export interface SavingsFinding {
  code: SavingsCode;
  /** unused: nothing uses it, removing it changes nothing but the bill. check: a per-gigabyte cost the snapshot cannot size. */
  kind: 'unused' | 'check';
  resourceId: string;
  resourceName: string;
  vpcId?: string;
  /** Fixed cost per month in USD (us-east-1 list price), when there is one. */
  monthly?: number;
  /** Cost per gigabyte that the free alternative avoids, for "check" findings. */
  perGb?: number;
  title: string;
  /** Why Pinhole says so, from the analysis. */
  why: string;
  /** What to do, in words. */
  fix: string;
  /** AWS CLI commands that do it, where the change is a command or two. */
  commands?: string[];
  /** Other resources the finding covers (subnets, servers). */
  related?: string[];
}

export interface SavingsReport {
  findings: SavingsFinding[];
  /** Sum of the fixed monthly cost of the "unused" findings. */
  unusedMonthly: number;
  /** Every public IPv4 address in the snapshot (attached or not) and what they cost together per month. */
  publicIpv4: { count: number; monthly: number };
  /** False when the snapshot has no Elastic IP list (collected before Pinhole asked for it): idle Elastic IPs cannot be found. */
  elasticIpsKnown: boolean;
}

/** Commands to detach and release an Elastic IP; the IDs are looked up first when the snapshot does not have them (--public-ip works only in EC2-Classic). */
function releaseCommands(ip: string, eip?: { id: string; associationId?: string }, attached = true): string[] {
  if (eip?.id.startsWith('eipalloc-')) return [...(attached ? [eip.associationId ? `aws ec2 disassociate-address --association-id ${eip.associationId}` : `aws ec2 disassociate-address --association-id $(aws ec2 describe-addresses --allocation-ids ${eip.id} --query 'Addresses[0].AssociationId' --output text)`] : []), `aws ec2 release-address --allocation-id ${eip.id}`];
  const look = (field: string) => `$(aws ec2 describe-addresses --public-ips ${ip} --query 'Addresses[0].${field}' --output text)`;
  return [...(attached ? [`aws ec2 disassociate-address --association-id ${look('AssociationId')}`] : []), `aws ec2 release-address --allocation-id ${look('AllocationId')}`];
}

const lbHour = (lb: LoadBalancer) => (lb.type === 'gateway' ? PRICES.gwlbHour : lb.type === 'network' ? PRICES.nlbHour : PRICES.albHour);

/** Route tables that some traffic follows: associated with a subnet (explicitly, or as the main table) or with a gateway. */
function usedRouteTables(model: NetworkModel): Set<string> {
  const used = new Set<string>();
  for (const s of model.subnets.values()) {
    const t = routeTableForSubnet(model, s);
    if (t) used.add(t.id);
  }
  for (const t of model.routeTables.values()) if (t.gatewayIds.length) used.add(t.id);
  return used;
}

/** The IPv4 default route's target in a table (0.0.0.0/0), if any. */
const defaultRoute = (t: RouteTable) => t.routes.find((r) => r.state === 'active' && r.destination && r.destination.start === 0 && r.destination.end === 0xffffffff);

function servers(model: NetworkModel, subnetId: string): Eni[] {
  return [...model.enis.values()].filter((e) => e.subnetId === subnetId && !isElbNode(e) && e.interfaceType !== 'nat_gateway' && e.interfaceType !== 'vpc_endpoint' && e.interfaceType !== 'gateway_load_balancer_endpoint');
}

export function analyzeSavings(model: NetworkModel, given: { exposure?: ExposureReport; egress?: EgressReport } = {}): SavingsReport {
  const exposure = given.exposure ?? analyzeExposure(model);
  const egress = given.egress ?? analyzeEgress(model);
  const findings: SavingsFinding[] = [];
  const allocationOf = new Map([...model.elasticIps.values()].map((a) => [a.publicIp, a]));

  // Elastic IPs attached to nothing.
  for (const a of model.elasticIps.values()) {
    if (a.associationId || a.eniId || a.instanceId) continue;
    findings.push({
      code: 'idle-elastic-ip',
      kind: 'unused',
      resourceId: a.id,
      resourceName: a.name ? `${a.name} (${a.publicIp})` : a.publicIp,
      monthly: monthly(PRICES.publicIpv4Hour),
      title: `Elastic IP ${a.publicIp} is attached to nothing`,
      why: 'It is not associated with any instance or network interface, so no traffic can use it. AWS bills every public IPv4 address by the hour, attached or not.',
      fix: 'Release it, unless you keep it so the address stays the same for later (an allow list somewhere, a DNS record).',
      commands: releaseCommands(a.publicIp, a, false),
    });
  }

  // Public IPs nothing reaches and nothing sends out from.
  const reachedFromInternet = new Set(exposure.findings.filter((f) => f.kind === 'interface').map((f) => f.resourceId));
  const sendsAs = new Set(egress.findings.map((f) => f.via.publicIp).filter((x): x is string => !!x));
  for (const eni of model.enis.values()) {
    if (!eni.publicAddresses.length || isElbNode(eni) || eni.interfaceType === 'nat_gateway') continue;
    if (reachedFromInternet.has(eni.id)) continue;
    for (const p of eni.publicAddresses) {
      if (sendsAs.has(p.publicIp)) continue;
      const name = displayName(model, eni);
      const eip = allocationOf.get(p.publicIp);
      const managed = eni.requesterManaged || (eni.interfaceType !== 'interface' && eni.interfaceType !== '');
      const commands = managed
        ? undefined
        : p.elastic
          ? releaseCommands(p.publicIp, eip)
          : [`aws ec2 modify-network-interface-attribute --network-interface-id ${eni.id} --no-associate-public-ip-address`];
      findings.push({
        code: 'unused-public-ip',
        kind: 'unused',
        resourceId: eni.id,
        resourceName: name,
        vpcId: eni.vpcId,
        monthly: monthly(PRICES.publicIpv4Hour),
        title: `${name} has a public IP that nothing uses (${p.publicIp})`,
        why: 'No internet address can open a connection to it on any port, and it cannot reach the internet through this address either: its rules, routes or network ACLs block both ways.',
        fix: managed
          ? `It belongs to a managed service (${eni.description || eni.interfaceType}): turn off its public access setting there.`
          : p.elastic
            ? 'Detach the Elastic IP and release it.'
            : 'Remove the auto-assigned public IP from the network interface. To stop new servers getting one, turn off "auto-assign public IPv4" on the subnet.',
        ...(commands ? { commands } : {}),
      });
    }
  }

  // NAT gateways no route sends traffic to.
  const used = usedRouteTables(model);
  const natRouted = new Map<string, string[]>();
  for (const t of model.routeTables.values()) {
    if (!used.has(t.id)) continue;
    for (const r of t.routes) if (r.target.type === 'nat' && r.state === 'active') natRouted.set(r.target.id, [...(natRouted.get(r.target.id) ?? []), t.id]);
  }
  for (const n of model.natGateways.values()) {
    if (n.state !== 'available' || natRouted.has(n.id)) continue;
    const ips = n.connectivity === 'public' ? Math.max(1, n.publicIps.length) : 0;
    findings.push({
      code: 'unused-nat-gateway',
      kind: 'unused',
      resourceId: n.id,
      resourceName: n.id,
      vpcId: n.vpcId,
      monthly: monthly(PRICES.natGatewayHour + ips * PRICES.publicIpv4Hour),
      title: `NAT gateway ${n.id} is not on any route`,
      why: 'No route table that a subnet or gateway uses sends traffic to it, so nothing can go through it. It is billed by the hour while it exists, and so are its public IPs.',
      fix: ips ? 'Delete it, then release its Elastic IP.' : 'Delete it.',
      commands: [`aws ec2 delete-nat-gateway --nat-gateway-id ${n.id}`, ...n.publicIps.flatMap((ip) => releaseCommands(ip, allocationOf.get(ip), false).map((c) => `${c}  # once the gateway is deleted`))],
    });
  }

  // Load balancers with nothing behind them.
  for (const lb of model.loadBalancers.values()) {
    const listeners = model.listeners.filter((l) => l.loadBalancerArn === lb.arn);
    const tgs = [...new Set(listeners.flatMap((l) => l.targetGroupArns))].map((a) => model.targetGroups.get(a)).filter((g) => !!g);
    const registered = tgs.reduce((n, g) => n + g.targets.length, 0);
    if (listeners.length && registered) continue;
    // Listeners pointing at target groups the snapshot does not have: not enough to say.
    if (listeners.length && tgs.length < new Set(listeners.flatMap((l) => l.targetGroupArns)).size) continue;
    const publicNodes = lb.scheme === 'internet-facing' && lb.type !== 'gateway' ? Math.max(lb.subnetIds.length, lb.nodeEniIds.filter((id) => model.enis.get(id)?.publicAddresses.length).length) : 0;
    // Listeners that forward nowhere may still redirect or return a fixed response.
    const forwardsNowhere = listeners.length > 0 && tgs.length === 0;
    findings.push({
      code: 'idle-load-balancer',
      kind: forwardsNowhere ? 'check' : 'unused',
      resourceId: lb.arn,
      resourceName: lb.name,
      vpcId: lb.vpcId,
      monthly: monthly(lbHour(lb) + publicNodes * PRICES.publicIpv4Hour),
      title: forwardsNowhere ? `Load balancer ${lb.name} forwards to no target group` : listeners.length ? `Load balancer ${lb.name} has no targets` : `Load balancer ${lb.name} has no listeners`,
      why: forwardsNowhere
        ? 'None of its listeners forwards to a target group. It may only redirect or return a fixed response; if not, it serves nothing while the hourly charge and its public IPs are billed.'
        : listeners.length
        ? 'Its listeners forward to target groups with no registered targets, so every request fails. The hourly charge and its public IPs are billed anyway.'
        : 'It has no listeners, so it accepts no traffic at all. The hourly charge and its public IPs are billed anyway.',
      fix: 'Delete it if nothing is about to be deployed behind it.',
      commands: [`aws elbv2 delete-load-balancer --load-balancer-arn ${lb.arn}`],
    });
  }

  // S3 through a NAT gateway with no gateway endpoint (free) in the route table.
  const s3Endpoint = new Map<string, Set<string>>();
  for (const e of model.vpcEndpoints.values()) if (/\.s3$/.test(e.serviceName) && (e.state ?? 'available') === 'available') s3Endpoint.set(e.vpcId, (s3Endpoint.get(e.vpcId) ?? new Set()).add(e.id));
  const s3Tables = new Map<string, { table: RouteTable; nat: string; subnets: string[] }>();
  const crossZone = new Map<string, { nat: string; subnets: string[]; zone: string; natZone: string }>();
  for (const s of model.subnets.values()) {
    const t = routeTableForSubnet(model, s);
    const d = t && defaultRoute(t);
    if (!t || !d || d.target.type !== 'nat' || !servers(model, s.id).length) continue;
    const nat = model.natGateways.get(d.target.id);
    const viaEndpoint = t.routes.some((r) => r.target.type !== 'nat' && s3Endpoint.get(t.vpcId)?.has(r.target.id));
    // An interface endpoint for S3 also keeps the traffic off the NAT gateway.
    const interfaceS3 = [...(s3Endpoint.get(t.vpcId) ?? [])].some((id) => model.vpcEndpoints.get(id)?.type === 'Interface');
    if (!viaEndpoint && !interfaceS3) {
      const k = t.id;
      const cur = s3Tables.get(k) ?? { table: t, nat: d.target.id, subnets: [] };
      cur.subnets.push(s.id);
      s3Tables.set(k, cur);
    }
    const natSubnet = nat && model.subnets.get(nat.subnetId);
    if (natSubnet && natSubnet.availabilityZone !== s.availabilityZone) {
      const k = `${s.availabilityZone}>${nat!.id}`;
      const cur = crossZone.get(k) ?? { nat: nat!.id, subnets: [], zone: s.availabilityZone, natZone: natSubnet.availabilityZone };
      cur.subnets.push(s.id);
      crossZone.set(k, cur);
    }
  }
  for (const { table, nat, subnets } of s3Tables.values()) {
    const region = model.region ?? '<region>';
    findings.push({
      code: 's3-through-nat',
      kind: 'check',
      resourceId: table.id,
      resourceName: table.id,
      vpcId: table.vpcId,
      perGb: PRICES.natGatewayGb,
      title: `S3 traffic from ${subnets.length === 1 ? 'one subnet' : `${subnets.length} subnets`} goes through NAT gateway ${nat}`,
      why: `Route table ${table.id} sends everything outside the VPC to the NAT gateway and has no S3 gateway endpoint, so every gigabyte to or from S3 is charged NAT data processing. A gateway endpoint for S3 is free and takes that traffic off the NAT gateway. DynamoDB has the same free endpoint.`,
      fix: 'Add an S3 gateway endpoint to this route table (and one for DynamoDB if you use it). Check the endpoint policy and any bucket policies that require a source IP.',
      commands: [`aws ec2 create-vpc-endpoint --vpc-id ${table.vpcId} --vpc-endpoint-type Gateway --service-name com.amazonaws.${region}.s3 --route-table-ids ${table.id}`],
      related: subnets,
    });
  }
  for (const { nat, subnets, zone, natZone } of crossZone.values()) {
    findings.push({
      code: 'nat-in-other-zone',
      kind: 'check',
      resourceId: nat,
      resourceName: nat,
      vpcId: model.natGateways.get(nat)?.vpcId,
      perGb: PRICES.crossAzGb,
      title: `${subnets.length === 1 ? 'A subnet' : `${subnets.length} subnets`} in ${zone} ${subnets.length === 1 ? 'reaches' : 'reach'} the internet through a NAT gateway in ${natZone}`,
      why: `Traffic between Availability Zones is charged per gigabyte in each direction, on top of NAT data processing. ${subnets.length === 1 ? 'The subnet also loses' : 'They also lose'} internet access if ${natZone} fails.`,
      fix: `If ${subnets.length === 1 ? 'it sends' : 'they send'} much traffic out, give ${zone} its own NAT gateway (a fixed hourly cost) and point its route tables at it. For little traffic, the cross-zone charge is cheaper than another gateway.`,
      related: subnets,
    });
  }

  // Every public IPv4 address billed: on interfaces (servers, NAT gateways, load balancer nodes) and Elastic IPs attached to nothing.
  const addresses = new Set<string>();
  for (const e of model.enis.values()) for (const p of e.publicAddresses) addresses.add(p.publicIp);
  for (const a of model.elasticIps.values()) addresses.add(a.publicIp);
  for (const n of model.natGateways.values()) for (const ip of n.publicIps) addresses.add(ip);

  const order = { unused: 0, check: 1 } as const;
  findings.sort((a, b) => order[a.kind] - order[b.kind] || (b.monthly ?? 0) - (a.monthly ?? 0) || a.resourceName.localeCompare(b.resourceName));
  return {
    findings,
    unusedMonthly: Math.round(findings.filter((f) => f.kind === 'unused').reduce((n, f) => n + (f.monthly ?? 0), 0) * 100) / 100,
    publicIpv4: { count: addresses.size, monthly: monthly(addresses.size * PRICES.publicIpv4Hour) },
    elasticIpsKnown: model.elasticIpsKnown === true,
  };
}
