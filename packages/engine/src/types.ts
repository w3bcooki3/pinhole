/**
 * Normalised network model used by the evaluator.
 *
 * The raw snapshot (see snapshot.ts) keeps AWS API field names so that it can be
 * produced by the AWS CLI, the SDK, or a Terraform plan adapter without a
 * translation layer in each. `normalize()` turns it into these types once, so
 * the evaluation code never has to deal with optional AWS fields or string
 * protocol names.
 *
 * Addresses are IPv4 only in v1. IPv6 rules are kept as text so hygiene checks
 * and warnings can mention them, but they never take part in path evaluation.
 */

/** Inclusive IPv4 range; start and end are unsigned 32-bit integers. */
export interface IpRange {
  start: number;
  end: number;
}

export interface Cidr extends IpRange {
  text: string;
  prefixLength: number;
}

/**
 * IP protocol number as a string, the way the EC2 API reports NACL entries:
 * "-1" (all), "6" (TCP), "17" (UDP), "1" (ICMP), "58" (ICMPv6), or any other
 * number. Security group rules that use names ("tcp") are converted to numbers.
 */
export type ProtocolNumber = string;

export const PROTO_ALL = '-1';
export const PROTO_TCP = '6';
export const PROTO_UDP = '17';
export const PROTO_ICMP = '1';

/** A single packet as seen by a filter. */
export interface Packet {
  /** IP protocol number, never "-1". */
  protocol: ProtocolNumber;
  /** Destination port for TCP/UDP. */
  port?: number;
  /** ICMP type and code for ICMP. */
  icmpType?: number;
  icmpCode?: number;
}

export interface PortRange {
  from: number;
  to: number;
}

// ---------------------------------------------------------------- NACLs

export interface NaclEntry {
  ruleNumber: number;
  egress: boolean;
  action: 'allow' | 'deny';
  protocol: ProtocolNumber;
  /** IPv4 CIDR; undefined for IPv6 entries. */
  cidr?: Cidr;
  ipv6CidrText?: string;
  portRange?: PortRange;
  icmp?: { type: number; code: number };
}

export interface Nacl {
  id: string;
  vpcId: string;
  isDefault: boolean;
  /** Entries in ascending rule number order, including the `*` rule (32767). */
  entries: NaclEntry[];
  subnetIds: string[];
}

// ---------------------------------------------------------------- Security groups

export interface SgRule {
  /** `sgr-...`, from DescribeSecurityGroupRules. */
  id: string;
  groupId: string;
  egress: boolean;
  protocol: ProtocolNumber;
  /** For TCP/UDP: port range. For ICMP: from = type, to = code (-1 = any). */
  fromPort?: number;
  toPort?: number;
  cidr?: Cidr;
  ipv6CidrText?: string;
  prefixListId?: string;
  referencedGroupId?: string;
  /** VPC of the referenced group when it lives in another VPC. */
  referencedVpcId?: string;
  referencedPeeringConnectionId?: string;
  description?: string;
}

export interface SecurityGroup {
  id: string;
  name: string;
  vpcId: string;
  ingress: SgRule[];
  egress: SgRule[];
}

// ---------------------------------------------------------------- Routing

export type RouteTargetType =
  | 'local'
  | 'igw'
  | 'nat'
  | 'pcx'
  | 'tgw'
  | 'vpce'
  | 'eni'
  | 'instance'
  | 'vgw'
  | 'eigw'
  | 'other';

export interface Route {
  /** IPv4 destination; undefined when the route uses a prefix list. */
  destination?: Cidr;
  destinationPrefixListId?: string;
  target: { type: RouteTargetType; id: string };
  state: 'active' | 'blackhole';
  /** CreateRouteTable (local), CreateRoute (static) or EnableVgwRoutePropagation. */
  origin: 'static' | 'propagated' | 'local';
}

/** An IPv6 route. Kept apart from IPv4 routes, which the IPv4 path walk uses. */
export interface Route6 {
  /** Destination CIDR text, e.g. "::/0". */
  destination: string;
  target: { type: RouteTargetType; id: string };
  state: 'active' | 'blackhole';
}

export interface RouteTable {
  id: string;
  vpcId: string;
  isMain: boolean;
  subnetIds: string[];
  /** Gateways (igw-/vgw-) this table is edge-associated with. */
  gatewayIds: string[];
  routes: Route[];
  /** IPv6 routes (DestinationIpv6CidrBlock). */
  routes6?: Route6[];
}

// ---------------------------------------------------------------- Topology

export interface Vpc {
  id: string;
  cidrs: Cidr[];
  ipv6CidrTexts: string[];
  ownerId?: string;
}

export interface Subnet {
  id: string;
  vpcId: string;
  cidr: Cidr;
  availabilityZone: string;
  availabilityZoneId?: string;
}

export interface InternetGateway {
  id: string;
  /** VPC it is attached to, if any (state "available" or "attached"). */
  vpcId?: string;
}

export interface NatGateway {
  id: string;
  vpcId: string;
  subnetId: string;
  state: string;
  connectivity: 'public' | 'private';
}

export interface PeeringConnection {
  id: string;
  status: string;
  requesterVpcId: string;
  requesterCidrs: Cidr[];
  requesterRegion?: string;
  accepterVpcId: string;
  accepterCidrs: Cidr[];
  accepterRegion?: string;
}

export interface TransitGateway {
  id: string;
  /** Options.SecurityGroupReferencingSupport === 'enable'. */
  sgReferencing: boolean;
}

export interface TgwAttachment {
  id: string;
  tgwId: string;
  resourceType: string;
  resourceId: string;
  state: string;
  associatedRouteTableId?: string;
  /** Only for VPC attachments. */
  subnetIds: string[];
  sgReferencing: boolean;
}

export interface TgwRoute {
  destination?: Cidr;
  prefixListId?: string;
  attachmentIds: string[];
  type: 'static' | 'propagated';
  state: 'active' | 'blackhole';
}

export interface TgwRouteTable {
  id: string;
  tgwId: string;
  routes: TgwRoute[];
  /** False when the collector could not read routes (e.g. a shared TGW). */
  routesKnown: boolean;
}

export interface PublicAddress {
  publicIp: string;
  privateIp: string;
  /** True for Elastic IPs (owner is not "amazon"). */
  elastic: boolean;
}

export interface Eni {
  id: string;
  subnetId: string;
  vpcId: string;
  interfaceType: string;
  description: string;
  requesterManaged: boolean;
  /** Primary private IP first. */
  privateIps: string[];
  publicAddresses: PublicAddress[];
  groupIds: string[];
  instanceId?: string;
  hasIpv6: boolean;
  /** IPv6 addresses. In a subnet routed to an internet gateway these are reachable from the internet without a public IP. */
  ipv6Addresses?: string[];
}

export interface Instance {
  id: string;
  name?: string;
  state: string;
  primaryEniId?: string;
  eniIds: string[];
}

export interface PrefixList {
  id: string;
  name: string;
  /** IPv4 entries only. */
  entries: Cidr[];
  /** False when the entries could not be read. */
  entriesKnown: boolean;
  hasIpv6Entries: boolean;
}

// ---------------------------------------------------------------- Load balancers

export interface LoadBalancer {
  arn: string;
  name: string;
  type: 'application' | 'network' | 'gateway';
  scheme: 'internet-facing' | 'internal';
  vpcId: string;
  subnetIds: string[];
  /** Empty for NLBs created without security groups. */
  securityGroupIds: string[];
  /** Private IPs of the load balancer nodes, from its ENIs. */
  nodeIps: string[];
  nodeEniIds: string[];
}

export interface Listener {
  arn: string;
  loadBalancerArn: string;
  port: number;
  protocol: string;
  targetGroupArns: string[];
}

export interface TargetGroup {
  arn: string;
  name: string;
  protocol?: string;
  port?: number;
  targetType: 'instance' | 'ip' | 'lambda' | 'alb';
  vpcId?: string;
  healthCheckPort?: string;
  /** preserve_client_ip.enabled; undefined when attributes were not collected. */
  preserveClientIp?: boolean;
  targets: { id: string; port?: number; availabilityZone?: string; state?: string }[];
}

export interface VpcEndpoint {
  id: string;
  type: 'Interface' | 'Gateway' | 'GatewayLoadBalancer' | string;
  serviceName: string;
  vpcId: string;
}

/** Everything the evaluator knows about one account and region. */
export interface NetworkModel {
  accountId?: string;
  region?: string;
  vpcs: Map<string, Vpc>;
  subnets: Map<string, Subnet>;
  routeTables: Map<string, RouteTable>;
  nacls: Map<string, Nacl>;
  securityGroups: Map<string, SecurityGroup>;
  prefixLists: Map<string, PrefixList>;
  internetGateways: Map<string, InternetGateway>;
  natGateways: Map<string, NatGateway>;
  peerings: Map<string, PeeringConnection>;
  transitGateways: Map<string, TransitGateway>;
  tgwAttachments: Map<string, TgwAttachment>;
  tgwRouteTables: Map<string, TgwRouteTable>;
  enis: Map<string, Eni>;
  instances: Map<string, Instance>;
  loadBalancers: Map<string, LoadBalancer>;
  listeners: Listener[];
  targetGroups: Map<string, TargetGroup>;
  vpcEndpoints: Map<string, VpcEndpoint>;
  /** Raw route-table entries the normaliser could not interpret, etc. */
  warnings: Warning[];
}

export interface Warning {
  code: string;
  message: string;
  resourceIds: string[];
  /** AWS documentation link explaining the behaviour that is not modelled. */
  docUrl?: string;
}
