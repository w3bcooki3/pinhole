/**
 * Snapshot file format (schemaVersion 1).
 *
 * A snapshot is the raw output of read-only AWS describe calls for ONE account
 * and ONE region, stored under the API's own field names (PascalCase, exactly
 * as `aws ec2 describe-*` prints them). Keeping the raw shape means:
 *  - the CloudShell script can build a snapshot with nothing but the AWS CLI
 *    and jq;
 *  - a reviewer can compare any value against the AWS API reference;
 *  - new engine features can use fields we already collect without a new
 *    collector release.
 *
 * Only fields the engine reads are typed here; anything else is preserved but
 * ignored. Every list is optional so that partial snapshots (for example from a
 * principal without permission for one API) still load; `errors` records which
 * calls failed so results can be marked incomplete.
 */

export const SNAPSHOT_SCHEMA_VERSION = 1;

/* eslint-disable @typescript-eslint/no-explicit-any */
type Tag = { Key?: string; Value?: string };

export interface RawVpc {
  VpcId: string;
  CidrBlock?: string;
  CidrBlockAssociationSet?: { CidrBlock?: string; CidrBlockState?: { State?: string } }[];
  Ipv6CidrBlockAssociationSet?: { Ipv6CidrBlock?: string }[];
  OwnerId?: string;
  Tags?: Tag[];
}

export interface RawSubnet {
  SubnetId: string;
  VpcId: string;
  CidrBlock: string;
  AvailabilityZone?: string;
  AvailabilityZoneId?: string;
  Tags?: Tag[];
}

export interface RawRoute {
  DestinationCidrBlock?: string;
  DestinationIpv6CidrBlock?: string;
  DestinationPrefixListId?: string;
  GatewayId?: string;
  NatGatewayId?: string;
  VpcPeeringConnectionId?: string;
  TransitGatewayId?: string;
  NetworkInterfaceId?: string;
  InstanceId?: string;
  EgressOnlyInternetGatewayId?: string;
  CarrierGatewayId?: string;
  LocalGatewayId?: string;
  CoreNetworkArn?: string;
  State?: string;
  Origin?: string;
}

export interface RawRouteTable {
  RouteTableId: string;
  VpcId: string;
  Routes?: RawRoute[];
  Associations?: { Main?: boolean; SubnetId?: string; GatewayId?: string; AssociationState?: { State?: string } }[];
  Tags?: Tag[];
}

export interface RawInternetGateway {
  InternetGatewayId: string;
  Attachments?: { VpcId?: string; State?: string }[];
}

export interface RawEgressOnlyInternetGateway {
  EgressOnlyInternetGatewayId: string;
  Attachments?: { VpcId?: string; State?: string }[];
}

export interface RawNatGateway {
  NatGatewayId: string;
  VpcId: string;
  SubnetId: string;
  State?: string;
  ConnectivityType?: string;
}

export interface RawPeeringVpcInfo {
  VpcId?: string;
  CidrBlock?: string;
  CidrBlockSet?: { CidrBlock?: string }[];
  OwnerId?: string;
  Region?: string;
}

export interface RawPeering {
  VpcPeeringConnectionId: string;
  Status?: { Code?: string };
  RequesterVpcInfo?: RawPeeringVpcInfo;
  AccepterVpcInfo?: RawPeeringVpcInfo;
}

export interface RawTransitGateway {
  TransitGatewayId: string;
  OwnerId?: string;
  State?: string;
  Options?: { SecurityGroupReferencingSupport?: string; [k: string]: any };
}

export interface RawTgwAttachment {
  TransitGatewayAttachmentId: string;
  TransitGatewayId: string;
  ResourceType?: string;
  ResourceId?: string;
  State?: string;
  Association?: { TransitGatewayRouteTableId?: string; State?: string };
}

export interface RawTgwVpcAttachment {
  TransitGatewayAttachmentId: string;
  TransitGatewayId?: string;
  VpcId?: string;
  SubnetIds?: string[];
  State?: string;
  Options?: { SecurityGroupReferencingSupport?: string; [k: string]: any };
}

export interface RawTgwRouteTable {
  TransitGatewayRouteTableId: string;
  TransitGatewayId: string;
  State?: string;
}

export interface RawTgwRoute {
  DestinationCidrBlock?: string;
  PrefixListId?: string;
  TransitGatewayAttachments?: { TransitGatewayAttachmentId?: string; ResourceId?: string; ResourceType?: string }[];
  Type?: string;
  State?: string;
}

export interface RawNaclEntry {
  RuleNumber: number;
  Protocol: string;
  RuleAction: string;
  Egress: boolean;
  CidrBlock?: string;
  Ipv6CidrBlock?: string;
  PortRange?: { From?: number; To?: number };
  IcmpTypeCode?: { Type?: number; Code?: number };
}

export interface RawNacl {
  NetworkAclId: string;
  VpcId: string;
  IsDefault?: boolean;
  Entries?: RawNaclEntry[];
  Associations?: { SubnetId?: string }[];
}

export interface RawIpPermission {
  IpProtocol: string;
  FromPort?: number;
  ToPort?: number;
  IpRanges?: { CidrIp?: string; Description?: string }[];
  Ipv6Ranges?: { CidrIpv6?: string; Description?: string }[];
  PrefixListIds?: { PrefixListId?: string; Description?: string }[];
  UserIdGroupPairs?: { GroupId?: string; VpcId?: string; VpcPeeringConnectionId?: string; Description?: string }[];
}

export interface RawSecurityGroup {
  GroupId: string;
  GroupName?: string;
  VpcId?: string;
  IpPermissions?: RawIpPermission[];
  IpPermissionsEgress?: RawIpPermission[];
}

export interface RawSecurityGroupRule {
  SecurityGroupRuleId: string;
  GroupId: string;
  IsEgress: boolean;
  IpProtocol: string;
  FromPort?: number;
  ToPort?: number;
  CidrIpv4?: string;
  CidrIpv6?: string;
  PrefixListId?: string;
  ReferencedGroupInfo?: { GroupId?: string; VpcId?: string; VpcPeeringConnectionId?: string; PeeringStatus?: string };
  Description?: string;
}

export interface RawPrefixList {
  PrefixListId: string;
  PrefixListName?: string;
  AddressFamily?: string;
}

export interface RawNetworkInterface {
  NetworkInterfaceId: string;
  SubnetId: string;
  VpcId: string;
  InterfaceType?: string;
  Description?: string;
  RequesterManaged?: boolean;
  PrivateIpAddress?: string;
  PrivateIpAddresses?: { PrivateIpAddress?: string; Primary?: boolean; Association?: { PublicIp?: string; IpOwnerId?: string } }[];
  Association?: { PublicIp?: string; IpOwnerId?: string };
  Groups?: { GroupId?: string; GroupName?: string }[];
  Attachment?: { InstanceId?: string; DeviceIndex?: number };
  Ipv6Addresses?: { Ipv6Address?: string }[];
  Status?: string;
}

export interface RawInstance {
  InstanceId: string;
  State?: { Name?: string };
  NetworkInterfaces?: { NetworkInterfaceId?: string; Attachment?: { DeviceIndex?: number } }[];
  Tags?: Tag[];
}

export interface RawVpcEndpoint {
  VpcEndpointId: string;
  VpcEndpointType?: string;
  ServiceName?: string;
  VpcId?: string;
}

export interface RawLoadBalancer {
  LoadBalancerArn: string;
  LoadBalancerName?: string;
  Type?: string;
  Scheme?: string;
  VpcId?: string;
  AvailabilityZones?: { SubnetId?: string; ZoneName?: string }[];
  SecurityGroups?: string[];
}

export interface RawAction {
  Type?: string;
  TargetGroupArn?: string;
  ForwardConfig?: { TargetGroups?: { TargetGroupArn?: string }[] };
}

export interface RawListener {
  ListenerArn: string;
  LoadBalancerArn: string;
  Port?: number;
  Protocol?: string;
  DefaultActions?: RawAction[];
}

export interface RawListenerRule {
  RuleArn?: string;
  ListenerArn?: string;
  Actions?: RawAction[];
}

export interface RawTargetGroup {
  TargetGroupArn: string;
  TargetGroupName?: string;
  Protocol?: string;
  Port?: number;
  TargetType?: string;
  VpcId?: string;
  HealthCheckPort?: string;
  LoadBalancerArns?: string[];
}

export interface RawTargetHealth {
  Target?: { Id?: string; Port?: number; AvailabilityZone?: string };
  TargetHealth?: { State?: string };
}

export interface Snapshot {
  schemaVersion: number;
  source?: 'aws-sdk' | 'aws-cli' | 'terraform-plan' | 'fixture' | string;
  tool?: { name?: string; version?: string };
  collectedAt?: string;
  accountId?: string;
  region?: string;
  ec2?: {
    Vpcs?: RawVpc[];
    Subnets?: RawSubnet[];
    RouteTables?: RawRouteTable[];
    InternetGateways?: RawInternetGateway[];
    EgressOnlyInternetGateways?: RawEgressOnlyInternetGateway[];
    NatGateways?: RawNatGateway[];
    VpcPeeringConnections?: RawPeering[];
    TransitGateways?: RawTransitGateway[];
    TransitGatewayAttachments?: RawTgwAttachment[];
    TransitGatewayVpcAttachments?: RawTgwVpcAttachment[];
    TransitGatewayRouteTables?: RawTgwRouteTable[];
    /** SearchTransitGatewayRoutes output, keyed by route table ID. */
    TransitGatewayRoutes?: Record<string, RawTgwRoute[]>;
    NetworkAcls?: RawNacl[];
    SecurityGroups?: RawSecurityGroup[];
    SecurityGroupRules?: RawSecurityGroupRule[];
    ManagedPrefixLists?: RawPrefixList[];
    /** GetManagedPrefixListEntries output, keyed by prefix list ID. */
    PrefixListEntries?: Record<string, { Cidr?: string; Description?: string }[]>;
    NetworkInterfaces?: RawNetworkInterface[];
    /** Flattened from DescribeInstances reservations. */
    Instances?: RawInstance[];
    VpcEndpoints?: RawVpcEndpoint[];
  };
  elbv2?: {
    LoadBalancers?: RawLoadBalancer[];
    Listeners?: RawListener[];
    Rules?: RawListenerRule[];
    TargetGroups?: RawTargetGroup[];
    /** DescribeTargetHealth output, keyed by target group ARN. */
    TargetHealth?: Record<string, RawTargetHealth[]>;
    /** DescribeTargetGroupAttributes output, keyed by target group ARN. */
    TargetGroupAttributes?: Record<string, { Key?: string; Value?: string }[]>;
  };
  /** API calls that failed during collection. */
  errors?: { api: string; message: string }[];
}

export class SnapshotError extends Error {}

/**
 * Structural checks that catch the wrong file being passed in. This is not a
 * full schema validation: missing optional lists are fine.
 */
export function assertSnapshot(value: unknown): asserts value is Snapshot {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SnapshotError('Snapshot must be a JSON object.');
  }
  const v = value as Record<string, unknown>;
  if (v.schemaVersion !== SNAPSHOT_SCHEMA_VERSION) {
    throw new SnapshotError(
      `Unsupported snapshot schemaVersion ${JSON.stringify(v.schemaVersion)}; this build reads version ${SNAPSHOT_SCHEMA_VERSION}.`,
    );
  }
  for (const key of ['ec2', 'elbv2'] as const) {
    if (v[key] !== undefined && (typeof v[key] !== 'object' || v[key] === null || Array.isArray(v[key]))) {
      throw new SnapshotError(`Snapshot field "${key}" must be an object.`);
    }
  }
  const ec2 = (v.ec2 ?? {}) as Record<string, unknown>;
  for (const [k, list] of Object.entries(ec2)) {
    const keyed = k === 'TransitGatewayRoutes' || k === 'PrefixListEntries';
    if (keyed ? typeof list !== 'object' || Array.isArray(list) : !Array.isArray(list)) {
      throw new SnapshotError(`Snapshot field "ec2.${k}" has the wrong type.`);
    }
  }
}
