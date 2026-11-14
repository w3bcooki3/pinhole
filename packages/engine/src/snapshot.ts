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
    if (keyed ? typeof list !== 'object' || list === null || Array.isArray(list) : !Array.isArray(list)) {
      throw new SnapshotError(`Snapshot field "ec2.${k}" has the wrong type.`);
    }
  }
  validate(v, SNAPSHOT, '');
}

// ------------------------------------------------------------------ deep validation
// Snapshots are files people pass around, so every field the engine reads is
// checked for type, range and characters before analysis. A wrong type would
// otherwise give a silently wrong answer; a control character could end up in a
// terminal or a copied command. Unknown fields are ignored for forward
// compatibility.

type Spec =
  | 'str' | 'text' | 'msg' | 'bool' | 'port' | 'portAny' | 'int' | 'ruleNo'
  | { arr: Spec; max?: number }
  | { obj: Record<string, Spec>; req?: string[] }
  | { map: Spec }
  | { re: RegExp; what: string };

const MAX_ITEMS = 500_000;
const MAX_STR = 4096;
// No control characters (newlines, escapes) in anything that may reach a terminal or a command line.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const CONTROL_ALL = /[\u0000-\u001f\u007f-\u009f]/g;
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);

const arr = (of: Spec, max = MAX_ITEMS): Spec => ({ arr: of, max });
const obj = (o: Record<string, Spec>, req: string[] = []): Spec => ({ obj: o, req });
const id = (prefix: string): Spec => ({ re: new RegExp(`^${prefix}-[0-9a-zA-Z][0-9a-zA-Z-]{0,79}$`), what: `an ID starting with "${prefix}-"` });
const ARN: Spec = { re: /^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:[\x21-\x7e]{1,1900}$/, what: 'an ARN' };
const TAGS = arr(obj({ Key: 'text', Value: 'text' }));
const PERM = obj({
  IpProtocol: 'str', FromPort: 'portAny', ToPort: 'portAny',
  IpRanges: arr(obj({ CidrIp: 'str', Description: 'text' })),
  Ipv6Ranges: arr(obj({ CidrIpv6: 'str', Description: 'text' })),
  PrefixListIds: arr(obj({ PrefixListId: 'str', Description: 'text' })),
  UserIdGroupPairs: arr(obj({ GroupId: 'str', VpcId: 'str', VpcPeeringConnectionId: 'str', Description: 'text' })),
}, ['IpProtocol']);
const ACTION = obj({ Type: 'str', TargetGroupArn: ARN, ForwardConfig: obj({ TargetGroups: arr(obj({ TargetGroupArn: ARN })) }) });
const ROUTE = obj({
  DestinationCidrBlock: 'str', DestinationIpv6CidrBlock: 'str', DestinationPrefixListId: 'str', GatewayId: 'str', NatGatewayId: 'str',
  VpcPeeringConnectionId: 'str', TransitGatewayId: 'str', NetworkInterfaceId: 'str', InstanceId: 'str', EgressOnlyInternetGatewayId: 'str',
  CarrierGatewayId: 'str', LocalGatewayId: 'str', CoreNetworkArn: 'str', State: 'str', Origin: 'str',
});
const PEER_INFO = obj({ VpcId: 'str', CidrBlock: 'str', CidrBlockSet: arr(obj({ CidrBlock: 'str' })), OwnerId: 'str', Region: 'str' });

const SNAPSHOT: Spec = obj({
  schemaVersion: 'int', source: 'text', tool: obj({ name: 'text', version: 'text' }),
  collectedAt: { re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})$/, what: 'an ISO 8601 time' },
  accountId: { re: /^\d{12}$/, what: 'a 12-digit AWS account ID' },
  region: { re: /^[a-z]{2}(-[a-z]+)+-\d{1,2}$/, what: 'an AWS region name' },
  ec2: obj({
    Vpcs: arr(obj({ VpcId: id('vpc'), CidrBlock: 'str', CidrBlockAssociationSet: arr(obj({ CidrBlock: 'str', CidrBlockState: obj({ State: 'str' }) })), Ipv6CidrBlockAssociationSet: arr(obj({ Ipv6CidrBlock: 'str' })), OwnerId: 'str', Tags: TAGS }, ['VpcId'])),
    Subnets: arr(obj({ SubnetId: id('subnet'), VpcId: id('vpc'), CidrBlock: 'str', AvailabilityZone: 'str', AvailabilityZoneId: 'str', Tags: TAGS }, ['SubnetId', 'VpcId', 'CidrBlock'])),
    RouteTables: arr(obj({ RouteTableId: id('rtb'), VpcId: id('vpc'), Routes: arr(ROUTE), Associations: arr(obj({ Main: 'bool', SubnetId: 'str', GatewayId: 'str', AssociationState: obj({ State: 'str' }) })), Tags: TAGS }, ['RouteTableId', 'VpcId'])),
    InternetGateways: arr(obj({ InternetGatewayId: id('igw'), Attachments: arr(obj({ VpcId: 'str', State: 'str' })) }, ['InternetGatewayId'])),
    EgressOnlyInternetGateways: arr(obj({ EgressOnlyInternetGatewayId: id('eigw'), Attachments: arr(obj({ VpcId: 'str', State: 'str' })) }, ['EgressOnlyInternetGatewayId'])),
    NatGateways: arr(obj({ NatGatewayId: id('nat'), VpcId: 'str', SubnetId: 'str', State: 'str', ConnectivityType: 'str' }, ['NatGatewayId'])),
    VpcPeeringConnections: arr(obj({ VpcPeeringConnectionId: id('pcx'), Status: obj({ Code: 'str' }), RequesterVpcInfo: PEER_INFO, AccepterVpcInfo: PEER_INFO }, ['VpcPeeringConnectionId'])),
    TransitGateways: arr(obj({ TransitGatewayId: id('tgw'), OwnerId: 'str', State: 'str', Options: obj({ SecurityGroupReferencingSupport: 'str' }) }, ['TransitGatewayId'])),
    TransitGatewayAttachments: arr(obj({ TransitGatewayAttachmentId: id('tgw-attach'), TransitGatewayId: id('tgw'), ResourceType: 'str', ResourceId: 'str', State: 'str', Association: obj({ TransitGatewayRouteTableId: 'str', State: 'str' }) }, ['TransitGatewayAttachmentId', 'TransitGatewayId'])),
    TransitGatewayVpcAttachments: arr(obj({ TransitGatewayAttachmentId: id('tgw-attach'), TransitGatewayId: 'str', VpcId: 'str', SubnetIds: arr('str'), State: 'str', Options: obj({ SecurityGroupReferencingSupport: 'str' }) }, ['TransitGatewayAttachmentId'])),
    TransitGatewayRouteTables: arr(obj({ TransitGatewayRouteTableId: id('tgw-rtb'), TransitGatewayId: id('tgw'), State: 'str' }, ['TransitGatewayRouteTableId', 'TransitGatewayId'])),
    TransitGatewayRoutes: { map: arr(obj({ DestinationCidrBlock: 'str', PrefixListId: 'str', TransitGatewayAttachments: arr(obj({ TransitGatewayAttachmentId: 'str', ResourceId: 'str', ResourceType: 'str' })), Type: 'str', State: 'str' })) },
    NetworkAcls: arr(obj({ NetworkAclId: id('acl'), VpcId: id('vpc'), IsDefault: 'bool', Entries: arr(obj({ RuleNumber: 'ruleNo', Protocol: 'str', RuleAction: { re: /^(allow|deny)$/, what: '"allow" or "deny"' }, Egress: 'bool', CidrBlock: 'str', Ipv6CidrBlock: 'str', PortRange: obj({ From: 'port', To: 'port' }), IcmpTypeCode: obj({ Type: 'int', Code: 'int' }) }, ['RuleNumber', 'Protocol', 'RuleAction', 'Egress'])), Associations: arr(obj({ SubnetId: 'str' })) }, ['NetworkAclId', 'VpcId'])),
    SecurityGroups: arr(obj({ GroupId: id('sg'), GroupName: 'text', VpcId: 'str', IpPermissions: arr(PERM), IpPermissionsEgress: arr(PERM) }, ['GroupId'])),
    SecurityGroupRules: arr(obj({ SecurityGroupRuleId: id('sgr'), GroupId: id('sg'), IsEgress: 'bool', IpProtocol: 'str', FromPort: 'portAny', ToPort: 'portAny', CidrIpv4: 'str', CidrIpv6: 'str', PrefixListId: 'str', ReferencedGroupInfo: obj({ GroupId: 'str', VpcId: 'str', VpcPeeringConnectionId: 'str', PeeringStatus: 'str' }), Description: 'text' }, ['SecurityGroupRuleId', 'GroupId', 'IsEgress', 'IpProtocol'])),
    ManagedPrefixLists: arr(obj({ PrefixListId: id('pl'), PrefixListName: 'text', AddressFamily: 'str' }, ['PrefixListId'])),
    PrefixListEntries: { map: arr(obj({ Cidr: 'str', Description: 'text' })) },
    NetworkInterfaces: arr(obj({
      NetworkInterfaceId: id('eni'), SubnetId: id('subnet'), VpcId: id('vpc'), InterfaceType: 'str', Description: 'text', RequesterManaged: 'bool', PrivateIpAddress: 'str',
      PrivateIpAddresses: arr(obj({ PrivateIpAddress: 'str', Primary: 'bool', Association: obj({ PublicIp: 'str', IpOwnerId: 'str' }) })),
      Association: obj({ PublicIp: 'str', IpOwnerId: 'str' }), Groups: arr(obj({ GroupId: 'str', GroupName: 'text' })), Attachment: obj({ InstanceId: 'str', DeviceIndex: 'int' }),
      Ipv6Addresses: arr(obj({ Ipv6Address: 'str' })), Status: 'str',
    }, ['NetworkInterfaceId', 'SubnetId', 'VpcId'])),
    Instances: arr(obj({ InstanceId: id('i'), State: obj({ Name: 'str' }), NetworkInterfaces: arr(obj({ NetworkInterfaceId: 'str', Attachment: obj({ DeviceIndex: 'int' }) })), Tags: TAGS }, ['InstanceId'])),
    VpcEndpoints: arr(obj({ VpcEndpointId: id('vpce'), VpcEndpointType: 'str', ServiceName: 'text', VpcId: 'str' }, ['VpcEndpointId'])),
  }),
  elbv2: obj({
    LoadBalancers: arr(obj({ LoadBalancerArn: ARN, LoadBalancerName: 'text', Type: 'str', Scheme: 'str', VpcId: 'str', AvailabilityZones: arr(obj({ SubnetId: 'str', ZoneName: 'str' })), SecurityGroups: arr('str') }, ['LoadBalancerArn'])),
    Listeners: arr(obj({ ListenerArn: ARN, LoadBalancerArn: ARN, Port: 'port', Protocol: 'str', DefaultActions: arr(ACTION) }, ['ListenerArn', 'LoadBalancerArn'])),
    Rules: arr(obj({ RuleArn: ARN, ListenerArn: ARN, Actions: arr(ACTION) })),
    TargetGroups: arr(obj({ TargetGroupArn: ARN, TargetGroupName: 'text', Protocol: 'str', Port: 'port', TargetType: 'str', VpcId: 'str', HealthCheckPort: 'str', LoadBalancerArns: arr(ARN) }, ['TargetGroupArn'])),
    TargetHealth: { map: arr(obj({ Target: obj({ Id: 'str', Port: 'port', AvailabilityZone: 'str' }), TargetHealth: obj({ State: 'str' }) })) },
    TargetGroupAttributes: { map: arr(obj({ Key: 'str', Value: 'text' })) },
  }),
  // Error text comes from AWS and may hold any character; it is only ever shown as text.
  errors: arr(obj({ api: 'text', message: 'msg' }), 10_000),
});

function fail(path: string, what: string): never {
  throw new SnapshotError(`Snapshot field "${path || '(top level)'}" ${what}. Collect the snapshot again with the Pinhole collector; edited or truncated files are refused.`);
}

/** Checks `value` against `spec`; returns it, with control characters in free text replaced. */
function validate(value: unknown, spec: Spec, path: string): unknown {
  if (value === undefined || value === null) return value;
  if (typeof spec === 'string') {
    switch (spec) {
      case 'str':
        if (typeof value !== 'string') fail(path, 'must be text');
        if (value.length > 512) fail(path, 'is too long');
        if (CONTROL.test(value)) fail(path, 'contains control characters');
        if (RESERVED.has(value)) fail(path, 'has a reserved value');
        return value;
      case 'text':
        // Names, tags and descriptions are free text that AWS allows wide character sets in:
        // one odd tag must not make a whole account unreadable, so control characters are
        // replaced rather than refused.
        if (typeof value !== 'string') fail(path, 'must be text');
        if (value.length > MAX_STR) fail(path, 'is too long');
        return CONTROL.test(value) ? value.replace(CONTROL_ALL, '\ufffd') : value;
      case 'msg':
        if (typeof value !== 'string' || value.length > 16_384) fail(path, 'must be text of reasonable length');
        return value;
      case 'bool':
        if (typeof value !== 'boolean') fail(path, 'must be true or false');
        return value;
      case 'int':
        if (!Number.isSafeInteger(value)) fail(path, 'must be a whole number');
        return value;
      case 'port':
        if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 65535) fail(path, 'must be a port number from 0 to 65535');
        return value;
      case 'portAny':
        if (!Number.isInteger(value) || (value as number) < -1 || (value as number) > 65535) fail(path, 'must be a port number from -1 to 65535');
        return value;
      case 'ruleNo':
        // 32767 is the IPv4 "*" rule, 32768 the IPv6 one.
        if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > 32768) fail(path, 'must be a rule number from 1 to 32768');
        return value;
    }
  }
  if ('re' in spec) {
    if (typeof value !== 'string' || value.length > 2048 || !spec.re.test(value)) fail(path, `must be ${spec.what}`);
    return value;
  }
  if ('arr' in spec) {
    if (!Array.isArray(value)) fail(path, 'must be a list');
    if (value.length > (spec.max ?? MAX_ITEMS)) fail(path, 'has too many entries');
    value.forEach((x, i) => { value[i] = validate(x, spec.arr, `${path}[${i}]`); });
    return value;
  }
  if (typeof value !== 'object' || Array.isArray(value)) fail(path, 'must be an object');
  const o = value as Record<string, unknown>;
  if ('map' in spec) {
    const keys = Object.keys(o);
    if (keys.length > MAX_ITEMS) fail(path, 'has too many entries');
    for (const k of keys) {
      if (RESERVED.has(k) || k.length > 2048 || CONTROL.test(k)) fail(`${path}.${k.slice(0, 40)}`, 'has an invalid key');
      o[k] = validate(o[k], spec.map, `${path}.${k}`);
    }
    return o;
  }
  for (const k of spec.req ?? []) if (o[k] === undefined || o[k] === null) fail(path ? `${path}.${k}` : k, 'is missing');
  for (const [k, sub] of Object.entries(spec.obj)) if (Object.hasOwn(o, k)) o[k] = validate(o[k], sub, path ? `${path}.${k}` : k);
  return o;
}
