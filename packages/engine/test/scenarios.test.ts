/**
 * Scenario tests built from small inline snapshots. They cover behaviour the
 * fixtures do not: port-range splitting in exposure, partial source sets,
 * prefix lists, ingress routing, same-subnet traffic, TGW Availability Zones,
 * TGW and inter-Region security group references.
 */
import { describe, expect, it } from 'vitest';
import { analyzeExposure, evaluatePath, normalize } from '../src/index.js';
import type { Snapshot } from '../src/index.js';

type Entry = { RuleNumber: number; Protocol: string; RuleAction: string; Egress: boolean; CidrBlock: string; PortRange?: { From: number; To: number } };
const allowAll = (egress: boolean): Entry[] => [
  { RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: egress, CidrBlock: '0.0.0.0/0' },
  { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: egress, CidrBlock: '0.0.0.0/0' },
];

/** One VPC, one public subnet, one instance with a public IP. */
function base(): Snapshot & { ec2: NonNullable<Snapshot['ec2']> } {
  return {
    schemaVersion: 1,
    ec2: {
      Vpcs: [{ VpcId: 'vpc-1', CidrBlock: '10.0.0.0/16' }],
      Subnets: [{ SubnetId: 'subnet-1', VpcId: 'vpc-1', CidrBlock: '10.0.1.0/24', AvailabilityZone: 'us-east-1a' }],
      InternetGateways: [{ InternetGatewayId: 'igw-1', Attachments: [{ VpcId: 'vpc-1', State: 'available' }] }],
      RouteTables: [
        {
          RouteTableId: 'rtb-1',
          VpcId: 'vpc-1',
          Associations: [{ Main: true }],
          Routes: [
            { DestinationCidrBlock: '10.0.0.0/16', GatewayId: 'local', State: 'active', Origin: 'CreateRouteTable' },
            { DestinationCidrBlock: '0.0.0.0/0', GatewayId: 'igw-1', State: 'active', Origin: 'CreateRoute' },
          ],
        },
      ],
      NetworkAcls: [{ NetworkAclId: 'acl-1', VpcId: 'vpc-1', IsDefault: true, Associations: [{ SubnetId: 'subnet-1' }], Entries: [...allowAll(false), ...allowAll(true)] }],
      SecurityGroups: [{ GroupId: 'sg-1', GroupName: 'one', VpcId: 'vpc-1' }],
      SecurityGroupRules: [],
      NetworkInterfaces: [
        {
          NetworkInterfaceId: 'eni-1',
          SubnetId: 'subnet-1',
          VpcId: 'vpc-1',
          InterfaceType: 'interface',
          PrivateIpAddresses: [{ PrivateIpAddress: '10.0.1.10', Primary: true, Association: { PublicIp: '52.0.0.1', IpOwnerId: 'amazon' } }],
          Groups: [{ GroupId: 'sg-1' }],
        },
      ],
    },
  };
}

const rule = (id: string, from: number, to: number, cidr: string, proto = 'tcp') => ({
  SecurityGroupRuleId: id,
  GroupId: 'sg-1',
  IsEgress: false,
  IpProtocol: proto,
  FromPort: from,
  ToPort: to,
  CidrIpv4: cidr,
});

describe('exposure: exact splitting', () => {
  it('splits an all-ports SG rule around a NACL deny on 22', () => {
    const s = base();
    s.ec2.SecurityGroupRules = [rule('sgr-all', 0, 65535, '0.0.0.0/0')];
    s.ec2.NetworkAcls![0]!.Entries = [
      { RuleNumber: 90, Protocol: '6', RuleAction: 'deny', Egress: false, CidrBlock: '0.0.0.0/0', PortRange: { From: 22, To: 22 } },
      ...allowAll(false),
      ...allowAll(true),
    ];
    const tcp = analyzeExposure(normalize(s)).findings.filter((f) => f.protocol === 'tcp');
    expect(tcp.map((f) => [f.ports.from, f.ports.to]).sort((a, b) => a[0]! - b[0]!)).toEqual([
      [0, 21],
      [23, 65535],
    ]);
    const wide = tcp.find((f) => f.ports.from === 23)!;
    expect(wide.severity).toBe('critical');
    expect(wide.reasons[0]).toMatch(/wide port range/);
    expect(wide.reasons.join()).toMatch(/RDP/);
  });

  it('reports exactly the source range a narrow SG rule admits', () => {
    const s = base();
    s.ec2.SecurityGroupRules = [rule('sgr-office', 22, 22, '203.0.113.0/24')];
    const [f] = analyzeExposure(normalize(s)).findings;
    expect(f?.sourceRanges).toEqual(['203.0.113.0/24']);
    expect(f?.sources).toEqual(['203.0.113.0/24']);
  });

  it('removes sources that an earlier NACL deny rule blocks', () => {
    const s = base();
    s.ec2.SecurityGroupRules = [rule('sgr-ssh', 22, 22, '0.0.0.0/0')];
    s.ec2.NetworkAcls![0]!.Entries = [{ RuleNumber: 50, Protocol: '-1', RuleAction: 'deny', Egress: false, CidrBlock: '198.51.100.0/24' }, ...allowAll(false), ...allowAll(true)];
    const [f] = analyzeExposure(normalize(s)).findings;
    expect(f).toBeDefined();
    expect(f!.sourceRanges.some((c) => c.startsWith('198.51.100.'))).toBe(false);
    expect(f!.sourceRanges).toContain('198.51.101.0/24');
    expect(evaluatePath(normalize(s), { from: { internet: '198.51.100.9' }, to: { eni: 'eni-1' }, protocol: 'tcp', port: 22 }).blockedAt?.stage).toBe('dest-nacl-ingress');
  });

  it('labels prefix-list sources by name', () => {
    const s = base();
    s.ec2.ManagedPrefixLists = [{ PrefixListId: 'pl-office', PrefixListName: 'office' }];
    s.ec2.PrefixListEntries = { 'pl-office': [{ Cidr: '198.51.100.0/24' }] };
    s.ec2.SecurityGroupRules = [{ SecurityGroupRuleId: 'sgr-pl', GroupId: 'sg-1', IsEgress: false, IpProtocol: 'tcp', FromPort: 22, ToPort: 22, PrefixListId: 'pl-office' }];
    const [f] = analyzeExposure(normalize(s)).findings;
    expect(f?.sources).toEqual(['pl-office (office)']);
    expect(f?.sourceRanges).toEqual(['198.51.100.0/24']);
  });

  it('reports ICMP echo as informational', () => {
    const s = base();
    s.ec2.SecurityGroupRules = [{ SecurityGroupRuleId: 'sgr-ping', GroupId: 'sg-1', IsEgress: false, IpProtocol: 'icmp', FromPort: 8, ToPort: -1, CidrIpv4: '0.0.0.0/0' }];
    const [f] = analyzeExposure(normalize(s)).findings;
    expect(f?.protocol).toBe('icmp');
    expect(f?.severity).toBe('info');
  });

  it('marks paths through an IGW gateway route table as unknown and does not report them', () => {
    const s = base();
    s.ec2.SecurityGroupRules = [rule('sgr-ssh', 22, 22, '0.0.0.0/0')];
    s.ec2.RouteTables!.push({ RouteTableId: 'rtb-edge', VpcId: 'vpc-1', Associations: [{ GatewayId: 'igw-1' }], Routes: [] });
    const report = analyzeExposure(normalize(s));
    expect(report.findings).toEqual([]);
    expect(report.warnings.map((w) => w.code)).toContain('gateway-route-table');
    const r = evaluatePath(normalize(s), { from: { internet: '8.8.8.8' }, to: { eni: 'eni-1' }, protocol: 'tcp', port: 22 });
    expect(r.verdict).toBe('unknown');
    expect(r.blockedAt?.stage).toBe('scope');
  });
});

describe('paths: subnet and VPC edge cases', () => {
  it('does not evaluate NACLs between interfaces in the same subnet', () => {
    const s = base();
    s.ec2.NetworkAcls![0]!.Entries = [
      { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: false, CidrBlock: '0.0.0.0/0' },
      { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: true, CidrBlock: '0.0.0.0/0' },
    ];
    s.ec2.SecurityGroupRules = [
      rule('sgr-in', 5432, 5432, '10.0.1.0/24'),
      { SecurityGroupRuleId: 'sgr-out', GroupId: 'sg-1', IsEgress: true, IpProtocol: '-1', FromPort: -1, ToPort: -1, CidrIpv4: '0.0.0.0/0' },
    ];
    s.ec2.NetworkInterfaces!.push({ NetworkInterfaceId: 'eni-2', SubnetId: 'subnet-1', VpcId: 'vpc-1', InterfaceType: 'interface', PrivateIpAddresses: [{ PrivateIpAddress: '10.0.1.20', Primary: true }], Groups: [{ GroupId: 'sg-1' }] });
    const r = evaluatePath(normalize(s), { from: { eni: 'eni-2' }, to: { eni: 'eni-1' }, protocol: 'tcp', port: 5432 });
    expect(r.verdict).toBe('reachable');
    expect(r.hops.some((h) => h.stage.includes('nacl'))).toBe(false);
  });

  it('checks the source security group outbound rules', () => {
    const s = base();
    s.ec2.SecurityGroupRules = [rule('sgr-in', 5432, 5432, '10.0.0.0/16')]; // no egress rules at all
    s.ec2.NetworkInterfaces!.push({ NetworkInterfaceId: 'eni-2', SubnetId: 'subnet-1', VpcId: 'vpc-1', InterfaceType: 'interface', PrivateIpAddresses: [{ PrivateIpAddress: '10.0.1.20', Primary: true }], Groups: [{ GroupId: 'sg-1' }] });
    const r = evaluatePath(normalize(s), { from: { eni: 'eni-2' }, to: { eni: 'eni-1' }, protocol: 'tcp', port: 5432 });
    expect(r.blockedAt?.stage).toBe('source-sg-egress');
  });
});

/** Two VPCs joined by a transit gateway; vpc-b only has an attachment subnet in us-east-1a. */
function tgwPair(opts: { tgwSgRef: boolean; srcAz: string }) {
  const s = base();
  const e = s.ec2;
  e.Vpcs!.push({ VpcId: 'vpc-b', CidrBlock: '10.1.0.0/16' });
  e.Subnets = [
    { SubnetId: 'subnet-1', VpcId: 'vpc-1', CidrBlock: '10.0.1.0/24', AvailabilityZone: opts.srcAz },
    { SubnetId: 'subnet-1-tgw', VpcId: 'vpc-1', CidrBlock: '10.0.255.0/28', AvailabilityZone: 'us-east-1a' },
    { SubnetId: 'subnet-b', VpcId: 'vpc-b', CidrBlock: '10.1.1.0/24', AvailabilityZone: 'us-east-1a' },
  ];
  e.RouteTables = [
    { RouteTableId: 'rtb-1', VpcId: 'vpc-1', Associations: [{ Main: true }], Routes: [
      { DestinationCidrBlock: '10.0.0.0/16', GatewayId: 'local', State: 'active', Origin: 'CreateRouteTable' },
      { DestinationCidrBlock: '10.1.0.0/16', TransitGatewayId: 'tgw-1', State: 'active', Origin: 'CreateRoute' },
    ] },
    { RouteTableId: 'rtb-b', VpcId: 'vpc-b', Associations: [{ Main: true }], Routes: [
      { DestinationCidrBlock: '10.1.0.0/16', GatewayId: 'local', State: 'active', Origin: 'CreateRouteTable' },
      { DestinationCidrBlock: '10.0.0.0/16', TransitGatewayId: 'tgw-1', State: 'active', Origin: 'CreateRoute' },
    ] },
  ];
  e.NetworkAcls = [
    { NetworkAclId: 'acl-1', VpcId: 'vpc-1', IsDefault: true, Associations: [], Entries: [...allowAll(false), ...allowAll(true)] },
    { NetworkAclId: 'acl-b', VpcId: 'vpc-b', IsDefault: true, Associations: [], Entries: [...allowAll(false), ...allowAll(true)] },
  ];
  e.TransitGateways = [{ TransitGatewayId: 'tgw-1', Options: { SecurityGroupReferencingSupport: opts.tgwSgRef ? 'enable' : 'disable' } }];
  e.TransitGatewayAttachments = [
    { TransitGatewayAttachmentId: 'tgw-attach-1', TransitGatewayId: 'tgw-1', ResourceType: 'vpc', ResourceId: 'vpc-1', State: 'available', Association: { TransitGatewayRouteTableId: 'tgw-rtb-1', State: 'associated' } },
    { TransitGatewayAttachmentId: 'tgw-attach-b', TransitGatewayId: 'tgw-1', ResourceType: 'vpc', ResourceId: 'vpc-b', State: 'available', Association: { TransitGatewayRouteTableId: 'tgw-rtb-1', State: 'associated' } },
  ];
  e.TransitGatewayVpcAttachments = [
    { TransitGatewayAttachmentId: 'tgw-attach-1', VpcId: 'vpc-1', SubnetIds: ['subnet-1-tgw'], Options: { SecurityGroupReferencingSupport: 'enable' } },
    { TransitGatewayAttachmentId: 'tgw-attach-b', VpcId: 'vpc-b', SubnetIds: ['subnet-b'], Options: { SecurityGroupReferencingSupport: 'enable' } },
  ];
  e.TransitGatewayRouteTables = [{ TransitGatewayRouteTableId: 'tgw-rtb-1', TransitGatewayId: 'tgw-1' }];
  e.TransitGatewayRoutes = {
    'tgw-rtb-1': [
      { DestinationCidrBlock: '10.0.0.0/16', TransitGatewayAttachments: [{ TransitGatewayAttachmentId: 'tgw-attach-1' }], Type: 'propagated', State: 'active' },
      { DestinationCidrBlock: '10.1.0.0/16', TransitGatewayAttachments: [{ TransitGatewayAttachmentId: 'tgw-attach-b' }], Type: 'propagated', State: 'active' },
    ],
  };
  e.SecurityGroups!.push({ GroupId: 'sg-b', GroupName: 'b', VpcId: 'vpc-b' });
  e.SecurityGroupRules = [
    { SecurityGroupRuleId: 'sgr-1-out', GroupId: 'sg-1', IsEgress: true, IpProtocol: '-1', FromPort: -1, ToPort: -1, CidrIpv4: '0.0.0.0/0' },
    { SecurityGroupRuleId: 'sgr-b-from-1', GroupId: 'sg-b', IsEgress: false, IpProtocol: 'tcp', FromPort: 443, ToPort: 443, ReferencedGroupInfo: { GroupId: 'sg-1' } },
  ];
  e.NetworkInterfaces!.push({ NetworkInterfaceId: 'eni-b', SubnetId: 'subnet-b', VpcId: 'vpc-b', InterfaceType: 'interface', PrivateIpAddresses: [{ PrivateIpAddress: '10.1.1.10', Primary: true }], Groups: [{ GroupId: 'sg-b' }] });
  return s;
}

describe('paths: transit gateway', () => {
  const q = { from: { eni: 'eni-1' }, to: { eni: 'eni-b' }, protocol: 'tcp', port: 443 };

  it('matches an inbound SG reference across a TGW when referencing support is on', () => {
    const r = evaluatePath(normalize(tgwPair({ tgwSgRef: true, srcAz: 'us-east-1a' })), q);
    expect(r.verdict).toBe('reachable');
    expect(r.hops.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds).toEqual(['sgr-b-from-1']);
  });

  it('does not match it when the transit gateway option is off', () => {
    const r = evaluatePath(normalize(tgwPair({ tgwSgRef: false, srcAz: 'us-east-1a' })), q);
    expect(r.blockedAt?.stage).toBe('dest-sg-ingress');
  });

  it('blocks sources in an AZ without an attachment subnet', () => {
    const r = evaluatePath(normalize(tgwPair({ tgwSgRef: true, srcAz: 'us-east-1b' })), q);
    expect(r.verdict).toBe('blocked');
    expect(r.blockedAt?.stage).toBe('tgw-attachment');
  });

  it('skips NACLs for TGW -> instance when the instance shares the attachment subnet', () => {
    const s = tgwPair({ tgwSgRef: true, srcAz: 'us-east-1a' });
    // Deny everything inbound in vpc-b. The doc says TGW -> instance in the same
    // subnet is not evaluated, but instance -> TGW (the return) is.
    s.ec2.NetworkAcls![1]!.Entries = [
      { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: false, CidrBlock: '0.0.0.0/0' },
      ...allowAll(true),
    ];
    const r = evaluatePath(normalize(s), q);
    expect(r.hops.some((h) => h.stage === 'dest-nacl-ingress')).toBe(false);
    // The return packet leaves eni-b towards the TGW: outbound and inbound rules
    // of the shared subnet are evaluated, so the inbound deny blocks it.
    expect(r.blockedAt?.stage).toBe('return-nacl');
  });
});

describe('paths: inter-Region peering', () => {
  it('does not match SG references across an inter-Region peering', () => {
    const s = tgwPair({ tgwSgRef: true, srcAz: 'us-east-1a' });
    const e = s.ec2;
    e.RouteTables![0]!.Routes![1] = { DestinationCidrBlock: '10.1.0.0/16', VpcPeeringConnectionId: 'pcx-1', State: 'active', Origin: 'CreateRoute' };
    e.RouteTables![1]!.Routes![1] = { DestinationCidrBlock: '10.0.0.0/16', VpcPeeringConnectionId: 'pcx-1', State: 'active', Origin: 'CreateRoute' };
    e.VpcPeeringConnections = [{
      VpcPeeringConnectionId: 'pcx-1', Status: { Code: 'active' },
      RequesterVpcInfo: { VpcId: 'vpc-1', CidrBlock: '10.0.0.0/16', Region: 'us-east-1' },
      AccepterVpcInfo: { VpcId: 'vpc-b', CidrBlock: '10.1.0.0/16', Region: 'us-east-1' },
    }];
    const same = evaluatePath(normalize(s), { from: { eni: 'eni-1' }, to: { eni: 'eni-b' }, protocol: 'tcp', port: 443 });
    expect(same.verdict).toBe('reachable');
    e.VpcPeeringConnections[0]!.AccepterVpcInfo!.Region = 'eu-west-1';
    const cross = evaluatePath(normalize(s), { from: { eni: 'eni-1' }, to: { eni: 'eni-b' }, protocol: 'tcp', port: 443 });
    expect(cross.blockedAt?.stage).toBe('dest-sg-ingress');
  });
});

describe('paths: traffic leaving through gateways or appliances', () => {
  it('is unknown, not blocked, when a route sends it to an appliance interface', () => {
    const s = tgwPair({ tgwSgRef: true, srcAz: 'us-east-1a' });
    s.ec2.RouteTables![0]!.Routes![1] = { DestinationCidrBlock: '10.1.0.0/16', NetworkInterfaceId: 'eni-appliance', State: 'active', Origin: 'CreateRoute' };
    const r = evaluatePath(normalize(s), { from: { eni: 'eni-1' }, to: { eni: 'eni-b' }, protocol: 'tcp', port: 443 });
    expect(r.verdict).toBe('unknown');
    expect(r.blockedAt?.stage).toBe('scope');
    expect(analyzeExposure(normalize(s)).warnings.map((w) => w.code)).toContain('middlebox-route');
  });

  it('is unknown when the reply to an internet client goes to a firewall endpoint', () => {
    const s = base();
    s.ec2.SecurityGroupRules = [rule('sgr-ssh', 22, 22, '0.0.0.0/0')];
    s.ec2.RouteTables![0]!.Routes![1] = { DestinationCidrBlock: '0.0.0.0/0', GatewayId: 'vpce-0firewall', State: 'active', Origin: 'CreateRoute' };
    const r = evaluatePath(normalize(s), { from: { internet: '8.8.8.8' }, to: { eni: 'eni-1' }, protocol: 'tcp', port: 22 });
    expect(r.verdict).toBe('unknown');
    expect(r.blockedAt?.stage).toBe('return-route');
    expect(analyzeExposure(normalize(s)).warnings.map((w) => w.code)).toContain('network-firewall-or-unknown-endpoint');
  });

  it('warns when an interface uses a security group missing from the snapshot', () => {
    const s = base();
    s.ec2.NetworkInterfaces![0]!.Groups = [{ GroupId: 'sg-gone' }];
    expect(analyzeExposure(normalize(s)).warnings.map((w) => w.code)).toContain('security-group-missing');
  });
});
