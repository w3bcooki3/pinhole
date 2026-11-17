#!/usr/bin/env node
// A large, realistic synthetic snapshot for scale testing: node scripts/synth-account.mjs [servers] [vpcs] > big.json
// Three tiers per VPC (public web, private app behind NAT, data), security groups that reference each other,
// a few rules open to the world, internet-facing load balancers, and a transit gateway joining the VPCs.
// Deterministic: the same arguments give the same file.
const N = Number(process.argv[2] ?? 3000);
const V = Number(process.argv[3] ?? 8);
const ACCOUNT = '999900001111';
const REGION = 'us-east-1';
const AZS = ['a', 'b', 'c'];
const TIERS = ['web', 'app', 'data'];
const SERVICES = { web: [[443], [80, 443], [8080]], app: [[8080], [9000], [8443], [5000]], data: [[5432], [3306], [6379], [27017], [9200]] };

let seed = 7;
const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const pick = (a) => a[Math.floor(rnd() * a.length)];

const ec2 = { Vpcs: [], Subnets: [], RouteTables: [], InternetGateways: [], NatGateways: [], NetworkAcls: [], SecurityGroups: [], SecurityGroupRules: [], NetworkInterfaces: [], Instances: [], TransitGateways: [], TransitGatewayAttachments: [], TransitGatewayVpcAttachments: [], TransitGatewayRouteTables: [], TransitGatewayRoutes: {} };
const elbv2 = { LoadBalancers: [], Listeners: [], TargetGroups: [], TargetHealth: {}, TargetGroupAttributes: {} };

ec2.TransitGateways.push({ TransitGatewayId: 'tgw-core', State: 'available', Options: { SecurityGroupReferencingSupport: 'disable' } });
ec2.TransitGatewayRouteTables.push({ TransitGatewayRouteTableId: 'tgw-rtb-core', TransitGatewayId: 'tgw-core', State: 'available' });
ec2.TransitGatewayRoutes['tgw-rtb-core'] = [];

let rule = 0;
const addRule = (groupId, r) => ec2.SecurityGroupRules.push({ SecurityGroupRuleId: `sgr-${(rule++).toString(16).padStart(8, '0')}`, GroupId: groupId, IsEgress: false, ...r });
const egressAll = (groupId) => ec2.SecurityGroupRules.push({ SecurityGroupRuleId: `sgr-${(rule++).toString(16).padStart(8, '0')}`, GroupId: groupId, IsEgress: true, IpProtocol: '-1', FromPort: -1, ToPort: -1, CidrIpv4: '0.0.0.0/0' });

const groups = []; // { id, vpc, tier, ports }
const subnetsOf = {}; // vpc|tier -> subnet ids
for (let v = 0; v < V; v++) {
  const vpc = `vpc-${v}`;
  const cidr = `10.${v}.0.0/16`;
  ec2.Vpcs.push({ VpcId: vpc, CidrBlock: cidr, OwnerId: ACCOUNT });
  ec2.InternetGateways.push({ InternetGatewayId: `igw-${v}`, Attachments: [{ VpcId: vpc, State: 'available' }] });
  const att = `tgw-attach-${v}`;
  const tgwSubnets = [];
  const nacl = { NetworkAclId: `acl-${v}`, VpcId: vpc, IsDefault: true, Associations: [], Entries: [] };
  // A realistic NACL: a few denies for known-bad ranges, then allow everything.
  for (let i = 0; i < 6; i++) nacl.Entries.push({ RuleNumber: 50 + i, Protocol: '-1', RuleAction: 'deny', Egress: false, CidrBlock: `198.18.${i * 8}.0/21` });
  nacl.Entries.push({ RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: false, CidrBlock: '0.0.0.0/0' }, { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: false, CidrBlock: '0.0.0.0/0' });
  nacl.Entries.push({ RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: true, CidrBlock: '0.0.0.0/0' }, { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: true, CidrBlock: '0.0.0.0/0' });
  ec2.NetworkAcls.push(nacl);
  TIERS.forEach((tier, t) => {
    const rtb = { RouteTableId: `rtb-${v}-${tier}`, VpcId: vpc, Associations: [], Routes: [{ DestinationCidrBlock: cidr, State: 'active', Origin: 'CreateRouteTable', GatewayId: 'local' }, { DestinationCidrBlock: '10.0.0.0/8', State: 'active', Origin: 'CreateRoute', TransitGatewayId: 'tgw-core' }] };
    if (tier === 'web') rtb.Routes.push({ DestinationCidrBlock: '0.0.0.0/0', State: 'active', Origin: 'CreateRoute', GatewayId: `igw-${v}` });
    if (tier === 'app') rtb.Routes.push({ DestinationCidrBlock: '0.0.0.0/0', State: 'active', Origin: 'CreateRoute', NatGatewayId: `nat-${v}` });
    ec2.RouteTables.push(rtb);
    subnetsOf[`${vpc}|${tier}`] = [];
    AZS.forEach((az, a) => {
      const id = `subnet-${v}-${tier}-${az}`;
      ec2.Subnets.push({ SubnetId: id, VpcId: vpc, CidrBlock: `10.${v}.${t * 64 + a * 16}.0/20`, AvailabilityZone: `${REGION}${az}` });
      rtb.Associations.push({ SubnetId: id });
      nacl.Associations.push({ SubnetId: id });
      subnetsOf[`${vpc}|${tier}`].push(id);
      if (tier === 'app') tgwSubnets.push(id);
    });
  });
  ec2.NatGateways.push({ NatGatewayId: `nat-${v}`, VpcId: vpc, SubnetId: `subnet-${v}-web-a`, State: 'available', ConnectivityType: 'public', NatGatewayAddresses: [{ PublicIp: `52.${v}.0.1` }] });
  ec2.TransitGatewayAttachments.push({ TransitGatewayAttachmentId: att, TransitGatewayId: 'tgw-core', ResourceType: 'vpc', ResourceId: vpc, State: 'available', Association: { TransitGatewayRouteTableId: 'tgw-rtb-core', State: 'associated' } });
  ec2.TransitGatewayVpcAttachments.push({ TransitGatewayAttachmentId: att, TransitGatewayId: 'tgw-core', VpcId: vpc, SubnetIds: tgwSubnets, State: 'available', Options: { ApplianceModeSupport: 'disable' } });
  ec2.TransitGatewayRoutes['tgw-rtb-core'].push({ DestinationCidrBlock: cidr, TransitGatewayAttachments: [{ TransitGatewayAttachmentId: att, ResourceId: vpc, ResourceType: 'vpc' }], Type: 'propagated', State: 'active' });

  // Groups: one per service per tier, plus a shared admin group and a monitoring group.
  const admin = `sg-${v}-admin`;
  ec2.SecurityGroups.push({ GroupId: admin, GroupName: `admin-${v}`, VpcId: vpc });
  addRule(admin, { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, CidrIpv4: '10.0.0.0/8' });
  if (v % 3 === 0) addRule(admin, { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, CidrIpv4: '0.0.0.0/0' });
  egressAll(admin);
  const mon = `sg-${v}-mon`;
  ec2.SecurityGroups.push({ GroupId: mon, GroupName: `monitoring-${v}`, VpcId: vpc });
  addRule(mon, { IpProtocol: 'tcp', FromPort: 9100, ToPort: 9100, CidrIpv4: '10.0.0.0/8' });
  egressAll(mon);
  const perTier = {};
  for (const tier of TIERS) {
    perTier[tier] = [];
    const count = tier === 'app' ? 12 : 8;
    for (let k = 0; k < count; k++) {
      const id = `sg-${v}-${tier}-${k}`;
      const ports = pick(SERVICES[tier]);
      ec2.SecurityGroups.push({ GroupId: id, GroupName: `${tier}-${v}-${k}`, VpcId: vpc });
      groups.push({ id, vpc, tier, ports });
      perTier[tier].push(id);
      egressAll(id);
    }
  }
  // Rules: web open to the world on its ports; app from web groups; data from app groups, sometimes from a CIDR.
  for (const g of groups.filter((x) => x.vpc === vpc)) {
    for (const p of g.ports) {
      if (g.tier === 'web') addRule(g.id, { IpProtocol: 'tcp', FromPort: p, ToPort: p, CidrIpv4: '0.0.0.0/0' });
      if (g.tier === 'app') for (let j = 0; j < 3; j++) addRule(g.id, { IpProtocol: 'tcp', FromPort: p, ToPort: p, ReferencedGroupInfo: { GroupId: pick(perTier.web) } });
      if (g.tier === 'data') {
        for (let j = 0; j < 4; j++) addRule(g.id, { IpProtocol: 'tcp', FromPort: p, ToPort: p, ReferencedGroupInfo: { GroupId: pick(perTier.app) } });
        if (rnd() < 0.3) addRule(g.id, { IpProtocol: 'tcp', FromPort: p, ToPort: p, CidrIpv4: `10.${Math.floor(rnd() * V)}.0.0/16` });
        if (rnd() < 0.04) addRule(g.id, { IpProtocol: 'tcp', FromPort: p, ToPort: p, CidrIpv4: '0.0.0.0/0' });
      }
    }
    // Legacy clutter: narrow and wide CIDR rules that real accounts accumulate.
    for (let j = 0; j < 5; j++) {
      const p = 1024 + Math.floor(rnd() * 60000);
      addRule(g.id, { IpProtocol: rnd() < 0.8 ? 'tcp' : 'udp', FromPort: p, ToPort: p + (rnd() < 0.2 ? 100 : 0), CidrIpv4: `${pick([10, 172, 192])}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}.0/24` });
    }
  }

  // Load balancers: a few internet-facing ALBs per VPC forwarding to app instances (filled in below).
  for (let k = 0; k < 4; k++) {
    const name = `alb-${v}-${k}`;
    const arn = `arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:loadbalancer/app/${name}/${(v * 16 + k).toString(16).padStart(16, '0')}`;
    const sg = `sg-${v}-albsg-${k}`;
    ec2.SecurityGroups.push({ GroupId: sg, GroupName: `${name}-sg`, VpcId: vpc });
    addRule(sg, { IpProtocol: 'tcp', FromPort: 443, ToPort: 443, CidrIpv4: '0.0.0.0/0' });
    egressAll(sg);
    elbv2.LoadBalancers.push({ LoadBalancerArn: arn, LoadBalancerName: name, Type: 'application', Scheme: 'internet-facing', VpcId: vpc, SecurityGroups: [sg], AvailabilityZones: AZS.map((az) => ({ SubnetId: `subnet-${v}-web-${az}`, ZoneName: `${REGION}${az}` })) });
    const tg = `arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:targetgroup/${name}-tg/${(v * 16 + k).toString(16).padStart(16, '0')}`;
    elbv2.TargetGroups.push({ TargetGroupArn: tg, TargetGroupName: `${name}-tg`, Protocol: 'HTTP', Port: 8080, TargetType: 'instance', VpcId: vpc });
    elbv2.Listeners.push({ ListenerArn: `${arn.replace('loadbalancer', 'listener')}/l1`, LoadBalancerArn: arn, Port: 443, Protocol: 'HTTPS', DefaultActions: [{ Type: 'forward', TargetGroupArn: tg }] });
    elbv2.TargetHealth[tg] = [];
    elbv2.TargetGroupAttributes[tg] = [];
    // Let the ALB reach app groups on 8080.
    for (const g of perTier.app.slice(k * 3, k * 3 + 3)) addRule(g, { IpProtocol: 'tcp', FromPort: 8080, ToPort: 8080, ReferencedGroupInfo: { GroupId: sg } });
  }
}

// Servers: spread over VPCs and tiers; 60% app, 25% data, 15% web. A third of web servers have a public IP.
for (let i = 0; i < N; i++) {
  const v = i % V;
  const vpc = `vpc-${v}`;
  const r = rnd();
  const tier = r < 0.15 ? 'web' : r < 0.75 ? 'app' : 'data';
  const t = TIERS.indexOf(tier);
  const subnet = pick(subnetsOf[`${vpc}|${tier}`]);
  const a = AZS.indexOf(subnet.slice(-1));
  const host = 4 + Math.floor(i / V);
  const ip = `10.${v}.${t * 64 + a * 16 + (host >> 8)}.${host & 255}`;
  const own = pick(groups.filter((g) => g.vpc === vpc && g.tier === tier)).id;
  const sgs = [{ GroupId: own }, { GroupId: `sg-${v}-mon` }];
  if (rnd() < 0.25) sgs.push({ GroupId: `sg-${v}-admin` });
  const eni = { NetworkInterfaceId: `eni-${i.toString(16).padStart(8, '0')}`, SubnetId: subnet, VpcId: vpc, InterfaceType: 'interface', PrivateIpAddress: ip, PrivateIpAddresses: [{ PrivateIpAddress: ip, Primary: true }], Groups: sgs, Attachment: { InstanceId: `i-${i.toString(16).padStart(8, '0')}`, DeviceIndex: 0 }, Status: 'in-use' };
  if (tier === 'web' && rnd() < 0.33) eni.PrivateIpAddresses[0].Association = { PublicIp: `54.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`, IpOwnerId: 'amazon' };
  ec2.NetworkInterfaces.push(eni);
  ec2.Instances.push({ InstanceId: eni.Attachment.InstanceId, State: { Name: 'running' }, Tags: [{ Key: 'Name', Value: `${tier}-${v}-${i}` }], NetworkInterfaces: [{ NetworkInterfaceId: eni.NetworkInterfaceId, Attachment: { DeviceIndex: 0 } }] });
  if (tier === 'app' && rnd() < 0.2) {
    const tgs = elbv2.TargetGroups.filter((g) => g.VpcId === vpc);
    elbv2.TargetHealth[pick(tgs).TargetGroupArn].push({ Target: { Id: eni.Attachment.InstanceId, Port: 8080 } });
  }
}

process.stdout.write(JSON.stringify({ schemaVersion: 1, source: 'synthetic', accountId: ACCOUNT, region: REGION, collectedAt: '2026-11-15T12:00:00Z', ec2, elbv2 }));
