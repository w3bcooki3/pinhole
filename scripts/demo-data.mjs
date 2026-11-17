// Demo environment shown by the web console before you load your own data.
// Built from the fixtures; every account ID and address is a documentation
// value, not a real resource.
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const fx = (n) => JSON.parse(readFileSync(join(root, 'fixtures', n, 'snapshot.json'), 'utf8'));

// ---------------------------------------------------------------- demo data
// A richer environment for the prototypes, built from fixture 06. Example data
// only: account IDs and addresses are documentation values.
function richProd() {
  const s = fx('06-public-ip-without-igw-route');
  s.accountId = '111122223333';
  s.region = 'us-east-1';
  s.collectedAt = '2026-11-12T09:41:00Z';
  s.ec2.Vpcs[0].VpcId = 'vpc-0a1b2c3d';
  const rename = (o) => JSON.parse(JSON.stringify(o).replaceAll('"vpc-1"', '"vpc-0a1b2c3d"'));
  Object.assign(s.ec2, rename(s.ec2));
  s.ec2.Vpcs[0].Ipv6CidrBlockAssociationSet = [{ Ipv6CidrBlock: '2600:1f18:abcd::/56' }];
  s.ec2.Instances = [{ InstanceId: 'i-public', State: { Name: 'running' }, Tags: [{ Key: 'Name', Value: 'bastion-prod' }], NetworkInterfaces: [{ NetworkInterfaceId: 'eni-public', Attachment: { DeviceIndex: 0 } }] }];
  const add = [
    ['win-jump-01', [[3389, 3389, '0.0.0.0/0']]],
    ['analytics-db', [[5432, 5432, '0.0.0.0/0']]],
    ['session-cache', [[6379, 6379, '203.0.113.0/24']]],
    ['legacy-batch', [[0, 65535, '0.0.0.0/0']]],
    ['grafana-ops', [[3000, 3000, '0.0.0.0/0']]],
    ['k8s-control', [[6443, 6443, '198.51.100.0/24']]],
    ['web-02', [[80, 80, '0.0.0.0/0'], [443, 443, '0.0.0.0/0']]],
    ['mail-relay', [[25, 25, '0.0.0.0/0']]],
  ];
  add.forEach(([name, rules], i) => {
    const sg = `sg-${name}`;
    s.ec2.SecurityGroups.push({ GroupId: sg, GroupName: name, VpcId: 'vpc-0a1b2c3d' });
    for (const [from, to, cidr] of rules) {
      s.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: `sgr-0${(i * 7919 + from).toString(16).padStart(8, '0')}`, GroupId: sg, IsEgress: false, IpProtocol: 'tcp', FromPort: from, ToPort: to, CidrIpv4: cidr });
    }
    s.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: `sgr-0e${i}egress000`, GroupId: sg, IsEgress: true, IpProtocol: '-1', FromPort: -1, ToPort: -1, CidrIpv4: '0.0.0.0/0' });
    const eni = `eni-0${(4096 + i * 977).toString(16)}${name.length}`;
    s.ec2.NetworkInterfaces.push({
      NetworkInterfaceId: eni, SubnetId: 'subnet-public', VpcId: 'vpc-0a1b2c3d', InterfaceType: 'interface',
      PrivateIpAddresses: [{ PrivateIpAddress: `10.0.1.${40 + i}`, Primary: true, Association: { PublicIp: `192.0.2.${100 + i * 7}`, IpOwnerId: i % 2 ? '111122223333' : 'amazon' } }],
      Groups: [{ GroupId: sg }], Attachment: { InstanceId: `i-0${(52000 + i * 311).toString(16)}`, DeviceIndex: 0 },
    });
    s.ec2.Instances.push({ InstanceId: `i-0${(52000 + i * 311).toString(16)}`, State: { Name: 'running' }, Tags: [{ Key: 'Name', Value: name }], NetworkInterfaces: [{ NetworkInterfaceId: eni, Attachment: { DeviceIndex: 0 } }] });
  });
  // An inspection route the engine does not model, so Coverage has something to show.
  s.ec2.RouteTables[1].Routes.push({ DestinationCidrBlock: '10.99.0.0/16', GatewayId: 'vpce-0fw1a2b3c4d', State: 'active', Origin: 'CreateRoute' });
  return s;
}
// The same account a week earlier, so the Compare page has something to show:
// RDP on win-jump-01 and Postgres on analytics-db were opened since, and a
// Prometheus port on grafana-ops was closed.
function richProdEarlier() {
  const s = richProd();
  s.collectedAt = '2026-11-05T09:38:00Z';
  const rule = (group, port) => s.ec2.SecurityGroupRules.find((r) => r.GroupId === group && r.FromPort === port && !r.IsEgress);
  s.ec2.SecurityGroupRules = s.ec2.SecurityGroupRules.filter((r) => r !== rule('sg-win-jump-01', 3389));
  rule('sg-analytics-db', 5432).CidrIpv4 = '10.0.0.0/8';
  s.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: 'sgr-0prometheus01', GroupId: 'sg-grafana-ops', IsEgress: false, IpProtocol: 'tcp', FromPort: 9090, ToPort: 9090, CidrIpv4: '0.0.0.0/0', Description: 'Prometheus' });
  return s;
}
// Two accounts linked by VPC peering (fixture 11), moved to eu-central-1 so
// they do not collide with the other demo scopes.
const linked = (file) => JSON.parse(readFileSync(join(root, 'fixtures', '11-cross-account-peering', file), 'utf8').replaceAll('us-east-1', 'eu-central-1'));
// Fixture 10 plus a dual-stack ALB with no public IPv4: reachable over IPv6 only.
function edge() {
  const s = fx('10-ipv6-exposure');
  const arn = 'arn:aws:elasticloadbalancing:us-east-2:444455556666:loadbalancer/app/storefront/5e6f7a8b';
  s.ec2.NetworkInterfaces.push({ NetworkInterfaceId: 'eni-0storefront', SubnetId: 'subnet-dual', VpcId: 'vpc-1', InterfaceType: 'interface', Description: 'ELB app/storefront/5e6f7a8b', PrivateIpAddresses: [{ PrivateIpAddress: '10.0.1.50', Primary: true }], Ipv6Addresses: [{ Ipv6Address: '2600:1f18:aaaa:ff01::50' }], Groups: [{ GroupId: 'sg-storefront' }] });
  s.ec2.SecurityGroups.push({ GroupId: 'sg-storefront', GroupName: 'storefront', VpcId: 'vpc-1' });
  s.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: 'sgr-0storefront443', GroupId: 'sg-storefront', IsEgress: false, IpProtocol: 'tcp', FromPort: 443, ToPort: 443, CidrIpv6: '::/0' });
  s.elbv2 = {
    LoadBalancers: [{ LoadBalancerArn: arn, LoadBalancerName: 'storefront', Type: 'application', Scheme: 'internet-facing', VpcId: 'vpc-1', IpAddressType: 'dualstack-without-public-ipv4', AvailabilityZones: [{ SubnetId: 'subnet-dual', ZoneName: 'us-east-1a' }], SecurityGroups: ['sg-storefront'] }],
    Listeners: [{ ListenerArn: `${arn}/l443`, LoadBalancerArn: arn, Port: 443, Protocol: 'HTTPS', DefaultActions: [{ Type: 'forward', TargetGroupArn: `${arn}/tg` }] }],
    TargetGroups: [{ TargetGroupArn: `${arn}/tg`, TargetGroupName: 'storefront', Protocol: 'HTTP', Port: 8080, TargetType: 'instance', VpcId: 'vpc-1' }],
    TargetHealth: { [`${arn}/tg`]: [{ Target: { Id: 'i-dual', Port: 8080 } }] },
  };
  return s;
}
/** A fixture moved to another account and region, ARNs and zone names included. */
const moved = (s, account, region) => JSON.parse(JSON.stringify(s).replaceAll('111122223333', account).replaceAll('us-east-1', region));
const withScope = (s, account, region) => ({ ...s, accountId: account, region, collectedAt: '2026-11-12T09:44:00Z' });
export const DEMO = [
  { name: 'prod us-east-1', snapshot: richProd() },
  { name: 'prod eu-west-1', snapshot: withScope(fx('07-alb-private-targets'), '111122223333', 'eu-west-1') },
  { name: 'platform us-east-1', snapshot: withScope(fx('08-nlb-client-ip-preservation'), '444455556666', 'us-east-1') },
  { name: 'platform ap-southeast-2', snapshot: withScope(fx('01-nacl-ephemeral-return'), '444455556666', 'ap-southeast-2') },
  { name: 'orders us-west-2', snapshot: withScope(fx('09-lateral-movement'), '111122223333', 'us-west-2') },
  { name: 'edge us-east-2', snapshot: withScope(edge(), '444455556666', 'us-east-2') },
  { name: 'shared-services eu-central-1', snapshot: linked('account-a/snapshot.json') },
  { name: 'payments eu-central-1', snapshot: linked('account-b/snapshot.json') },
  { name: 'inspected us-east-1', snapshot: withScope(moved(fx('12-network-firewall'), '777788889999', 'us-east-1'), '777788889999', 'us-east-1') },
  { name: 'network-hub us-west-1', snapshot: withScope(moved(fx('13-inspection-vpc'), '777788889999', 'us-west-1'), '777788889999', 'us-west-1') },
  { name: 'datacenter-link us-west-2', snapshot: withScope(moved(fx('15-hybrid'), '333344445555', 'us-west-2'), '333344445555', 'us-west-2') },
  { name: 'partner-api eu-west-2', snapshot: withScope(moved(fx('16-privatelink'), '222233334444', 'eu-west-2'), '222233334444', 'eu-west-2') },
  { name: 'sandbox us-east-1', snapshot: withScope(moved(fx('17-savings'), '555566667777', 'us-east-1'), '555566667777', 'us-east-1') },
  { name: 'prod us-east-1, a week earlier', snapshot: richProdEarlier() },
];

