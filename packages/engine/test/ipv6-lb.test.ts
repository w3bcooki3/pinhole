/**
 * IPv6 clients on dual-stack load balancers. Built on fixture 10's dual-stack
 * subnet: its network ACL allows 22, 443 and 5432 in over IPv6 (5432 except
 * 2001:db8:dead::/48) and only 49152-65535 out, so responses reach Windows
 * clients but not all Linux ones.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { analyzeExposure, normalize } from '../src/index.js';

const ALB = 'arn:aws:elasticloadbalancing:us-east-1:444455556666:loadbalancer/app/web6/a1b2c3';
const NLB = 'arn:aws:elasticloadbalancing:us-east-1:444455556666:loadbalancer/net/db6/d4e5f6';

function snapshot(albType: string | null = 'dualstack-without-public-ipv4') {
  const s = JSON.parse(readFileSync(join(__dirname, '../../../fixtures/10-ipv6-exposure/snapshot.json'), 'utf8'));
  const node = (id: string, desc: string, v4: string, v6: string, groups: string[]) => ({
    NetworkInterfaceId: id, SubnetId: 'subnet-dual', VpcId: 'vpc-1', InterfaceType: 'interface', Description: desc,
    PrivateIpAddresses: [{ PrivateIpAddress: v4, Primary: true }], Ipv6Addresses: [{ Ipv6Address: v6 }], Groups: groups.map((GroupId) => ({ GroupId })),
  });
  s.ec2.NetworkInterfaces.push(node('eni-alb6', 'ELB app/web6/a1b2c3', '10.0.1.50', '2600:1f18:aaaa:ff01::50', ['sg-alb6']));
  s.ec2.NetworkInterfaces.push(node('eni-nlb6', 'ELB net/db6/d4e5f6', '10.0.1.60', '2600:1f18:aaaa:ff01::60', []));
  s.ec2.SecurityGroups.push({ GroupId: 'sg-alb6', GroupName: 'alb6', VpcId: 'vpc-1' });
  s.ec2.SecurityGroupRules.push(
    { SecurityGroupRuleId: 'sgr-alb6-https', GroupId: 'sg-alb6', IsEgress: false, IpProtocol: 'tcp', FromPort: 443, ToPort: 443, CidrIpv6: '::/0' },
    { SecurityGroupRuleId: 'sgr-alb6-http', GroupId: 'sg-alb6', IsEgress: false, IpProtocol: 'tcp', FromPort: 80, ToPort: 80, CidrIpv6: '::/0' },
    { SecurityGroupRuleId: 'sgr-alb6-out', GroupId: 'sg-alb6', IsEgress: true, IpProtocol: '-1', FromPort: -1, ToPort: -1, CidrIpv4: '0.0.0.0/0' },
  );
  const lb = (arn: string, name: string, type: string, groups: string[], ipType?: string) => ({
    LoadBalancerArn: arn, LoadBalancerName: name, Type: type, Scheme: 'internet-facing', VpcId: 'vpc-1',
    AvailabilityZones: [{ SubnetId: 'subnet-dual', ZoneName: 'us-east-1a' }], SecurityGroups: groups, ...(ipType ? { IpAddressType: ipType } : {}),
  });
  const listener = (arn: string, port: number, protocol: string) => ({ ListenerArn: `${arn}/l${port}`, LoadBalancerArn: arn, Port: port, Protocol: protocol, DefaultActions: [{ Type: 'forward', TargetGroupArn: `${arn}/tg${port}` }] });
  s.elbv2 = {
    LoadBalancers: [lb(ALB, 'web6', 'application', ['sg-alb6'], albType ?? undefined), lb(NLB, 'db6', 'network', [], 'dualstack')],
    Listeners: [listener(ALB, 443, 'HTTPS'), listener(ALB, 80, 'HTTP'), listener(NLB, 5432, 'TCP')],
    TargetGroups: [
      { TargetGroupArn: `${ALB}/tg443`, TargetGroupName: 'web', Protocol: 'HTTP', Port: 443, TargetType: 'instance', VpcId: 'vpc-1' },
      { TargetGroupArn: `${ALB}/tg80`, TargetGroupName: 'web80', Protocol: 'HTTP', Port: 80, TargetType: 'instance', VpcId: 'vpc-1' },
      { TargetGroupArn: `${NLB}/tg5432`, TargetGroupName: 'db', Protocol: 'TCP', Port: 5432, TargetType: 'instance', VpcId: 'vpc-1' },
    ],
    TargetHealth: { [`${ALB}/tg443`]: [{ Target: { Id: 'i-dual', Port: 443 } }], [`${ALB}/tg80`]: [], [`${NLB}/tg5432`]: [{ Target: { Id: 'i-dual', Port: 5432 } }] },
  };
  return s;
}
const lbFindings = (s: unknown) => analyzeExposure(normalize(s)).findings.filter((f) => f.kind === 'load-balancer');

describe('IPv6 on dual-stack load balancers', () => {
  it('reports an ALB listener reachable over IPv6, with the same exactness as an interface', () => {
    const f = lbFindings(snapshot()).find((x) => x.resourceId === ALB && x.ports.from === 443)!;
    expect(f).toMatchObject({ family: 'ipv6', protocol: 'tcp', sources: ['::/0 (every internet address)'], returnPath: 'partial', publicIps: ['2600:1f18:aaaa:ff01::50'] });
    expect(f.trace[0]!.detail).toMatch(/dual-stack application load balancer web6, listener HTTPS:443, IPv6 clients/);
    expect(f.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds).toEqual(['sgr-alb6-https']);
  });

  it('stops at the network ACL: port 80 is open in the security group but not in the ACL', () => {
    expect(lbFindings(snapshot()).some((x) => x.resourceId === ALB && x.ports.from === 80)).toBe(false);
  });

  it('evaluates the targets from the load balancer nodes, not the IPv6 client', () => {
    const f = lbFindings(snapshot()).find((x) => x.resourceId === ALB && x.ports.from === 443)!;
    // sg-dual has no IPv4 rule for 443 from the load balancer's private address.
    expect(f.targets?.map((t) => [t.targetId, t.verdict, t.clientIpPreserved])).toEqual([['i-dual', 'blocked', false]]);
  });

  it('treats an NLB without security groups as open, leaving the network ACL to decide', () => {
    const f = lbFindings(snapshot()).find((x) => x.resourceId === NLB)!;
    expect(f).toMatchObject({ family: 'ipv6', severity: 'critical', ports: { from: 5432, to: 5432 }, sources: ['::/0 (every internet address) except 2001:db8:dead::/48'] });
    expect(f.trace.find((h) => h.stage === 'dest-sg-ingress')?.detail).toMatch(/no security groups/);
  });

  it('does not report the load balancer nodes as interfaces, nor warn about missing public IPv4', () => {
    const r = analyzeExposure(normalize(snapshot()));
    expect(r.findings.some((f) => f.resourceId === 'eni-alb6' || f.resourceId === 'eni-nlb6')).toBe(false);
    expect(r.warnings.some((w) => w.code === 'lb-nodes-without-public-ip' && w.resourceIds.includes(ALB))).toBe(false);
    expect(r.warnings.some((w) => w.code === 'ipv6-load-balancer')).toBe(false);
  });

  it('says so when the snapshot does not record the IP address type', () => {
    const r = analyzeExposure(normalize(snapshot(null)));
    expect(r.findings.some((f) => f.resourceId === ALB)).toBe(false);
    expect(r.warnings.find((w) => w.code === 'ipv6-load-balancer')?.resourceIds).toEqual(['web6']);
  });

  it('leaves an IPv4-only load balancer to the IPv4 analysis', () => {
    expect(lbFindings(snapshot('ipv4')).some((x) => x.resourceId === ALB && x.family === 'ipv6')).toBe(false);
  });
});
