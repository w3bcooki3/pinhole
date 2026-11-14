import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeExposure, normalize } from '../src/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const fixture = (n: string) => JSON.parse(readFileSync(join(root, 'fixtures', n, 'snapshot.json'), 'utf8'));

describe('interfaces that share a subnet and security groups', () => {
  it('get the same findings, each with its own interface and public IP in the trace', () => {
    const snap = fixture('06-public-ip-without-igw-route');
    const eni = snap.ec2.NetworkInterfaces.find((e: { NetworkInterfaceId: string }) => e.NetworkInterfaceId === 'eni-public');
    const copy = structuredClone(eni);
    copy.NetworkInterfaceId = 'eni-public-2';
    copy.PrivateIpAddresses[0].PrivateIpAddress = '10.0.1.11';
    copy.PrivateIpAddresses[0].Association.PublicIp = '52.0.0.9';
    copy.Attachment.InstanceId = 'i-public-2';
    snap.ec2.NetworkInterfaces.push(copy);
    const report = analyzeExposure(normalize(snap));
    const a = report.findings.filter((f) => f.resourceId === 'eni-public');
    const b = report.findings.filter((f) => f.resourceId === 'eni-public-2');
    expect(a.length).toBeGreaterThan(0);
    expect(b.map((f) => [f.protocol, f.ports, f.sourceRanges, f.severity])).toEqual(a.map((f) => [f.protocol, f.ports, f.sourceRanges, f.severity]));
    const pub = b[0]!.trace.find((h) => h.stage === 'public-ip')!;
    expect(pub.resourceId).toBe('eni-public-2');
    expect(pub.detail).toMatch(/52\.0\.0\.9 -> 10\.0\.1\.11/);
  });

  it('in another subnet, with a narrower NACL, are analysed on their own', () => {
    const snap = fixture('06-public-ip-without-igw-route');
    const eni = snap.ec2.NetworkInterfaces.find((e: { NetworkInterfaceId: string }) => e.NetworkInterfaceId === 'eni-public');
    const copy = structuredClone(eni);
    copy.NetworkInterfaceId = 'eni-other-subnet';
    copy.SubnetId = 'subnet-public-b';
    copy.PrivateIpAddresses[0].PrivateIpAddress = '10.0.3.10';
    copy.PrivateIpAddresses[0].Association.PublicIp = '52.0.0.10';
    snap.ec2.NetworkInterfaces.push(copy);
    snap.ec2.Subnets.push({ SubnetId: 'subnet-public-b', VpcId: 'vpc-1', CidrBlock: '10.0.3.0/24', AvailabilityZone: 'us-east-1a' });
    snap.ec2.RouteTables[0].Associations.push({ SubnetId: 'subnet-public-b' });
    snap.ec2.NetworkAcls.push({ NetworkAclId: 'acl-strict', VpcId: 'vpc-1', Associations: [{ SubnetId: 'subnet-public-b' }], Entries: [
      { RuleNumber: 100, Protocol: '6', RuleAction: 'allow', Egress: false, CidrBlock: '198.51.100.0/24', PortRange: { From: 22, To: 22 } },
      { RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: true, CidrBlock: '0.0.0.0/0' },
    ] });
    snap.ec2.NetworkAcls[0].Associations = snap.ec2.NetworkAcls[0].Associations.filter((a: { SubnetId?: string }) => a.SubnetId !== 'subnet-public-b');
    const report = analyzeExposure(normalize(snap));
    const b = report.findings.filter((f) => f.resourceId === 'eni-other-subnet');
    expect(b).toHaveLength(1);
    expect(b[0]!.sourceRanges).toEqual(['198.51.100.0/24']);
  });
});

describe('Classic Load Balancers', () => {
  it('are reported as not analysed rather than ignored', () => {
    const snap = fixture('06-public-ip-without-igw-route');
    snap.ec2.NetworkInterfaces.push({
      NetworkInterfaceId: 'eni-clb',
      SubnetId: 'subnet-public',
      VpcId: 'vpc-1',
      InterfaceType: 'interface',
      Description: 'ELB legacy-web',
      RequesterId: 'amazon-elb',
      PrivateIpAddresses: [{ PrivateIpAddress: '10.0.1.50', Primary: true, Association: { PublicIp: '52.0.0.50', IpOwnerId: 'amazon-elb' } }],
      Groups: [{ GroupId: 'sg-ssh' }],
    });
    const report = analyzeExposure(normalize(snap));
    const w = report.warnings.find((x) => x.code === 'classic-load-balancer');
    expect(w?.message).toMatch(/legacy-web/);
    expect(w?.resourceIds).toEqual(['eni-clb']);
  });
});
