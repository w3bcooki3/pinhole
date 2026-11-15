/**
 * Differential test: random networks, random questions, the engine against
 * the reference evaluator in reference.ts. Seeded, so a failure reproduces;
 * the seed and the snapshot are printed when the two disagree.
 */
import { describe, expect, it } from 'vitest';
import { analyzeCleanup, analyzeExposure, applyChanges, evaluatePath, INTERNET, normalize, RangeSet } from '../src/index.js';

/** The exact addresses of a finding (`sources` are the rules' labels; `sourceRanges` are what gets through). */
const exact = (ranges: string[]) => (ranges[0]?.startsWith('0.0.0.0/0 ') ? INTERNET : RangeSet.fromCidrs(ranges));
import { inCidr, ip, referenceReach } from './reference.js';

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const POOL = ['0.0.0.0/0', '203.0.113.0/24', '203.0.113.128/25', '198.51.100.0/24', '198.51.0.0/16', '54.0.0.0/8', '10.0.0.0/8', '203.0.113.64/26'];
const CLIENTS = ['203.0.113.5', '203.0.113.70', '203.0.113.200', '198.51.100.9', '198.51.7.7', '54.1.2.3', '8.8.8.8'];
const PORTS = [1, 22, 23, 80, 443, 1023, 1024, 3389, 5432, 8080, 65535];

function randomSnapshot(r: () => number) {
  const pick = <T>(xs: T[]) => xs[Math.floor(r() * xs.length)]!;
  const portRange = () => {
    const a = pick(PORTS);
    const b = r() < 0.5 ? a : pick(PORTS);
    return [Math.min(a, b), Math.max(a, b)] as const;
  };
  const subnets = ['subnet-a', 'subnet-b'];
  const igwAttached = r() < 0.85;
  const routes = (extra: boolean) => {
    const out: any[] = [{ DestinationCidrBlock: '10.0.0.0/16', GatewayId: 'local', State: 'active' }];
    const def = r();
    if (def < 0.6) out.push({ DestinationCidrBlock: '0.0.0.0/0', GatewayId: 'igw-1', State: 'active' });
    else if (def < 0.8) out.push({ DestinationCidrBlock: '0.0.0.0/0', NatGatewayId: 'nat-1', State: 'active' });
    if (extra) {
      const t = r();
      const dest = pick(['203.0.113.0/24', '203.0.113.128/25', '198.51.0.0/16', '54.0.0.0/8']);
      if (t < 0.4) out.push({ DestinationCidrBlock: dest, GatewayId: 'igw-1', State: 'active' });
      else if (t < 0.7) out.push({ DestinationCidrBlock: dest, NatGatewayId: 'nat-1', State: 'active' });
      else out.push({ DestinationCidrBlock: dest, GatewayId: 'igw-1', State: 'blackhole' });
    }
    return out;
  };
  const nacl = (id: string, isDefault: boolean, assoc: string[]) => {
    const entries: any[] = [];
    const used = new Set<number>();
    const n = Math.floor(r() * 5);
    for (let i = 0; i < n; i++) {
      let num = 10 * (1 + Math.floor(r() * 20));
      while (used.has(num)) num += 1;
      used.add(num);
      const proto = pick(['6', '17', '-1']);
      const [from, to] = portRange();
      entries.push({ RuleNumber: num, Protocol: proto, RuleAction: r() < 0.7 ? 'allow' : 'deny', Egress: false, CidrBlock: pick(POOL), ...(proto !== '-1' ? { PortRange: { From: from, To: to } } : {}) });
    }
    if (r() < 0.6) entries.push({ RuleNumber: 500, Protocol: '-1', RuleAction: 'allow', Egress: false, CidrBlock: '0.0.0.0/0' });
    entries.push({ RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: false, CidrBlock: '0.0.0.0/0' });
    entries.push({ RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: true, CidrBlock: '0.0.0.0/0' }, { RuleNumber: 32767, Protocol: '-1', RuleAction: 'deny', Egress: true, CidrBlock: '0.0.0.0/0' });
    return { NetworkAclId: id, VpcId: 'vpc-1', IsDefault: isDefault, Associations: assoc.map((SubnetId) => ({ SubnetId })), Entries: entries };
  };
  const ownAcl = r() < 0.5;
  const ownRtb = r() < 0.5;
  const groups = ['sg-1', 'sg-2', 'sg-3'];
  const rules: any[] = [];
  let k = 0;
  for (const g of groups) {
    const n = Math.floor(r() * 4);
    for (let i = 0; i < n; i++) {
      const proto = pick(['tcp', 'udp', '-1', 'tcp']);
      const [from, to] = portRange();
      rules.push({ SecurityGroupRuleId: `sgr-${++k}`, GroupId: g, IsEgress: false, IpProtocol: proto, ...(proto === '-1' ? { FromPort: -1, ToPort: -1 } : { FromPort: from, ToPort: to }), CidrIpv4: pick(POOL) });
    }
    rules.push({ SecurityGroupRuleId: `sgr-${++k}`, GroupId: g, IsEgress: true, IpProtocol: '-1', FromPort: -1, ToPort: -1, CidrIpv4: '0.0.0.0/0' });
  }
  const enis = subnets.map((s, i) => ({
    NetworkInterfaceId: `eni-${i}`,
    SubnetId: s,
    VpcId: 'vpc-1',
    InterfaceType: 'interface',
    PrivateIpAddresses: [{ PrivateIpAddress: `10.0.${i}.10`, Primary: true, ...(r() < 0.8 ? { Association: { PublicIp: `52.0.0.${i + 1}`, IpOwnerId: 'amazon' } } : {}) }],
    Groups: groups.filter(() => r() < 0.5).concat(i === 0 ? ['sg-1'] : ['sg-2']).filter((g, j, a) => a.indexOf(g) === j).map((GroupId) => ({ GroupId })),
    Attachment: { InstanceId: `i-${i}`, DeviceIndex: 0 },
  }));
  return {
    schemaVersion: 1,
    source: 'fuzz',
    accountId: '111122223333',
    region: 'us-east-1',
    ec2: {
      Vpcs: [{ VpcId: 'vpc-1', CidrBlock: '10.0.0.0/16' }],
      Subnets: subnets.map((s, i) => ({ SubnetId: s, VpcId: 'vpc-1', CidrBlock: `10.0.${i}.0/24`, AvailabilityZone: 'us-east-1a' })),
      InternetGateways: [{ InternetGatewayId: 'igw-1', Attachments: igwAttached ? [{ VpcId: 'vpc-1', State: 'available' }] : [] }],
      NatGateways: [{ NatGatewayId: 'nat-1', VpcId: 'vpc-1', SubnetId: 'subnet-a', State: 'available', ConnectivityType: 'public' }],
      RouteTables: [
        { RouteTableId: 'rtb-main', VpcId: 'vpc-1', Associations: [{ Main: true }], Routes: routes(r() < 0.5) },
        ...(ownRtb ? [{ RouteTableId: 'rtb-b', VpcId: 'vpc-1', Associations: [{ SubnetId: 'subnet-b' }], Routes: routes(r() < 0.7) }] : []),
      ],
      NetworkAcls: [nacl('acl-default', true, ownAcl ? ['subnet-a'] : subnets), ...(ownAcl ? [nacl('acl-b', false, ['subnet-b'])] : [])],
      SecurityGroups: groups.map((GroupId) => ({ GroupId, GroupName: GroupId, VpcId: 'vpc-1' })),
      SecurityGroupRules: rules,
      NetworkInterfaces: enis,
      Instances: enis.map((e, i) => ({ InstanceId: `i-${i}`, State: { Name: 'running' }, NetworkInterfaces: [{ NetworkInterfaceId: e.NetworkInterfaceId, Attachment: { DeviceIndex: 0 } }] })),
    },
  };
}

describe('differential: engine against a packet-at-a-time reference', () => {
  const RUNS = Number(process.env.PINHOLE_FUZZ_RUNS ?? 400);
  it(`agrees on ${RUNS} random networks`, () => {
    let questions = 0;
    let reachable = 0;
    for (let seed = 1; seed <= RUNS; seed++) {
      const r = rng(seed);
      const snap = randomSnapshot(r);
      const model = normalize(JSON.parse(JSON.stringify(snap)));
      const findings = analyzeExposure(model).findings;
      for (const eni of ['eni-0', 'eni-1']) {
        for (const client of CLIENTS) {
          for (const protocol of ['tcp', 'udp'] as const) {
            for (const port of PORTS) {
              questions += 1;
              const want = referenceReach(snap, eni, client, protocol, port);
              const path = evaluatePath(model, { from: { internet: client }, to: { eni }, protocol, port }).verdict === 'reachable';
              const listed = findings.some((f) => f.resourceId === eni && f.protocol === protocol && f.ports.from <= port && f.ports.to >= port && exact(f.sourceRanges).containsIp(ip(client)));
              if (want) reachable += 1;
              if (path !== want || listed !== want) {
                throw new Error(`seed ${seed}: ${client} -> ${eni} ${protocol}/${port}: reference ${want}, path ${path}, exposure ${listed}\n${JSON.stringify(snap)}`);
              }
            }
          }
        }
      }
    }
    // The generator has to produce both answers often enough to mean something.
    expect(reachable).toBeGreaterThan(questions * 0.03);
    expect(reachable).toBeLessThan(questions * 0.97);
  }, 10_000 + RUNS * 10);
});

describe('differential: rule compaction keeps every packet the same', () => {
  const RUNS = Number(process.env.PINHOLE_FUZZ_RUNS ?? 400);
  it(`on ${RUNS} random groups`, () => {
    let compacted = 0;
    for (let seed = 1; seed <= RUNS; seed++) {
      const r = rng(seed * 7919);
      const pick = <T>(xs: T[]) => xs[Math.floor(r() * xs.length)]!;
      const cidrs = ['10.0.0.0/25', '10.0.0.128/25', '10.0.0.0/24', '10.0.1.0/24', '203.0.113.0/24', '203.0.113.0/25', '0.0.0.0/0', '198.51.100.7/32'];
      const rules: any[] = [];
      const n = 2 + Math.floor(r() * 7);
      for (let i = 0; i < n; i++) {
        const proto = pick(['tcp', 'tcp', 'udp', '-1']);
        const a = pick([22, 80, 81, 443, 444, 1000, 1999, 2000, 8080]);
        const b = r() < 0.5 ? a : pick([22, 80, 81, 443, 444, 1000, 1999, 2000, 8080]);
        rules.push({ SecurityGroupRuleId: `sgr-${i}`, GroupId: 'sg-1', IsEgress: false, IpProtocol: proto, ...(proto === '-1' ? { FromPort: -1, ToPort: -1 } : { FromPort: Math.min(a, b), ToPort: Math.max(a, b) }), ...(r() < 0.15 ? { ReferencedGroupInfo: { GroupId: 'sg-2' } } : { CidrIpv4: pick(cidrs) }) });
      }
      const snap = { schemaVersion: 1, source: 'fuzz', ec2: { Vpcs: [{ VpcId: 'vpc-1', CidrBlock: '10.0.0.0/16' }], SecurityGroups: [{ GroupId: 'sg-1', GroupName: 'one', VpcId: 'vpc-1' }, { GroupId: 'sg-2', GroupName: 'two', VpcId: 'vpc-1' }], SecurityGroupRules: rules } };
      const model = normalize(snap);
      const c = analyzeCleanup(model).compactions.find((x) => x.groupId === 'sg-1');
      if (!c) continue;
      compacted += 1;
      const after = applyChanges(model, c.changes).securityGroups.get('sg-1')!.ingress;
      // Reference: does any rule in the list match this packet?
      const matches = (list: { protocol: string; fromPort?: number; toPort?: number; cidr?: { text: string }; referencedGroupId?: string }[], addr: number, inGroup: boolean, proto: string, port: number) =>
        list.some((x) => (x.protocol === '-1' || x.protocol === proto) && (x.protocol === '-1' || x.fromPort === undefined || (port >= x.fromPort && port <= x.toPort!)) && (x.referencedGroupId ? inGroup && x.referencedGroupId === 'sg-2' : !!x.cidr && inCidr(addr, x.cidr.text)));
      for (const host of ['10.0.0.5', '10.0.0.200', '10.0.1.9', '10.0.2.1', '203.0.113.9', '203.0.113.200', '198.51.100.7', '198.51.100.8', '8.8.8.8']) {
        for (const inGroup of [false, true]) {
          for (const proto of ['6', '17']) {
            for (const port of [21, 22, 23, 79, 80, 81, 82, 443, 444, 445, 999, 1000, 1500, 1999, 2000, 2001, 8080, 65535]) {
              const a = matches(model.securityGroups.get('sg-1')!.ingress, ip(host), inGroup, proto, port);
              const b = matches(after, ip(host), inGroup, proto, port);
              if (a !== b) throw new Error(`seed ${seed}: ${host} ${inGroup ? '(in sg-2) ' : ''}${proto}/${port}: before ${a}, after ${b}\n${JSON.stringify(rules)}\n${c.rules.join('\n')}`);
            }
          }
        }
      }
    }
    expect(compacted).toBeGreaterThan(RUNS / 10);
  }, 10_000 + RUNS * 10);
});
