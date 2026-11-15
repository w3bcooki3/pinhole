/**
 * Differential test: random networks, random questions, the engine against
 * the reference evaluator in reference.ts. Seeded, so a failure reproduces;
 * the seed and the snapshot are printed when the two disagree.
 */
import { describe, expect, it } from 'vitest';
import { analyzeCleanup, analyzeExposure, applyChanges, evaluatePath, INTERNET, normalize, RangeSet } from '../src/index.js';

/** The exact addresses of a finding (`sources` are the rules' labels; `sourceRanges` are what gets through). */
const exact = (ranges: string[]) => (ranges[0]?.startsWith('0.0.0.0/0 ') ? INTERNET : RangeSet.fromCidrs(ranges));
import { inCidr, ip, referenceFirewall, referenceReach } from './reference.js';
import type { RefPolicy } from './reference.js';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

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

describe('differential: Network Firewall against a reference', () => {
  const RUNS = Number(process.env.PINHOLE_FUZZ_RUNS ?? 400);
  const root = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');
  const base = JSON.parse(readFileSync(join(root, '12-network-firewall', 'snapshot.json'), 'utf8'));
  const POLICY = 'arn:aws:network-firewall:us-east-1:111122223333:firewall-policy/edge-policy';
  const SL = 'arn:aws:network-firewall:us-east-1:111122223333:stateless-rulegroup/no-telnet';
  const SF = 'arn:aws:network-firewall:us-east-1:111122223333:stateful-rulegroup/web-in';
  it(`agrees on ${RUNS} random firewall policies, per client port`, () => {
    let agreed = 0;
    let passed = 0;
    for (let seed = 1; seed <= RUNS; seed++) {
      const r = rng(seed * 104729);
      const pick = <T>(xs: T[]) => xs[Math.floor(r() * xs.length)]!;
      const PORTS = [22, 443, 8080];
      const range = (): [number, number] => {
        const a = pick([0, 22, 443, 1024, 32768, 40000, 50000, 61001]);
        const b = pick([22, 443, 8080, 40000, 49151, 61000, 65535]);
        return [Math.min(a, b), Math.max(a, b)];
      };
      const cidrs = ['203.0.113.0/24', '198.51.100.0/24', '0.0.0.0/0', '8.8.8.0/24', '10.0.0.0/16', '10.0.1.10/32'];
      const policy: RefPolicy = {
        stateless: Array.from({ length: Math.floor(r() * 4) }, (_, i) => ({
          priority: i + 1,
          action: pick(['pass', 'drop', 'forward', 'forward'] as const),
          protocols: pick([[], [6], [17], [6, 17]]),
          sources: r() < 0.3 ? [pick(cidrs)] : [],
          srcPorts: r() < 0.3 ? [range()] : [],
          dstPorts: r() < 0.5 ? [range()] : [],
        })),
        statelessDefault: pick(['forward', 'forward', 'pass', 'drop'] as const),
        stateful: Array.from({ length: Math.floor(r() * 5) }, () => ({
          action: pick(['pass', 'pass', 'drop', 'reject', 'alert'] as const),
          proto: pick(['tcp', 'udp', 'ip'] as const),
          src: pick(['any', '$EXTERNAL_NET', '$HOME_NET', ...cidrs]),
          dst: pick(['any', '$HOME_NET', '10.0.1.10/32', '198.51.100.0/24']),
          dstPort: pick(['any', '22', '443', '8080', '400:9000', '1024:65535']),
          both: r() < 0.25,
        })),
        strict: r() < 0.5,
        defaults: [],
        home: '10.0.0.0/16',
      };
      if (policy.strict) policy.defaults = pick([[], ['aws:drop_strict'], ['aws:drop_established'], ['aws:alert_strict']]);
      const s = JSON.parse(JSON.stringify(base));
      s.ec2.SecurityGroupRules = [
        ...['tcp', 'udp'].map((p, i) => ({ SecurityGroupRuleId: `sgr-all-${i}`, GroupId: 'sg-web', IsEgress: false, IpProtocol: p, FromPort: 0, ToPort: 65535, CidrIpv4: '0.0.0.0/0' })),
        { SecurityGroupRuleId: 'sgr-out', GroupId: 'sg-web', IsEgress: true, IpProtocol: '-1', FromPort: -1, ToPort: -1, CidrIpv4: '0.0.0.0/0' },
      ];
      const pol = s.networkFirewall.FirewallPolicies[POLICY].FirewallPolicy;
      pol.StatelessDefaultActions = [{ pass: 'aws:pass', drop: 'aws:drop', forward: 'aws:forward_to_sfe' }[policy.statelessDefault]];
      pol.StatefulRuleGroupReferences = policy.strict ? [{ ResourceArn: SF, Priority: 1 }] : [{ ResourceArn: SF }];
      if (policy.strict) {
        pol.StatefulEngineOptions = { RuleOrder: 'STRICT_ORDER' };
        pol.StatefulDefaultActions = policy.defaults;
      } else {
        delete pol.StatefulEngineOptions;
        delete pol.StatefulDefaultActions;
      }
      s.networkFirewall.RuleGroups[SL].RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules = policy.stateless.map((x) => ({
        Priority: x.priority,
        RuleDefinition: {
          Actions: [{ pass: 'aws:pass', drop: 'aws:drop', forward: 'aws:forward_to_sfe' }[x.action]],
          MatchAttributes: {
            ...(x.protocols.length ? { Protocols: x.protocols } : {}),
            ...(x.sources.length ? { Sources: x.sources.map((c) => ({ AddressDefinition: c })) } : {}),
            ...(x.srcPorts.length ? { SourcePorts: x.srcPorts.map(([a, b]) => ({ FromPort: a, ToPort: b })) } : {}),
            ...(x.dstPorts.length ? { DestinationPorts: x.dstPorts.map(([a, b]) => ({ FromPort: a, ToPort: b })) } : {}),
          },
        },
      }));
      const rg = s.networkFirewall.RuleGroups[SF].RuleGroup;
      delete rg.RuleVariables;
      rg.RulesSource = { RulesString: policy.stateful.map((x, i) => `${x.action} ${x.proto} ${x.src} any ${x.both ? '<>' : '->'} ${x.dst} ${x.dstPort} (sid:${i + 1};)`).join('\n') || '# none' };
      const model = normalize(s);
      for (const client of ['203.0.113.9', '8.8.8.8', '198.51.100.77']) {
        for (const protocol of ['tcp', 'udp'] as const) {
          for (const port of PORTS) {
            const got = evaluatePath(model, { from: { internet: client }, to: { eni: 'eni-web' }, protocol, port });
            const allowed = (got.returnProfiles ?? []).flatMap((x) => x.allowed);
            for (const eph of [33000, 50000, 61000, 61001, 63000]) {
              const want = referenceFirewall(policy, ip(client), ip('10.0.1.10'), protocol === 'tcp' ? 6 : 17, port, eph);
              const engine = got.verdict === 'reachable' && allowed.some((a) => eph >= a.from && eph <= a.to);
              if (want !== engine) {
                throw new Error(`seed ${seed}: ${client} -> ${protocol}/${port} from client port ${eph}: reference ${want}, engine ${engine} (${got.verdict}: ${got.summary})\n${JSON.stringify(policy)}`);
              }
              agreed += 1;
              if (want) passed += 1;
            }
          }
        }
      }
    }
    expect(passed).toBeGreaterThan(agreed * 0.1);
    expect(passed).toBeLessThan(agreed * 0.9);
  }, 10_000 + RUNS * 20);
});
