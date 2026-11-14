#!/usr/bin/env node
// Synthetic scale test for the engine: node scripts/bench-engine.mjs [interfaces] [groups] [rules per group]
// Run `npm run build` first. Prints timings, finding count and heap use.
import { readFileSync } from 'node:fs';
import { normalize, analyzeExposure } from '../packages/engine/dist/index.js';
const base = JSON.parse(readFileSync(new URL('../fixtures/', import.meta.url).pathname + '06-public-ip-without-igw-route/snapshot.json', 'utf8'));
const N = Number(process.argv[2] ?? 3000), G = Number(process.argv[3] ?? 300), R = Number(process.argv[4] ?? 40);
const s = structuredClone(base);
s.ec2.SecurityGroups = []; s.ec2.SecurityGroupRules = []; s.ec2.NetworkInterfaces = []; s.ec2.Instances = [];
// NACL with many rules too
const acl = s.ec2.NetworkAcls[0];
for (let i = 0; i < 60; i++) acl.Entries.push({ RuleNumber: 10 + i, Protocol: '6', RuleAction: i % 3 ? 'allow' : 'deny', Egress: false, CidrBlock: `${20 + i}.0.0.0/8`, PortRange: { From: 1000 + i, To: 2000 + i * 7 } });
for (let g = 0; g < G; g++) {
  s.ec2.SecurityGroups.push({ GroupId: `sg-${g}`, GroupName: `g${g}`, VpcId: 'vpc-1' });
  for (let r = 0; r < R; r++) {
    const p = (g * 37 + r * 101) % 65000;
    s.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: `sgr-${g}-${r}`, GroupId: `sg-${g}`, IsEgress: false, IpProtocol: r % 5 ? 'tcp' : 'udp', FromPort: p, ToPort: p + (r % 4 ? 0 : 50), CidrIpv4: r % 7 ? `${(g + r) % 223 + 1}.${r}.0.0/16` : '0.0.0.0/0' });
  }
  s.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: `sgr-${g}-e`, GroupId: `sg-${g}`, IsEgress: true, IpProtocol: '-1', FromPort: -1, ToPort: -1, CidrIpv4: '0.0.0.0/0' });
}
for (let i = 0; i < N; i++) s.ec2.NetworkInterfaces.push({ NetworkInterfaceId: `eni-${i}`, SubnetId: 'subnet-public', VpcId: 'vpc-1', InterfaceType: 'interface', PrivateIpAddresses: [{ PrivateIpAddress: `10.0.${1 + (i >> 8) % 250}.${i % 250 + 2}`, Primary: true, Association: { PublicIp: `54.${i >> 16}.${(i >> 8) & 255}.${i & 255}`, IpOwnerId: 'amazon' } }], Groups: [{ GroupId: `sg-${i % G}` }, { GroupId: `sg-${(i * 7) % G}` }], Attachment: { InstanceId: `i-${i}`, DeviceIndex: 0 } });
const json = JSON.stringify(s);
const t0 = performance.now();
const m = normalize(JSON.parse(json));
const t1 = performance.now();
const rep = analyzeExposure(m);
const t2 = performance.now();
console.log(`size ${(json.length / 1e6).toFixed(1)} MB  enis ${N} sgs ${G}x${R}  normalize ${(t1 - t0).toFixed(0)} ms  analyse ${(t2 - t1).toFixed(0)} ms  findings ${rep.findings.length} cells ${rep.stats.cellsEvaluated}  heap ${(process.memoryUsage().heapUsed / 1e6).toFixed(0)} MB`);
