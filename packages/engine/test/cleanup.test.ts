import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeCleanup, analyzeExposure, applyChanges, normalize, sameRules } from '../src/index.js';
import type { Change } from '../src/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');
const load = (f: string) => normalize(JSON.parse(readFileSync(join(root, f, 'snapshot.json'), 'utf8')));
const rule = (groupId: string, fromPort: number, toPort: number, cidr: string, protocol = 'tcp'): Change => ({ kind: 'add-sg-rule', groupId, egress: false, protocol, fromPort, toPort, cidr });
const idOf = (m: ReturnType<typeof load>, g: string, from: number, cidr: string) => m.securityGroups.get(g)!.ingress.find((r) => r.fromPort === from && r.cidr?.text === cidr)!.id;

describe('rule cleanup', () => {
  it('finds a rule that several others cover together, and compacts the group exactly', () => {
    const m = applyChanges(load('02-sg-to-sg-reference'), [rule('sg-web', 1000, 1999, '10.0.0.0/8'), rule('sg-web', 2000, 2999, '10.0.0.0/8'), rule('sg-web', 1500, 2500, '10.1.0.0/16'), rule('sg-web', 8080, 8080, '10.2.0.0/25'), rule('sg-web', 8080, 8080, '10.2.0.128/25')]);
    const c = analyzeCleanup(m);
    const red = c.redundant.find((r) => r.ruleId === idOf(m, 'sg-web', 1500, '10.1.0.0/16'))!;
    expect(red.scope).toBe('group');
    expect(red.coveredBy).toEqual(expect.arrayContaining([idOf(m, 'sg-web', 1000, '10.0.0.0/8'), idOf(m, 'sg-web', 2000, '10.0.0.0/8')]));
    const comp = c.compactions.find((x) => x.groupId === 'sg-web' && !x.egress)!;
    expect(comp.equivalent).toBe(true);
    expect(comp.rules).toEqual(expect.arrayContaining(['tcp/1000-2999 from 10.0.0.0/8', 'tcp/8080 from 10.2.0.0/24']));
    expect(comp.after).toBeLessThan(comp.before);
    // Applying the compaction changes nothing the internet or anyone else can reach.
    const after = applyChanges(m, comp.changes);
    expect(sameRules(m.securityGroups.get('sg-web')!.ingress, after.securityGroups.get('sg-web')!.ingress, m.prefixLists)).toBe(true);
    expect(JSON.stringify(analyzeExposure(after).findings.map((f) => [f.resourceId, f.ports, f.sources]))).toBe(JSON.stringify(analyzeExposure(m).findings.map((f) => [f.resourceId, f.ports, f.sources])));
  });

  it('the equivalence check catches a difference of one port or one address', () => {
    const m = applyChanges(load('02-sg-to-sg-reference'), [rule('sg-web', 1000, 1999, '10.0.0.0/8')]);
    const a = m.securityGroups.get('sg-web')!.ingress;
    const narrowerPort = a.map((r) => (r.fromPort === 1000 ? { ...r, toPort: 1998 } : r));
    const narrowerAddr = a.map((r) => (r.fromPort === 1000 ? { ...r, cidr: { ...r.cidr!, end: r.cidr!.end - 1 } } : r));
    expect(sameRules(a, a, m.prefixLists)).toBe(true);
    expect(sameRules(a, narrowerPort, m.prefixLists)).toBe(false);
    expect(sameRules(a, narrowerAddr, m.prefixLists)).toBe(false);
  });

  it('finds a rule that another attached group covers everywhere it is used', () => {
    const m = applyChanges(load('02-sg-to-sg-reference'), [{ kind: 'attach-sg', eniId: 'eni-web', groupId: 'sg-other' }, rule('sg-other', 9000, 9000, '0.0.0.0/0'), rule('sg-web', 9000, 9000, '203.0.113.0/24')]);
    const red = analyzeCleanup(m).redundant.find((r) => r.ruleId === idOf(m, 'sg-web', 9000, '203.0.113.0/24'))!;
    expect(red.scope).toBe('attached');
    // eni-other also uses sg-other, so sg-other's own rule is not redundant.
    expect(analyzeCleanup(m).redundant.some((r) => r.groupId === 'sg-other')).toBe(false);
  });

  it('finds a network ACL entry that earlier entries cover together', () => {
    const add = (ruleNumber: number, action: 'allow' | 'deny', fromPort: number, toPort: number, cidr: string): Change => ({ kind: 'add-nacl-entry', naclId: 'acl-app', egress: false, ruleNumber, action, protocol: 'tcp', cidr, fromPort, toPort });
    const m = applyChanges(load('07-alb-private-targets'), [add(50, 'deny', 1000, 1999, '10.0.0.0/8'), add(60, 'deny', 2000, 2999, '10.0.0.0/8'), add(70, 'allow', 1500, 2500, '10.5.0.0/16')]);
    const s = analyzeCleanup(m).shadowed.find((x) => x.naclId === 'acl-app' && x.ruleNumber === 70)!;
    expect(s.by).toEqual([50, 60]);
    expect(s.harmless).toBe(false);
  });

  it('warns near the rule quotas', () => {
    const m = applyChanges(load('02-sg-to-sg-reference'), Array.from({ length: 50 }, (_, i) => rule('sg-db', 10000 + i, 10000 + i, `10.9.${i}.0/24`)));
    const q = analyzeCleanup(m).quotas.find((x) => x.resourceId === 'sg-db')!;
    expect(q.used).toBe(51);
    expect(q.limit).toBe(60);
  });
});
