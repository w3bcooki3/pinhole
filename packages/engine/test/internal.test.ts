import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeBlastRadius, analyzeExposure, applyChanges, findFixes, normalize, planFixes } from '../src/index.js';
import { internalBreaks, internalFlows, isWanted, touchedInterfaces } from '../src/internal.js';
import type { Change } from '../src/whatif.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');
const load = (f: string) => normalize(JSON.parse(readFileSync(join(root, f, 'snapshot.json'), 'utf8')));
const breaks = (fixture: string, changes: Change[]) => {
  const m = load(fixture);
  return internalBreaks(m, applyChanges(m, changes), changes);
};

describe('internal traffic a change cuts', () => {
  it('a load balancer losing its target is a break, from every node', () => {
    const b = breaks('07-alb-private-targets', [{ kind: 'revoke-sg-rule', ruleId: 'sgr-app-from-alb' }]);
    const lb = b.filter((x) => x.flow.evidence === 'load-balancer');
    expect(lb.map((x) => `${x.flow.from}>${x.flow.to} ${x.flow.protocol}/${x.flow.ports?.from}`).sort()).toEqual(['eni-alb-a>eni-app1 tcp/8080', 'eni-alb-b>eni-app1 tcp/8080']);
    expect(lb.every((x) => x.closed && isWanted(x))).toBe(true);
    expect(lb[0]!.flow.note).toMatch(/web sends traffic to this target on 8080/);
  });

  it('a separate health check port is a flow of its own', () => {
    const m0 = load('07-alb-private-targets');
    const setup: Change[] = [
      { kind: 'add-sg-rule', groupId: 'sg-app', egress: false, protocol: 'tcp', fromPort: 9000, toPort: 9000, referencedGroupId: 'sg-alb' },
      { kind: 'add-sg-rule', groupId: 'sg-alb', egress: true, protocol: 'tcp', fromPort: 9000, toPort: 9000, cidr: '10.0.10.0/24' },
      // acl-app allows only 8080 in.
      { kind: 'add-nacl-entry', naclId: 'acl-app', egress: false, ruleNumber: 150, action: 'allow', protocol: 'tcp', cidr: '10.0.0.0/16', fromPort: 9000, toPort: 9000 },
    ];
    const m = applyChanges(m0, setup);
    for (const tg of m.targetGroups.values()) tg.healthCheckPort = '9000';
    const ruleId = [...m.securityGroups.get('sg-app')!.ingress].find((r) => r.fromPort === 9000)!.id;
    const change: Change[] = [{ kind: 'revoke-sg-rule', ruleId }];
    const b = internalBreaks(m, applyChanges(m, change), change);
    expect(b.filter((x) => x.flow.evidence === 'health-check').map((x) => x.flow.ports?.from)).toEqual([9000, 9000]);
    expect(b.some((x) => x.flow.evidence === 'load-balancer')).toBe(false);
  });

  it('a rule that names the source group is a break; an address range alone is a cut', () => {
    const b = breaks('02-sg-to-sg-reference', [{ kind: 'revoke-sg-rule', ruleId: 'sgr-db-from-web' }]);
    expect(b.map((x) => [x.flow.from, x.flow.to, x.flow.evidence])).toEqual([['eni-web', 'eni-db', 'group-reference']]);
    const c = breaks('02-sg-to-sg-reference', [{ kind: 'revoke-sg-rule', ruleId: 'sgr-web-https' }]);
    expect(c.length).toBeGreaterThan(0);
    expect(c.every((x) => x.flow.evidence === 'network')).toBe(true);
  });

  it('narrowing a range keeps what is left and reports only what is lost', () => {
    const b = breaks('09-lateral-movement', [{ kind: 'edit-sg-rule', ruleId: 'sgr-db-ssh-vpc', cidr: '10.0.1.0/24' }]);
    for (const x of b) expect(x.flow.to).toBe('eni-db');
    const m = load('09-lateral-movement');
    const after = applyChanges(m, [{ kind: 'edit-sg-rule', ruleId: 'sgr-db-ssh-vpc', cidr: '10.0.1.0/24' }]);
    const kept = internalFlows(after, new Set(['eni-db'])).filter((f) => f.protocol === 'tcp' && f.ports?.from === 22).map((f) => f.from);
    expect(b.map((x) => x.flow.from).some((id) => kept.includes(id))).toBe(false);
  });

  it('a route table change touches every interface in the subnets that use it', () => {
    const m = load('06-public-ip-without-igw-route');
    const t = touchedInterfaces(m, [{ kind: 'remove-route', routeTableId: 'rtb-public', destination: '0.0.0.0/0' }]);
    expect(t.has('eni-public')).toBe(true);
    expect(t.has('eni-private-eip')).toBe(false);
    expect(touchedInterfaces(m, [{ kind: 'remove-public-ip', eniId: 'eni-public', publicIp: '1.1.1.1' }]).size).toBe(0);
  });
});

describe('fixes that keep what uses the rule', () => {
  it('offers the narrowest replacement and proves it breaks nothing', () => {
    const m = load('09-lateral-movement');
    const f = analyzeExposure(m).findings.find((x) => x.resourceId === 'eni-bastion')!;
    const fixes = findFixes(m, f);
    const narrow = fixes.find((x) => x.title === 'Allow sgr-bastion-ssh-world only from what uses it')!;
    expect(narrow.verified).toBe(true);
    expect(narrow.safe).toBe(true);
    expect(narrow.breaks).toEqual([]);
    expect(narrow.changes[0]).toEqual({ kind: 'revoke-sg-rule', ruleId: 'sgr-bastion-ssh-world' });
    expect(narrow.changes.slice(1).every((c) => c.kind === 'add-sg-rule' && (c.referencedGroupId || c.cidr?.endsWith('/32')))).toBe(true);
    // Removing the rule outright is still verified, and lists what it cuts.
    const revoke = fixes.find((x) => x.title === 'Remove sgr-bastion-ssh-world')!;
    expect(revoke.breaks.length).toBeGreaterThan(0);
    expect(revoke.breaks.every((b) => !isWanted(b))).toBe(true);
    expect(revoke.safe).toBe(true);
  });

  it('every plan step says what internal traffic it cuts', () => {
    const m = load('09-lateral-movement');
    const e = analyzeExposure(m);
    const p = planFixes(m, e, analyzeBlastRadius(m, e));
    expect(p.steps.length).toBeGreaterThan(0);
    for (const s of p.steps) expect(Array.isArray(s.breaks)).toBe(true);
  });
});

describe('plan size proof', () => {
  const plan = (fx: string, budget?: number) => {
    const m = load(fx);
    const e = analyzeExposure(m);
    return planFixes(m, e, analyzeBlastRadius(m, e), budget === undefined ? {} : { proofBudget: budget });
  };
  it('proves a small plan is the fewest steps', () => {
    const p = plan('09-lateral-movement');
    expect(p.optimality.status).toBe('optimal');
    expect(p.optimality.lowerBound).toBeLessThanOrEqual(p.steps.length);
  });
  it('the lower bound never exceeds the plan, and no budget means no search', () => {
    for (const fx of ['02-sg-to-sg-reference', '06-public-ip-without-igw-route', '10-ipv6-exposure', '09-lateral-movement']) {
      const p = plan(fx, 0);
      expect(p.optimality.searched).toBe(0);
      const q = plan(fx);
      expect(q.optimality.lowerBound).toBeLessThanOrEqual(q.steps.length);
    }
  });
});

describe('protected traffic', () => {
  it('a plan never takes a step that breaks a protected connection, and cuts the foothold instead', () => {
    const m = load('09-lateral-movement');
    const e = analyzeExposure(m);
    const b = analyzeBlastRadius(m, e);
    const bastionToDb = (mm: typeof m) => (internalFlows(mm, new Set(['eni-db'])).some((f) => f.from === 'eni-bastion' && f.protocol === 'tcp' && f.ports && f.ports.from <= 22 && f.ports.to >= 22) ? 0 : 1);
    const p = planFixes(m, e, b, { protect: bastionToDb });
    const after = p.steps.reduce((mm, s) => applyChanges(mm, s.changes), m);
    expect(bastionToDb(after)).toBe(0);
    expect(p.after.chains).toBe(0);
    expect(p.steps.some((s) => s.title.startsWith('Allow sgr-db-ssh-vpc only from what uses it, not'))).toBe(true);
  });
});
