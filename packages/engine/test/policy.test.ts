import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeBlastRadius, analyzeExposure, applyChanges, checkPolicy, diffPolicy, normalize, parsePolicy, PolicyError } from '../src/index.js';
import type { NetworkModel } from '../src/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');
const raw = (f: string) => JSON.parse(readFileSync(join(root, f, 'snapshot.json'), 'utf8'));
const run = (m: NetworkModel, policy: unknown) => {
  const e = analyzeExposure(m);
  return checkPolicy(m, e, analyzeBlastRadius(m, e), parsePolicy(policy));
};
const one = (m: NetworkModel, rule: unknown, groups: unknown = {}) => run(m, { groups, rules: [{ id: 'r', ...(rule as object) }] }).results[0]!;

describe('policies', () => {
  const m09 = normalize(raw('09-lateral-movement'));

  it('deny from the internet: a direct exposure fails, with the rule that lets it in', () => {
    const r = one(m09, { deny: { from: 'internet', to: { names: ['bastion'] }, ports: 'tcp/22' } });
    expect(r.status).toBe('fail');
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0]!.ruleIds).toContain('sgr-bastion-ssh-world');
    expect(r.violations[0]!.path.some((l) => l.includes('dest-sg-ingress'))).toBe(true);
    // Other ports on the bastion are not part of this rule.
    expect(one(m09, { deny: { from: 'internet', to: { names: ['bastion'] }, ports: 'tcp/3389' } }).status).toBe('pass');
  });

  it('indirect: attack chains to the target count', () => {
    const direct = one(m09, { deny: { from: 'internet', to: { names: ['orders-db'] } } });
    expect(direct.status).toBe('pass');
    const indirect = one(m09, { deny: { from: 'internet', to: { names: ['orders-db'] }, indirect: true } });
    expect(indirect.status).toBe('fail');
    expect(indirect.violations[0]!.detail).toMatch(/attack chain from the internet: .*orders-db/);
  });

  it('deny between groups lists every connection that gets through', () => {
    const r = one(m09, { deny: { from: 'web', to: 'db', ports: 'tcp/22' } }, { web: { names: ['web'] }, db: { names: ['orders-db'] } });
    expect(r.status).toBe('fail');
    expect(r.violations.map((v) => `${v.from}>${v.to} ${v.protocol}/${v.ports?.from}`)).toEqual(['eni-web>eni-db tcp/22']);
    expect(r.violations[0]!.ruleIds).toContain('sgr-db-ssh-vpc');
  });

  it('require: a pair that cannot connect fails with the hop that blocks it', () => {
    const ok = one(m09, { require: { from: { names: ['bastion'] }, to: { names: ['orders-db'] }, ports: 'tcp/22' } });
    expect(ok.status).toBe('pass');
    const bad = one(m09, { require: { from: { names: ['bastion'] }, to: { names: ['orders-db'] }, ports: 'tcp/9999' } });
    expect(bad.status).toBe('fail');
    expect(bad.violations[0]!.detail).toMatch(/blocked at/);
    expect(one(m09, { require: { from: 'internet', to: { names: ['web'] }, ports: 'tcp/443' } }).status).toBe('pass');
    expect(one(m09, { require: { from: 'internet', to: { names: ['web'] }, ports: 'tcp/8443' } }).status).toBe('fail');
  });

  it('the internet reaches what is behind a load balancer, on the target port', () => {
    const m = normalize(raw('07-alb-private-targets'));
    const r = one(m, { deny: { from: 'internet', to: { ids: ['i-app1', 'i-app2'] }, ports: 'tcp/8080' } });
    expect(r.violations.map((v) => v.to)).toEqual(['eni-app1']);
    expect(r.violations[0]!.detail).toMatch(/through ALB web \(listener tcp\/443\)/);
    // The listener port is not the target port.
    expect(one(m, { deny: { from: 'internet', to: { ids: ['i-app1'] }, ports: 'tcp/443' } }).status).toBe('pass');
  });

  it('selects by tags from the instance, subnet and VPC, and by not / any', () => {
    const s = raw('09-lateral-movement');
    s.ec2.Vpcs[0].Tags = [{ Key: 'env', Value: 'prod' }];
    for (const i of s.ec2.Instances) if (i.InstanceId === 'i-db') i.Tags = [...(i.Tags ?? []), { Key: 'role', Value: 'db' }];
    const m = normalize(s);
    const r = one(m, { deny: { from: 'internet', to: 'prod-db', indirect: true } }, { 'prod-db': { tags: { env: 'prod', role: ['db', 'cache'] } } });
    expect(r.status).toBe('fail');
    expect(new Set(r.violations.map((v) => v.to))).toEqual(new Set(['eni-db']));
    const notBastion = one(m, { deny: { from: 'internet', to: { not: { names: ['bastion'] } }, ports: 'tcp/22' } });
    expect(notBastion.status).toBe('pass');
    const any = one(m, { deny: { from: 'internet', to: { any: [{ names: ['bastion'] }, { names: ['web'] }] } } });
    expect(new Set(any.violations.map((v) => v.to))).toEqual(new Set(['eni-bastion', 'eni-web']));
  });

  it('diff shows what a change fixes and what it breaks', () => {
    const policy = { rules: [{ id: 'no-ssh', deny: { from: 'internet', to: '*', ports: 'tcp/22' } }, { id: 'bastion-to-db', require: { from: { names: ['bastion'] }, to: { names: ['orders-db'] }, ports: 'tcp/22' } }] };
    const before = run(m09, policy);
    const after = run(applyChanges(m09, [{ kind: 'revoke-sg-rule', ruleId: 'sgr-bastion-ssh-world' }, { kind: 'revoke-sg-rule', ruleId: 'sgr-db-ssh-vpc' }]), policy);
    const d = diffPolicy(before, after);
    expect(d.find((x) => x.id === 'no-ssh')!.resolved).toHaveLength(1);
    expect(d.find((x) => x.id === 'bastion-to-db')!.added).toHaveLength(1);
  });

  it('says when a rule matches nothing, apart from a pass', () => {
    const none = one(m09, { deny: { from: 'internet', to: { names: ['no-such-host'] } } });
    expect(none.matched).toBe(0);
    expect(none.status).toBe('pass');
    const unexposed = one(m09, { deny: { from: 'internet', to: { names: ['orders-db'] } } });
    expect(unexposed.matched).toBe(1);
    expect(unexposed.status).toBe('pass');
  });

  it('checks what groups can send to the internet', () => {
    const m = normalize(raw('14-outbound'));
    const deny = one(m, { deny: { from: { names: ['db'] }, to: 'internet' } });
    expect(deny.status).toBe('fail');
    expect(deny.violations[0]!.detail).toMatch(/db .* can open tcp\/0-65535 to 0\.0\.0\.0\/0 .* through nat-1/);
    expect(deny.violations[0]!.ruleIds).toEqual(['sgr-db-out']);
    expect(one(m, { deny: { from: { names: ['app'] }, to: 'internet', ports: 'tcp/22' } }).status).toBe('pass');
    expect(one(m, { require: { from: { names: ['app'] }, to: 'internet', ports: 'tcp/443' } }).status).toBe('pass');
    const req = one(m, { require: { from: { names: ['batch'] }, to: 'internet', ports: 'tcp/443' } });
    expect(req.status).toBe('fail');
    expect(req.violations[0]!.detail).toMatch(/blocked at rtb-isolated/);
    expect(() => parsePolicy({ rules: [{ id: 'x', deny: { from: 'internet', to: 'internet' } }] })).toThrow(/cannot both be "internet"/);
  });

  it('checks what on-premises networks can reach', () => {
    const m = normalize(raw('15-hybrid'));
    const ssh = one(m, { deny: { from: 'onprem', to: '*', ports: 'tcp/22' } });
    expect(ssh.status).toBe('fail');
    expect(ssh.violations).toHaveLength(1);
    expect(ssh.violations[0]!.detail).toMatch(/192\.168\.10\.0\/24 on-premises can open tcp\/22 on app .* over vgw-1/);
    expect(ssh.violations[0]!.ruleIds).toContain('sgr-app-ssh');
    expect(one(m, { deny: { from: 'onprem', to: { names: ['db'] } } }).status).toBe('pass');
    expect(one(m, { require: { from: 'onprem', to: { names: ['web'] }, ports: 'tcp/80' } }).status).toBe('pass');
    const req = one(m, { require: { from: 'onprem', to: { names: ['db'] }, ports: 'tcp/5432' } });
    expect(req.status).toBe('fail');
    expect(req.violations[0]!.detail).toMatch(/no way back on-premises/);
    expect(() => parsePolicy({ rules: [{ id: 'x', deny: { from: '*', to: 'onprem' } }] })).toThrow(/only be the "from"/);
    expect(() => parsePolicy({ groups: { onprem: {} }, rules: [{ id: 'x', deny: { from: 'onprem', to: '*' } }] })).toThrow(/reserved/);
  });

  it('rejects bad policies, naming the field', () => {
    const bad = (p: unknown, msg: RegExp) => expect(() => parsePolicy(p)).toThrow(msg);
    bad([], /JSON object/);
    bad({ rules: [] }, /non-empty/);
    bad({ rules: [{ id: 'a', deny: { from: 'nope', to: '*' } }] }, /rules\[0\]\.deny\.from: "nope"/);
    bad({ rules: [{ id: 'a', deny: { from: 'internet', to: '*', ports: 'tcp/99999' } }] }, /not a valid port range/);
    bad({ rules: [{ id: 'a', deny: { from: 'internet', to: '*' }, require: { from: 'internet', to: '*', ports: 'tcp/1' } }] }, /exactly one/);
    bad({ rules: [{ id: 'a', require: { from: 'internet', to: '*' } }] }, /ports is required/);
    bad({ rules: [{ id: 'a', deny: { from: '*', to: '*', indirect: true } }] }, /internet" only/);
    bad({ rules: [{ id: 'a', deny: { from: 'internet', to: { tagz: {} } } }] }, /unknown selector key "tagz"/);
    bad({ groups: { internet: {} }, rules: [{ id: 'a', deny: { from: 'internet', to: '*' } }] }, /reserved/);
    expect(() => parsePolicy({ rules: [{ id: 'a b', deny: { from: 'internet', to: '*' } }] })).toThrow(PolicyError);
  });
});
