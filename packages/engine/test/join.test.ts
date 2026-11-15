import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { analyzeBlastRadius, analyzeExposure, applyChanges, crossChains, joinSnapshots, normalize, planFixes } from '../src/index.js';
import type { NetworkModel } from '../src/index.js';

const dir = join(__dirname, '../../../fixtures/11-cross-account-peering');
const raw = (f: string) => JSON.parse(readFileSync(join(dir, f), 'utf8'));
const A = () => raw('account-a/snapshot.json');
const B = () => raw('account-b/snapshot.json');
const both = (a = A(), b = B()) => joinSnapshots([{ key: 'A', model: normalize(a) }, { key: 'B', model: normalize(b) }]);
const chainsOf = (a = A(), b = B()) => crossChains(both(a, b).estates[0]!).chains;
const target = (c: { steps: { eniId: string }[] }) => c.steps.at(-1)!.eniId;

describe('joining snapshots', () => {
  it('finds nothing across the link when each snapshot is analysed alone', () => {
    for (const s of [A(), B()]) {
      const m = normalize(s);
      expect(analyzeBlastRadius(m, analyzeExposure(m)).chains).toEqual([]);
    }
  });

  it('joins snapshots that share a peering connection', () => {
    const r = both();
    expect(r.skipped).toEqual([]);
    expect(r.estates).toHaveLength(1);
    expect(r.estates[0]!.links).toEqual([{ kind: 'peering', id: 'pcx-0c11', keys: ['A', 'B'] }]);
    expect(r.estates[0]!.owner.get('eni-0a-bastion')).toBe('A');
    expect(r.estates[0]!.owner.get('eni-0b-db')).toBe('B');
  });

  it('follows an attacker from an internet-facing server in one account into another', () => {
    const chains = chainsOf();
    expect(chains.map(target).sort()).toEqual(['eni-0b-admin', 'eni-0b-db']);
    const db = chains.find((c) => target(c) === 'eni-0b-db')!;
    expect(db).toMatchObject({ severity: 'critical', impact: 'data', scopes: ['A', 'B'] });
    expect(db.steps.map((s) => s.service ?? null)).toEqual([null, 'tcp/5432']);
  });

  it('honours a security group reference across same-Region peering', () => {
    // sgr-0b-admin-ssh allows sg-0a-bastion by reference, not by address.
    expect(chainsOf().some((c) => target(c) === 'eni-0b-admin')).toBe(true);
  });

  it('drops the reference across Regions, where AWS does not support it', () => {
    const a = A();
    const b = B();
    for (const s of [a, b]) s.ec2.VpcPeeringConnections[0].AccepterVpcInfo.Region = 'eu-west-1';
    const targets = chainsOf(a, b).map(target);
    expect(targets).not.toContain('eni-0b-admin');
    expect(targets).toContain('eni-0b-db');
  });

  it('needs a route back: the cache subnet has none, so nothing reaches it', () => {
    expect(chainsOf().map(target)).not.toContain('eni-0b-cache');
    const b = B();
    b.ec2.RouteTables[0].Routes = b.ec2.RouteTables[0].Routes.filter((r: { VpcPeeringConnectionId?: string }) => !r.VpcPeeringConnectionId);
    expect(chainsOf(A(), b)).toEqual([]);
  });

  it('does not join snapshots that are not linked', () => {
    const other = normalize(JSON.parse(readFileSync(join(__dirname, '../../../fixtures/09-lateral-movement/snapshot.json'), 'utf8')));
    expect(joinSnapshots([{ key: 'A', model: normalize(A()) }, { key: 'X', model: other }]).estates).toEqual([]);
  });

  it('refuses to merge linked snapshots that share other resource IDs', () => {
    const r = joinSnapshots([{ key: 'A', model: normalize(A()) }, { key: 'B', model: normalize(B()) }, { key: 'A again', model: normalize(A()) }]);
    expect(r.estates).toEqual([]);
    expect(r.skipped[0]!.keys).toEqual(['A', 'B', 'A again']);
    expect(r.skipped[0]!.reason).toMatch(/share resource IDs \(vpc-0a11/);
  });

  it('plans one change at the entry point instead of one per chain', () => {
    const report = crossChains(both().estates[0]!);
    const ids = new Set(report.chains.map((c) => c.id));
    const p = planFixes(report.estate.model, report.exposure, report.blast, { goals: { chain: (c) => ids.has(c.id) } });
    expect(p.steps).toHaveLength(1);
    expect(p.steps[0]!.changes[0]).toMatchObject({ ruleId: 'sgr-0a-ssh-world' });
    expect(p.after).toEqual({ exposures: 0, chains: 0 });
  });
});

describe('fix plans', () => {
  const fixtures = ['02-sg-to-sg-reference', '06-public-ip-without-igw-route', '09-lateral-movement', '10-ipv6-exposure'];
  const goalWeight = (m: NetworkModel) => {
    const e = analyzeExposure(m);
    const b = analyzeBlastRadius(m, e);
    return e.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length + b.chains.filter((c) => c.severity === 'critical' || c.severity === 'high').length;
  };

  for (const name of fixtures) {
    it(`has no redundant step: ${name}`, () => {
      const m = normalize(JSON.parse(readFileSync(join(__dirname, `../../../fixtures/${name}/snapshot.json`), 'utf8')));
      const e = analyzeExposure(m);
      const p = planFixes(m, e, analyzeBlastRadius(m, e));
      expect(p.steps.length).toBeGreaterThan(0);
      const done = goalWeight(p.steps.reduce((mm, s) => applyChanges(mm, s.changes), m));
      // Leaving out any one step must leave something open that the full plan closes.
      p.steps.forEach((_, i) => {
        const rest = p.steps.filter((__, j) => j !== i).reduce((mm, s) => applyChanges(mm, s.changes), m);
        expect(goalWeight(rest)).toBeGreaterThan(done);
      });
      expect(p.stats.evaluations).toBeGreaterThan(0);
    });
  }
});
