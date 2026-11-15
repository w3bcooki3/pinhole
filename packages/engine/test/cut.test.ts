import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeBlastRadius, analyzeExposure, applyChanges, findCrownJewels, findMinCut, normalize } from '../src/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');
const raw = () => JSON.parse(readFileSync(join(root, '09-lateral-movement', 'snapshot.json'), 'utf8'));
const analyse = (s: unknown) => {
  const m = normalize(s);
  const e = analyzeExposure(m);
  return { m, e, b: analyzeBlastRadius(m, e) };
};

describe('crown jewels and the smallest cut', () => {
  it('without tags, jewels are the data stores and control planes chains end at', () => {
    const { m, b } = analyse(raw());
    const j = findCrownJewels(m, b);
    expect(j.map((x) => x.eniId).sort()).toEqual(['eni-cache', 'eni-db']);
    expect(j.every((x) => /end of an attack chain/.test(x.reason))).toBe(true);
  });

  it('tags decide when present, and chains to tagged jewels rank first', () => {
    const s = raw();
    for (const i of s.ec2.Instances) if (i.InstanceId === 'i-cache') i.Tags = [...(i.Tags ?? []), { Key: 'DataClassification', Value: 'Confidential' }];
    const { m, b } = analyse(s);
    expect(findCrownJewels(m, b).map((x) => [x.eniId, x.reason])).toEqual([['eni-cache', 'tagged DataClassification=Confidential']]);
    expect(b.chains[0]!.targetId).toBe('eni-cache');
    expect(b.chains[0]!.crownJewel).toBe('tagged DataClassification=Confidential');
    expect(b.chains[0]!.why.some((w) => /is a crown jewel/.test(w))).toBe(true);
  });

  it('cuts every path to the jewels with the fewest wanted rules, verified, and keeps the public website', () => {
    const { m, e, b } = analyse(raw());
    const c = findMinCut(m, e, b);
    expect(c.ruleIds.sort()).toEqual(['sgr-bastion-ssh-world', 'sgr-db-ssh-vpc']);
    expect(c.verified).toBe(true);
    expect(c.before).toBeGreaterThan(0);
    expect(c.after).toBe(0);
    expect(c.ruleIds).not.toContain('sgr-web-https');
    // The claim holds: removing the rules leaves no chain to a jewel.
    const m1 = applyChanges(m, c.changes);
    const e1 = analyzeExposure(m1);
    const jewels = new Set(c.jewels.map((x) => x.eniId));
    expect(analyzeBlastRadius(m1, e1).chains.filter((x) => jewels.has(x.targetId))).toEqual([]);
    // Each rule is needed: without it, a chain comes back.
    for (const id of c.ruleIds) {
      const m2 = applyChanges(m, c.changes.filter((x) => 'ruleId' in x && x.ruleId !== id));
      const e2 = analyzeExposure(m2);
      expect(analyzeBlastRadius(m2, e2).chains.some((x) => jewels.has(x.targetId))).toBe(true);
    }
  });

  it('nothing to cut when no chain reaches a jewel', () => {
    const { m, e, b } = analyse(JSON.parse(readFileSync(join(root, '02-sg-to-sg-reference', 'snapshot.json'), 'utf8')));
    const c = findMinCut(m, e, b, []);
    expect(c.ruleIds).toEqual([]);
    expect(c.verified).toBe(true);
  });
});
