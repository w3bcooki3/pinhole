import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeBlastRadius, analyzeExposure, applyChanges, normalize, reachBetween, reachServices, serviceLabel } from '../src/index.js';
import type { NetworkModel, PairReach } from '../src/index.js';

// Servers that no rule, route or address range tells apart share one
// reachability result. These tests hold that sharing to the direct answer,
// on a synthetic account with three tiers, transit gateway routing and
// security groups that reference each other.
const here = dirname(fileURLToPath(import.meta.url));
const synth = (servers: number, vpcs: number) => normalize(JSON.parse(execFileSync(process.execPath, [join(here, '../../../scripts/synth-account.mjs'), String(servers), String(vpcs)], { encoding: 'utf8', maxBuffer: 64 << 20 })));
const shape = (r: PairReach) => r.services.map((s) => `${serviceLabel(s)} ${s.verdict} ${s.returnPath ?? ''} ${s.category}`).sort();
const sgRules = (r: PairReach) => r.services.map((s) => (s.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds ?? []).join('+')).sort();

function samplePairs(m: NetworkModel, n: number): [string, string][] {
  const ids = [...m.enis.keys()];
  let seed = 11;
  const rnd = () => (seed = (seed * 48271) % 2147483647) / 2147483647;
  const out: [string, string][] = [];
  while (out.length < n) {
    const a = ids[Math.floor(rnd() * ids.length)]!;
    const b = ids[Math.floor(rnd() * ids.length)]!;
    if (a !== b) out.push([a, b]);
  }
  return out;
}

describe('grouped reachability on a large synthetic account', () => {
  const m = synth(90, 3);

  it('gives every pair the same services and deciding rules as evaluating it directly', () => {
    for (const [a, b] of samplePairs(m, 300)) {
      const direct = reachServices(m, a, b);
      const shared = reachBetween(m, a, b);
      expect(shape(shared), `${a} -> ${b}`).toEqual(shape(direct));
      expect(sgRules(shared), `${a} -> ${b}`).toEqual(sgRules(direct));
    }
  });

  it('stays exact on a changed copy, where unchanged results are reused', () => {
    // Remove the rules that admit SSH from inside the network: every server in those groups changes.
    const ids = [...m.securityGroups.values()].flatMap((g) => g.ingress.filter((r) => r.fromPort === 22).map((r) => r.id));
    expect(ids.length).toBeGreaterThan(0);
    for (const [a, b] of samplePairs(m, 200)) reachBetween(m, a, b); // fill the original's results first
    const m1 = applyChanges(m, ids.map((ruleId) => ({ kind: 'revoke-sg-rule' as const, ruleId })));
    for (const [a, b] of samplePairs(m1, 300)) expect(shape(reachBetween(m1, a, b)), `${a} -> ${b}`).toEqual(shape(reachServices(m1, a, b)));
  });

  it('gives each attack chain step a trace for its own two servers', () => {
    const x = analyzeExposure(m);
    const blast = analyzeBlastRadius(m, x);
    expect(blast.chains.length).toBeGreaterThan(5);
    const ip = (id: string) => m.enis.get(id)!.privateIps[0]!;
    for (const c of blast.chains) {
      for (const route of [c.steps, ...c.altRoutes]) {
        for (let i = 1; i < route.length; i++) {
          const e = blast.edges.find((y) => y.from === route[i - 1]!.eniId && y.to === route[i]!.eniId)!;
          expect(e).toBeDefined();
          const t = e.services[0]!.trace;
          expect(t.find((h) => h.stage === 'dest-sg-ingress')!.detail).toContain(`from ${ip(route[i - 1]!.eniId)}`);
        }
      }
    }
  });
});
