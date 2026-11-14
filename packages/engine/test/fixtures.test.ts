/**
 * Runs every hand-written fixture in /fixtures against the engine.
 *
 * Each fixture directory holds:
 *   snapshot.json  a snapshot in the collector's format
 *   expected.json  the answers, with AWS documentation links
 *   README.md      the scenario and the reasoning, for humans
 *
 * The README's pass count is produced by `npm run test:fixtures`.
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { normalize, evaluatePath, analyzeExposure, analyzeBlastRadius, analyzeHygiene, applyChanges, diffExposure, findFixes, reachServices, serviceLabel } from '../src/index.js';
import type { Change, Endpoint, ExposureFinding, PathResult } from '../src/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');

interface PathCase {
  name: string;
  from: Endpoint;
  to: Endpoint;
  protocol: string;
  port?: number;
  expect: { verdict: PathResult['verdict']; returnPath?: string; blockedAt?: string; via?: string[]; sgRules?: string[] };
}

interface Expected {
  description: string;
  docs: string[];
  paths?: PathCase[];
  exposure?: {
    exposed?: { resource: string; protocol: string; port: number; returnPath?: string }[];
    notExposed?: { resource: string; protocol: string; port: number }[];
    exactResources?: string[];
    lbTargets?: { lb: string; listenerPort: number; target: string; port: number; verdict: string }[];
  };
  lateral?: {
    reach?: { from: string; to: string; services: string[] }[];
    chains?: { steps: string[]; service: string; severity: string; entries?: string[] }[];
    chainCount?: number;
    noChains?: { steps: string[]; why: string }[];
    topChain?: { steps: string[]; endsWith: string };
  };
  hygiene?: { exact: string[] };
  fixes?: { resource: string; protocol: string; port: number; best: string; allVerified?: boolean }[];
  whatIf?: {
    name: string;
    changes: Change[];
    exposureUnchanged?: boolean;
    chainsClosed?: string[][];
    chainsStillOpen?: string[][];
    deltas?: { resource: string; protocol: string; port: number; status: string }[];
  }[];
}

const covers = (f: ExposureFinding, resource: string, protocol: string, port: number) =>
  f.resourceId === resource && f.protocol === protocol && port >= f.ports.from && port <= f.ports.to;

const dirs = readdirSync(root, { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(join(root, d.name, 'expected.json')))
  .map((d) => d.name)
  .sort();

describe('fixtures', () => {
  it('exist', () => {
    expect(dirs.length).toBeGreaterThan(0);
  });

  for (const dir of dirs) {
    const snapshot = JSON.parse(readFileSync(join(root, dir, 'snapshot.json'), 'utf8')) as unknown;
    const expected = JSON.parse(readFileSync(join(root, dir, 'expected.json'), 'utf8')) as Expected;

    describe(dir, () => {
      it('cites AWS documentation', () => {
        expect(expected.docs.length).toBeGreaterThan(0);
        for (const url of expected.docs) expect(url).toMatch(/^https:\/\/docs\.aws\.amazon\.com\//);
      });

      for (const c of expected.paths ?? []) {
        it(`path: ${c.name}`, () => {
          const model = normalize(snapshot);
          const r = evaluatePath(model, { from: c.from, to: c.to, protocol: c.protocol, ...(c.port !== undefined ? { port: c.port } : {}) });
          const context = `\n${JSON.stringify({ verdict: r.verdict, blockedAt: r.blockedAt, returnPath: r.returnPath, hops: r.hops.map((h) => `${h.stage}:${h.decision}:${h.resourceId}`) }, null, 1)}`;
          expect(r.verdict, context).toBe(c.expect.verdict);
          if (c.expect.blockedAt) expect(r.blockedAt?.stage, context).toBe(c.expect.blockedAt);
          if (c.expect.returnPath) expect(r.returnPath, context).toBe(c.expect.returnPath);
          for (const id of c.expect.via ?? []) {
            expect(r.hops.some((h) => h.resourceId === id || h.relatedIds?.includes(id)), `${id} not on path${context}`).toBe(true);
          }
          for (const id of c.expect.sgRules ?? []) {
            expect(r.hops.some((h) => h.ruleIds?.includes(id)), `${id} not cited${context}`).toBe(true);
          }
        });
      }

      const exp = expected.exposure;
      if (exp) {
        it('exposure report', () => {
          const report = analyzeExposure(normalize(snapshot));
          const summary = `\n${report.findings.map((f) => `${f.resourceId} ${f.protocol}/${f.ports.from}-${f.ports.to} ${f.returnPath}`).join('\n')}`;
          for (const e of exp.exposed ?? []) {
            const f = report.findings.find((x) => covers(x, e.resource, e.protocol, e.port));
            expect(f, `expected ${e.resource} ${e.protocol}/${e.port} exposed${summary}`).toBeDefined();
            if (e.returnPath) expect(f?.returnPath, summary).toBe(e.returnPath);
          }
          for (const e of exp.notExposed ?? []) {
            const f = report.findings.find((x) => covers(x, e.resource, e.protocol, e.port));
            expect(f, `expected ${e.resource} ${e.protocol}/${e.port} NOT exposed${summary}`).toBeUndefined();
          }
          if (exp.exactResources) {
            expect([...new Set(report.findings.map((f) => f.resourceId))].sort(), summary).toEqual([...exp.exactResources].sort());
          }
          for (const t of exp.lbTargets ?? []) {
            const f = report.findings.find((x) => x.resourceId === t.lb && x.ports.from <= t.listenerPort && t.listenerPort <= x.ports.to);
            expect(f, summary).toBeDefined();
            const target = f?.targets?.find((x) => x.targetId === t.target && x.port === t.port);
            expect(target, `target ${t.target}:${t.port} missing`).toBeDefined();
            expect(target?.verdict).toBe(t.verdict);
          }
        });
      }

      const lat = expected.lateral;
      for (const r of lat?.reach ?? []) {
        it(`reach: ${r.from} -> ${r.to}`, () => {
          const got = reachServices(normalize(snapshot), r.from, r.to).services.filter((x) => x.verdict === 'reachable').map(serviceLabel);
          expect(got.sort()).toEqual([...r.services].sort());
        });
      }
      if (lat?.chains || lat?.noChains || lat?.topChain) {
        it('blast radius chains', () => {
          const model = normalize(snapshot);
          const blast = analyzeBlastRadius(model, analyzeExposure(model));
          const shape = (steps: string[]) => steps.join(' > ');
          const all = blast.chains.map((c) => ({ path: shape(c.steps.map((s) => s.eniId)), service: c.steps.at(-1)!.service, severity: c.severity, impact: c.impact, entries: c.entries.map((e) => e.eniId) }));
          const summary = `\n${all.map((c) => `${c.severity} ${c.path} ${c.service}`).join('\n')}`;
          for (const c of lat.chains ?? []) {
            const hit = all.find((x) => x.path === shape(c.steps) && x.service === c.service);
            expect(hit, `missing chain ${shape(c.steps)} ${c.service}${summary}`).toBeDefined();
            expect(hit?.severity, summary).toBe(c.severity);
            if (c.entries) expect(hit?.entries.sort(), summary).toEqual([...c.entries].sort());
          }
          if (lat.chainCount !== undefined) expect(all.length, summary).toBe(lat.chainCount);
          for (const c of lat.noChains ?? []) expect(all.some((x) => x.path === shape(c.steps)), `unexpected chain ${shape(c.steps)} (${c.why})${summary}`).toBe(false);
          if (lat.topChain) {
            expect(all[0]!.path.startsWith(shape(lat.topChain.steps)), summary).toBe(true);
            expect(all[0]!.impact, summary).toBe(lat.topChain.endsWith);
          }
        });
      }
      if (expected.hygiene) {
        it('rule hygiene', () => {
          const got = analyzeHygiene(normalize(snapshot)).map((h) => `${h.code} ${h.ruleId ?? h.resourceId}`);
          expect(got.sort()).toEqual([...expected.hygiene!.exact].sort());
        });
      }
      for (const fx of expected.fixes ?? []) {
        it(`fixes: ${fx.resource} ${fx.protocol}/${fx.port}`, () => {
          const model = normalize(snapshot);
          const f = analyzeExposure(model).findings.find((x) => covers(x, fx.resource, fx.protocol, fx.port))!;
          const fixes = findFixes(model, f);
          const best = fixes[0]!;
          expect(best.changes.map((c) => `${c.kind} ${'ruleId' in c ? c.ruleId : ''}`.trim()).join(', ')).toBe(fx.best);
          if (fx.allVerified) expect(fixes.every((x) => x.verified)).toBe(true);
        });
      }
      for (const w of expected.whatIf ?? []) {
        it(`what-if: ${w.name}`, () => {
          const model = normalize(snapshot);
          const after = applyChanges(model, w.changes);
          const e0 = analyzeExposure(model);
          const e1 = analyzeExposure(after);
          const diff = diffExposure(e0, e1, { before: analyzeBlastRadius(model, e0), after: analyzeBlastRadius(after, e1) });
          if (w.exposureUnchanged) expect(diff.deltas).toEqual([]);
          for (const steps of w.chainsStillOpen ?? []) {
            expect(diff.chainsClosed.some((c) => c.steps.map((s) => s.eniId).join('>') === steps.join('>')), `chain ${steps.join('>')} should stay open`).toBe(false);
          }
          for (const steps of w.chainsClosed ?? []) {
            expect(diff.chainsClosed.some((c) => c.steps.map((s) => s.eniId).join('>') === steps.join('>')), `chain ${steps.join('>')} not closed`).toBe(true);
          }
          for (const d of w.deltas ?? []) {
            const hit = diff.deltas.find((x) => x.resourceId === d.resource && x.protocol === d.protocol && x.ports && x.ports.from <= d.port && d.port <= x.ports.to);
            expect(hit?.status, JSON.stringify(diff.deltas)).toBe(d.status);
          }
        });
      }
    });
  }
});
