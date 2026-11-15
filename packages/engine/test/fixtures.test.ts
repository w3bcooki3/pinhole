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
import { analyzeEgress, analyzeOnPrem, analyzeOnPremBlast, analyzePrivateLink, normalize, evaluatePath, analyzeExposure, analyzeBlastRadius, analyzeHygiene, applyChanges, diffExposure, findFixes, reachServices, serviceLabel } from '../src/index.js';
import type { Change, Endpoint, ExposureFinding, PathResult } from '../src/index.js';
import { INTERNET6, RangeSet6 } from '../src/ipv6.js';

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
    exposed?: { resource: string; protocol: string; port: number; returnPath?: string; family?: string; sources?: string[]; from?: string[]; notFrom?: string[]; inspectedBy?: string[]; caveat?: boolean }[];
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
  egress?: {
    open?: { resource: string; protocol: string; port: number; via: string; severity?: string; returnPath?: string; destinations?: string[] }[];
    closed?: { resource: string; protocol: string; port: number }[];
    counts?: { interfaces: number; open: number; wide: number };
  };
  privatelink?: {
    services: { id: string; severity: string; open: boolean; external?: string[]; listeners: { port: number; filter: string; consumers: string[]; targets: string[] }[]; externalConsumers?: string[]; remoteRegions?: string[] }[];
    endpoints: { id: string; severity: string; policy: string; otherAccount: boolean }[];
  };
  onprem?: {
    links?: { id: string; kind: string; networks: string[] }[];
    reachable?: { resource: string; protocol: string; port: number; via: string; sources?: string[] }[];
    unreachable?: { resource: string; protocol: string; port: number }[];
    counts?: { interfaces: number; reachable: number };
    chains?: { steps: string[]; service: string; severity: string }[];
  };
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
            if (e.family) expect(f?.family, summary).toBe(e.family);
            if (e.sources) expect(f?.sourceRanges, summary).toEqual(e.sources);
            if (e.inspectedBy) expect(f?.inspectedBy, summary).toEqual(e.inspectedBy);
            if (e.caveat !== undefined) expect(!!f?.caveats?.length, `caveats: ${JSON.stringify(f?.caveats)}${summary}`).toBe(e.caveat);
            const set = f?.family === 'ipv6' ? (f.sourceRanges[0]?.startsWith('::/0 (') ? INTERNET6 : RangeSet6.fromCidrs(f.sourceRanges)) : undefined;
            for (const c of e.from ?? []) expect(set && RangeSet6.fromCidrs([c]).subtract(set).isEmpty(), `${c} should be a source${summary}`).toBe(true);
            for (const c of e.notFrom ?? []) expect(set && RangeSet6.fromCidrs([c]).intersect(set).isEmpty(), `${c} should not be a source${summary}`).toBe(true);
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

      const pl = expected.privatelink;
      if (pl) {
        it('PrivateLink report', () => {
          const r = analyzePrivateLink(normalize(snapshot));
          expect(r.services.map((x) => x.id).sort()).toEqual(pl.services.map((x) => x.id).sort());
          for (const e of pl.services) {
            const got = r.services.find((x) => x.id === e.id)!;
            const ctx = JSON.stringify({ severity: got.severity, reasons: got.reasons });
            expect(got.severity, ctx).toBe(e.severity);
            expect(got.open).toBe(e.open);
            if (e.external) expect(got.external).toEqual(e.external);
            if (e.remoteRegions) expect(got.remoteRegions).toEqual(e.remoteRegions);
            if (e.externalConsumers) expect([...new Set(got.consumers.filter((c) => c.external).map((c) => c.owner))]).toEqual(e.externalConsumers);
            for (const l of e.listeners) {
              const gl = got.listeners.find((x) => x.port === l.port);
              expect(gl, `listener ${l.port}`).toBeDefined();
              expect(gl?.filter).toBe(l.filter);
              expect(gl?.consumers).toEqual(l.consumers);
              expect(gl?.targets.map((t) => `${t.targetId}:${t.port}:${t.verdict}`)).toEqual(l.targets);
              for (const t of gl?.targets ?? []) expect(t.clientIpPreserved).toBe(false);
            }
          }
          expect(r.endpoints.map((x) => x.id).sort()).toEqual(pl.endpoints.map((x) => x.id).sort());
          for (const e of pl.endpoints) {
            const got = r.endpoints.find((x) => x.id === e.id)!;
            expect({ severity: got.severity, policy: got.policy, otherAccount: got.otherAccount }, got.reasons.join('; ')).toEqual({ severity: e.severity, policy: e.policy, otherAccount: e.otherAccount });
          }
        });
      }

      const op = expected.onprem;
      if (op) {
        it('on-premises report', () => {
          const report = analyzeOnPrem(normalize(snapshot));
          const summary = `\n${report.findings.map((f) => `${f.resourceId} ${f.protocol}/${f.ports.from}-${f.ports.to} from ${f.sources.join(',')} via ${f.via}`).join('\n')}`;
          for (const l of op.links ?? []) {
            const got = report.links.find((x) => x.id === l.id);
            expect(got, `link ${l.id}`).toBeDefined();
            expect(got?.kind).toBe(l.kind);
            expect(got?.networks).toEqual(l.networks);
          }
          for (const e of op.reachable ?? []) {
            const f = report.findings.find((x) => x.resourceId === e.resource && x.protocol === e.protocol && e.port >= x.ports.from && e.port <= x.ports.to);
            expect(f, `expected ${e.resource} ${e.protocol}/${e.port} reachable from on-premises${summary}`).toBeDefined();
            expect(f?.via, summary).toBe(e.via);
            if (e.sources) expect(f?.sources, summary).toEqual(e.sources);
            expect(f?.caveats?.length, 'on-premises paths carry a caveat').toBeGreaterThan(0);
          }
          for (const e of op.unreachable ?? []) {
            expect(report.findings.find((x) => x.resourceId === e.resource && x.protocol === e.protocol && e.port >= x.ports.from && e.port <= x.ports.to), `${e.resource} ${e.protocol}/${e.port}${summary}`).toBeUndefined();
          }
          if (op.counts) expect({ interfaces: report.interfaces, reachable: report.reachable }).toEqual(op.counts);
          if (op.chains) {
            const b = analyzeOnPremBlast(normalize(snapshot), report);
            expect(b.chains.map((c) => ({ steps: c.steps.map((x) => x.eniId), service: c.steps[c.steps.length - 1]!.service, severity: c.severity }))).toEqual(op.chains);
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
      if (expected.egress) {
        it('outbound report', () => {
          const r = analyzeEgress(normalize(snapshot));
          const summary = `\n${r.findings.map((f) => `${f.resourceId} ${f.protocol}/${f.ports.from}-${f.ports.to} via ${f.via.gateway} ${f.severity}`).join('\n')}`;
          const find = (e: { resource: string; protocol: string; port: number }) => r.findings.find((f) => f.resourceId === e.resource && f.protocol === e.protocol && f.ports.from <= e.port && e.port <= f.ports.to);
          for (const e of expected.egress!.open ?? []) {
            const f = find(e);
            expect(f, `expected ${e.resource} ${e.protocol}/${e.port} out${summary}`).toBeDefined();
            expect(f?.via.gateway, summary).toBe(e.via);
            if (e.severity) expect(f?.severity, summary).toBe(e.severity);
            if (e.returnPath) expect(f?.returnPath, summary).toBe(e.returnPath);
            if (e.destinations) expect(f?.destinations, summary).toEqual(e.destinations);
          }
          for (const e of expected.egress!.closed ?? []) expect(find(e), `expected ${e.resource} ${e.protocol}/${e.port} NOT out${summary}`).toBeUndefined();
          if (expected.egress!.counts) expect({ interfaces: r.interfaces, open: r.open, wide: r.wide }).toEqual(expected.egress!.counts);
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
