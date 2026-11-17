#!/usr/bin/env node
// Times every analysis the console runs when a snapshot loads: node scripts/bench-console.mjs big.json
// Run `npm run build` first. Each stage is listed with its own time; a stage over the budget is marked.
import { readFileSync } from 'node:fs';
import * as E from '../packages/engine/dist/index.js';
const text = readFileSync(process.argv[2], 'utf8');
const BUDGET = Number(process.env.BUDGET_MS ?? 2000);
const out = [];
const time = (name, fn) => {
  const t = performance.now();
  const v = fn();
  const ms = performance.now() - t;
  out.push([name, ms]);
  console.log(`${ms > BUDGET ? 'SLOW' : '    '} ${name.padEnd(22)} ${ms.toFixed(0).padStart(7)} ms`);
  return v;
};
const raw = time('parse', () => JSON.parse(text));
time('validate', () => E.assertSnapshot(raw));
const model = time('normalize', () => E.normalize(raw));
const exposure = time('exposure', () => E.analyzeExposure(model));
const blast = time('blast radius', () => E.analyzeBlastRadius(model, exposure));
time('min cut (crown jewels)', () => E.findMinCut(model, exposure, blast));
time('chokepoints', () => (blast.chains.length ? E.findChokepoints(model, exposure, blast, 12) : []));
const cleanup = time('cleanup', () => E.analyzeCleanup(model));
time('hygiene', () => [...E.analyzeHygiene(model, exposure), ...E.cleanupFindings(model, cleanup)]);
time('egress', () => E.analyzeEgress(model));
time('on-premises', () => E.analyzeOnPrem(model));
time('privatelink', () => E.analyzePrivateLink(model));
const f = exposure.findings[0];
if (f) time('fixes for one finding', () => E.findFixes(model, f));
if (!process.env.NO_PLAN) time('fix plan', () => E.planFixes(model, exposure, blast));
const total = out.reduce((s, [, ms]) => s + ms, 0);
console.log(`size ${(text.length / 1e6).toFixed(1)} MB  interfaces ${model.enis.size}  groups ${model.securityGroups?.size ?? '?'}  findings ${exposure.findings.length}  chains ${blast.chains.length}  total ${(total / 1000).toFixed(1)} s  heap ${(process.memoryUsage().heapUsed / 1e6).toFixed(0)} MB`);
