/**
 * `pinhole diff OLD NEW`: what changed between two snapshots, as text, JSON
 * or Markdown, and whether it crosses a --fail-on threshold.
 */
import { SEVERITY_ORDER } from '@pinhole/engine';
import { describeChange } from '@pinhole/engine';
import type { AttackChain, ExposureDelta, ExposureDiff, NetworkModel, PlanMapping, Severity, SnapshotDiff } from '@pinhole/engine';

export interface DiffSide {
  file: string;
  collectedAt?: string;
}

const tag = (s: Severity) => `[${s.toUpperCase()}]`;
const ports = (d: ExposureDelta) => (d.ports ? `/${d.ports.from === d.ports.to ? d.ports.from : `${d.ports.from}-${d.ports.to}`}` : '');
const what = (d: ExposureDelta) => `${d.resourceName} ${d.protocol}${ports(d)}${d.family === 'ipv6' ? ' over IPv6' : ''}${d.listenerPort !== undefined ? ` (listener ${d.listenerPort})` : ''}`;
const sources = (xs: string[]) => xs.map((x) => x.replace(/ \(every internet address\)$/, '')).join(', ') || 'nobody';
const chain = (c: AttackChain) => c.steps.map((s) => s.name.replace(/ \(.*\)$/, '')).join(' -> ');

/** Exposure that got worse: opened, or more sources than before. */
export const worse = (d: SnapshotDiff) => d.exposure.deltas.filter((x) => x.status === 'opened' || x.status === 'widened' || x.status === 'changed');

/** Number of new exposures and chains at or above `level`. */
export function newAtOrAbove(d: SnapshotDiff, level: Severity): number {
  const limit = SEVERITY_ORDER.indexOf(level);
  const at = (s: Severity) => SEVERITY_ORDER.indexOf(s) <= limit;
  return worse(d).filter((x) => at(x.severity)).length + d.exposure.chainsOpened.filter((c) => at(c.severity)).length;
}

export function diffText(d: SnapshotDiff, before: DiffSide, after: DiffSide): string {
  const out: string[] = [];
  const e = d.exposure;
  const bad = worse(d);
  const better = e.deltas.filter((x) => x.status === 'closed' || x.status === 'narrowed');
  out.push(`Pinhole diff: account ${d.accountId ?? 'unknown'}, ${d.region ?? 'unknown region'}`);
  out.push(`  before: ${before.collectedAt ?? 'time not recorded'} (${before.file})`);
  out.push(`  after:  ${after.collectedAt ?? 'time not recorded'} (${after.file})`);
  out.push('');
  if (!e.deltas.length && !e.chainsOpened.length && !e.chainsClosed.length && !d.config.length) {
    out.push('No changes.');
    return `${out.join('\n')}\n`;
  }
  out.push(`Internet exposure: ${bad.length} new or wider, ${better.length} closed or narrower.`);
  for (const x of bad) out.push(`  ${tag(x.severity)} ${x.status === 'opened' ? 'NEW' : x.status === 'widened' ? 'WIDER' : 'CHANGED'} ${what(x)} from ${sources(x.after)}${x.status !== 'opened' ? ` (was ${sources(x.before)})` : ''}`);
  for (const x of better) out.push(`  ${tag(x.severity)} ${x.status === 'closed' ? 'closed' : 'narrower'} ${what(x)}${x.status === 'narrowed' ? `: now ${sources(x.after)} (was ${sources(x.before)})` : ''}`);
  out.push('');
  out.push(`Attack chains: ${e.chainsOpened.length} new, ${e.chainsClosed.length} closed.`);
  for (const c of e.chainsOpened) out.push(`  ${tag(c.severity)} NEW ${chain(c)}`);
  for (const c of e.chainsClosed) out.push(`  ${tag(c.severity)} closed ${chain(c)}`);
  for (const c of e.chainsRevealed) out.push(`  ${tag(c.severity)} still reachable from inside ${chain(c)} (hidden before by a direct exposure that is now closed)`);
  out.push('');
  out.push(`Configuration changes: ${d.config.length}.`);
  for (const c of d.config) {
    const body = c.change === 'changed' ? `${c.before} -> ${c.after}` : c.change === 'added' ? c.after : c.before;
    out.push(`  ${c.change.padEnd(7)} ${c.kind} ${c.id}${c.where && c.where !== c.id ? ` in ${c.where}` : ''}${body ? `: ${body}` : ''}`);
  }
  return `${out.join('\n')}\n`;
}

/** Markdown for a pull request comment or a ticket. Cell text is escaped. */
export function diffMarkdown(d: SnapshotDiff, before: DiffSide, after: DiffSide): string {
  const cell = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[<>]/g, (c) => (c === '<' ? '&lt;' : '&gt;')).replace(/[\r\n]+/g, ' ');
  const e = d.exposure;
  const bad = worse(d);
  const better = e.deltas.filter((x) => x.status === 'closed' || x.status === 'narrowed');
  const out: string[] = [];
  out.push(`### Pinhole: network changes in ${cell(d.accountId ?? 'unknown account')} ${cell(d.region ?? '')}`);
  out.push('');
  out.push(`Compared ${cell(before.collectedAt ?? before.file)} with ${cell(after.collectedAt ?? after.file)}.`);
  out.push('');
  const verdict = bad.length || e.chainsOpened.length ? `**${bad.length} new or wider internet exposure${bad.length === 1 ? '' : 's'} and ${e.chainsOpened.length} new attack chain${e.chainsOpened.length === 1 ? '' : 's'}.**` : '**No new internet exposure or attack chains.**';
  out.push(verdict);
  out.push('');
  if (bad.length || better.length) {
    out.push('| Severity | Change | Resource | Service | Open to | Before |');
    out.push('|---|---|---|---|---|---|');
    for (const x of [...bad, ...better]) out.push(`| ${x.severity} | ${x.status} | ${cell(x.resourceName)} | ${cell(`${x.protocol}${ports(x)}`)} | ${cell(sources(x.after))} | ${cell(sources(x.before))} |`);
    out.push('');
  }
  if (e.chainsOpened.length || e.chainsClosed.length) {
    out.push('| Severity | Attack chain | Change |');
    out.push('|---|---|---|');
    for (const c of e.chainsOpened) out.push(`| ${c.severity} | ${cell(chain(c).replace(/ -> /g, ' → '))} | new |`);
    for (const c of e.chainsClosed) out.push(`| ${c.severity} | ${cell(chain(c).replace(/ -> /g, ' → '))} | closed |`);
    out.push('');
  }
  if (d.config.length) {
    out.push('<details><summary>' + `${d.config.length} configuration change${d.config.length === 1 ? '' : 's'}` + '</summary>');
    out.push('');
    out.push('| Change | What | ID | Where | Before | After |');
    out.push('|---|---|---|---|---|---|');
    for (const c of d.config) out.push(`| ${c.change} | ${c.kind} | ${cell(c.id)} | ${cell(c.where)} | ${cell(c.before ?? '')} | ${cell(c.after ?? '')} |`);
    out.push('');
    out.push('</details>');
  }
  return `${out.join('\n')}\n`;
}

// ------------------------------------------------------------------ pinhole plan

export interface PlanCheck {
  mapping: PlanMapping;
  exposure: ExposureDiff;
}

const exposureLines = (e: ExposureDiff, out: string[]) => {
  const bad = e.deltas.filter((x) => x.status === 'opened' || x.status === 'widened' || x.status === 'changed');
  const better = e.deltas.filter((x) => x.status === 'closed' || x.status === 'narrowed');
  out.push(`Internet exposure: ${bad.length} new or wider, ${better.length} closed or narrower.`);
  for (const x of bad) out.push(`  ${tag(x.severity)} ${x.status === 'opened' ? 'NEW' : x.status === 'widened' ? 'WIDER' : 'CHANGED'} ${what(x)} from ${sources(x.after)}${x.status !== 'opened' ? ` (was ${sources(x.before)})` : ''}`);
  for (const x of better) out.push(`  ${tag(x.severity)} ${x.status === 'closed' ? 'closed' : 'narrower'} ${what(x)}${x.status === 'narrowed' ? `: now ${sources(x.after)} (was ${sources(x.before)})` : ''}`);
  out.push(`Attack chains: ${e.chainsOpened.length} new, ${e.chainsClosed.length} closed.`);
  for (const c of e.chainsOpened) out.push(`  ${tag(c.severity)} NEW ${chain(c)}`);
  for (const c of e.chainsClosed) out.push(`  ${tag(c.severity)} closed ${chain(c)}`);
};

/** New or wider exposure and new chains at or above `level`, for --fail-on. */
export function tfPlanNewAtOrAbove(p: PlanCheck, level: Severity): number {
  return newAtOrAbove({ exposure: p.exposure, config: [] }, level);
}

export function tfPlanText(p: PlanCheck, model: NetworkModel, snapFile: string, planFile: string): string {
  const out: string[] = [];
  const m = p.mapping;
  out.push(`Pinhole plan check: ${planFile} against ${snapFile} (account ${model.accountId ?? 'unknown'}, ${model.region ?? 'unknown region'})`);
  out.push('');
  out.push(`Analysed: ${D(m.changes.length, 'change')} from ${D(m.resources.length, 'resource')}.`);
  for (const r of m.resources) {
    if (!r.changes.length) continue;
    out.push(`  ${r.address} (${r.actions.join(', ')})`);
    for (const c of r.changes) out.push(`    ${describeChange(model, c)}`);
  }
  if (m.skipped.length) {
    out.push(`Not analysed: ${m.skipped.length}. Check these yourself.`);
    for (const s of m.skipped) out.push(`  ${s.address}: ${s.reason}`);
  }
  if (m.ignored) out.push(`Ignored: ${D(m.ignored, 'resource change')} outside networking.`);
  out.push('');
  exposureLines(p.exposure, out);
  out.push('');
  const bad = worse({ exposure: p.exposure, config: [] });
  out.push(bad.length || p.exposure.chainsOpened.length ? `This plan opens ${D(bad.length, 'new or wider internet exposure')} and ${D(p.exposure.chainsOpened.length, 'new attack chain')}.` : `This plan opens no new internet exposure or attack chains${m.skipped.length ? ' among the changes analysed' : ''}.`);
  return `${out.join('\n')}\n`;
}

export function tfPlanMarkdown(p: PlanCheck, model: NetworkModel): string {
  const cell = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[<>]/g, (c) => (c === '<' ? '&lt;' : '&gt;')).replace(/[\r\n]+/g, ' ');
  const e = p.exposure;
  const bad = worse({ exposure: e, config: [] });
  const better = e.deltas.filter((x) => x.status === 'closed' || x.status === 'narrowed');
  const out: string[] = [];
  out.push(`### Pinhole: what this plan does to network exposure`);
  out.push('');
  out.push(bad.length || e.chainsOpened.length ? `**This plan opens ${D(bad.length, 'new or wider internet exposure')} and ${D(e.chainsOpened.length, 'new attack chain')}.**` : `**No new internet exposure or attack chains${p.mapping.skipped.length ? ' among the changes analysed' : ''}.**`);
  out.push('');
  if (bad.length || better.length) {
    out.push('| Severity | Change | Resource | Service | Open to | Before |');
    out.push('|---|---|---|---|---|---|');
    for (const x of [...bad, ...better]) out.push(`| ${x.severity} | ${x.status} | ${cell(x.resourceName)} | ${cell(`${x.protocol}${ports(x)}`)} | ${cell(sources(x.after))} | ${cell(sources(x.before))} |`);
    out.push('');
  }
  if (e.chainsOpened.length) {
    out.push('| Severity | New attack chain |');
    out.push('|---|---|');
    for (const c of e.chainsOpened) out.push(`| ${c.severity} | ${cell(chain(c).replace(/ -> /g, ' → '))} |`);
    out.push('');
  }
  if (p.mapping.skipped.length) {
    out.push(`<details><summary>${D(p.mapping.skipped.length, 'resource change')} not analysed: check these yourself</summary>`);
    out.push('');
    for (const s of p.mapping.skipped) out.push(`- \`${cell(s.address)}\`: ${cell(s.reason)}`);
    out.push('');
    out.push('</details>');
    out.push('');
  }
  out.push(`<sub>Checked against a snapshot of ${cell(model.accountId ?? 'unknown account')} ${cell(model.region ?? '')} by Pinhole.</sub>`);
  return `${out.join('\n')}\n`;
}

const D = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;
