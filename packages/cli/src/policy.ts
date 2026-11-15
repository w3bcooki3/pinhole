/** `pinhole policy`: check a snapshot against network policies. */
import { readFileSync } from 'node:fs';
import { analyzeBlastRadius, analyzeExposure, checkPolicy, parsePolicy, PolicyError, SEVERITY_ORDER } from '@pinhole/engine';
import type { NetworkModel, PolicyFile, PolicyReport, Severity } from '@pinhole/engine';

export function readPolicy(file: string): PolicyFile {
  let raw: unknown;
  try {
    const text = readFileSync(file, 'utf8');
    if (text.length > 5_000_000) throw new Error('the file is larger than 5 MB');
    raw = JSON.parse(text);
  } catch (e) {
    throw new PolicyError(`Cannot read ${file}: ${(e as Error).message}`);
  }
  try {
    return parsePolicy(raw);
  } catch (e) {
    throw new PolicyError(`${file}: ${(e as Error).message}`);
  }
}

export function policyCheck(model: NetworkModel, policy: PolicyFile): PolicyReport {
  const e = analyzeExposure(model);
  return checkPolicy(model, e, analyzeBlastRadius(model, e), policy);
}

const tag = (s: Severity) => `[${s.toUpperCase()}]`.padEnd(10);

export function policyText(r: PolicyReport, verbose: boolean): string {
  const lines = [`Policy: ${r.failed} of ${r.results.length} rule(s) fail.`, ''];
  for (const x of r.results) {
    lines.push(`${x.status === 'pass' ? (x.matched ? 'PASS      ' : 'NO MATCH  ') : tag(x.severity)} ${x.id}${x.description ? `: ${x.description}` : ''}  (${x.matched} resource(s), ${x.checked} checked)`);
    const shown = verbose ? x.violations : x.violations.slice(0, 5);
    for (const v of shown) {
      lines.push(`    ${v.detail}`);
      if (v.ruleIds.length) lines.push(`      let through by: ${v.ruleIds.join(', ')}`);
      if (verbose) for (const h of v.path) lines.push(`      ${h}`);
    }
    if (shown.length < x.violations.length) lines.push(`    ... and ${x.violations.length - shown.length} more (--verbose shows all, with paths)`);
  }
  return `${lines.join('\n')}\n`;
}

export function policyMarkdown(r: PolicyReport): string {
  const esc = (t: string) => t.replace(/[|\\`*_<>[\]]/g, (c) => `\\${c}`);
  const lines = [`### Pinhole policy: ${r.failed ? `${r.failed} of ${r.results.length} rules fail` : `all ${r.results.length} rules pass`}`, '', '| Rule | Severity | Result | Violations |', '| --- | --- | --- | --- |'];
  for (const x of r.results) lines.push(`| ${esc(x.id)} | ${x.severity} | ${x.status === 'pass' ? 'pass' : '**fail**'} | ${x.violations.slice(0, 3).map((v) => esc(v.detail)).join('<br>')}${x.violations.length > 3 ? `<br>and ${x.violations.length - 3} more` : ''} |`);
  return `${lines.join('\n')}\n`;
}

/** Failing rules at or above `level`. */
export function policyFailsAt(r: PolicyReport, level: Severity): number {
  return r.results.filter((x) => x.status === 'fail' && SEVERITY_ORDER.indexOf(x.severity) <= SEVERITY_ORDER.indexOf(level)).length;
}
