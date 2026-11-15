/**
 * The analysis commands added in 0.2: can, blast, fix, hygiene, whatif.
 * Each returns text for the terminal; --format json returns the engine's
 * objects as they are.
 */
import {
  analyzeBlastRadius,
  analyzeCleanup,
  analyzeExposure,
  analyzeHygiene,
  applyChanges,
  changeScope,
  cleanupFindings,
  compareSeverity,
  crossChains,
  describeBreak,
  diffExposure,
  evaluatePath,
  findFixes,
  joinSnapshots,
  planFixes,
  parseIpv4,
  reachServices,
  serviceLabel,
  SEVERITY_ORDER,
  summarizeBreaks,
} from '@pinhole/engine';
import type { Breakage, BlastReport, MinCut, Change, CrossChain, ExposureDiff, JoinLink, JoinResult, FixCandidate, FixPlan, HygieneFinding, NetworkModel, PathResult, ServiceReach, Severity } from '@pinhole/engine';

export class LookupError extends Error {}

const PRIVATE = [
  [0x0a000000, 0x0affffff],
  [0xac100000, 0xac1fffff],
  [0xc0a80000, 0xc0a8ffff],
];

/** An interface ID, instance ID, private IP or instance Name tag, as an ENI ID. */
export function resolveEni(model: NetworkModel, ref: string): string {
  if (model.enis.has(ref)) return ref;
  const inst = model.instances.get(ref) ?? [...model.instances.values()].find((i) => i.name === ref);
  if (inst?.primaryEniId) return inst.primaryEniId;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ref)) {
    const hit = [...model.enis.values()].find((e) => e.privateIps.includes(ref));
    if (hit) return hit.id;
  }
  const named = [...model.instances.values()].filter((i) => i.name?.toLowerCase() === ref.toLowerCase());
  if (named.length === 1 && named[0]!.primaryEniId) return named[0]!.primaryEniId;
  if (named.length > 1) throw new LookupError(`"${ref}" names ${named.length} instances; use an instance or interface ID.`);
  throw new LookupError(`"${ref}" is not an interface ID, instance ID, private IP or instance name in this snapshot.`);
}

function isInternetRef(ref: string): string | undefined {
  if (ref === 'internet') return '198.51.100.1';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ref)) {
    const ip = parseIpv4(ref);
    if (!PRIVATE.some(([a, b]) => ip >= a! && ip <= b!)) return ref;
  }
  return undefined;
}

const sevTag = (s: Severity) => `[${s.toUpperCase()}]`;
const name = (model: NetworkModel, eniId: string) => {
  const e = model.enis.get(eniId);
  const inst = e?.instanceId ? model.instances.get(e.instanceId) : undefined;
  return inst?.name ? `${inst.name} (${eniId})` : eniId;
};

function hopsText(r: PathResult, indent = '    '): string[] {
  return r.hops.flatMap((h) => [`${indent}${h.decision === 'pass' ? 'ok ' : h.decision === 'block' ? 'NO ' : '?? '} ${h.stage}: ${h.detail}`, ...(h.caveat ? [`${indent}    note: ${h.caveat}`] : [])]);
}

// ------------------------------------------------------------------ can

export function canText(model: NetworkModel, fromRef: string, toRef: string, protocol: string, port: number | undefined): { text: string; json: unknown; reachable: boolean } {
  const to = resolveEni(model, toRef);
  const internet = isInternetRef(fromRef);
  if (internet) {
    if (port === undefined) {
      const report = analyzeExposure(model, { only: new Set([to]) });
      const lines = [`From the internet to ${name(model, to)}:`];
      if (!report.findings.length) lines.push('  nothing is reachable.');
      for (const f of report.findings) lines.push(`  ${sevTag(f.severity)} ${serviceLabel(f)} from ${f.sources.join(', ')}`);
      return { text: `${lines.join('\n')}\n`, json: report.findings, reachable: report.findings.length > 0 };
    }
    const r = evaluatePath(model, { from: { internet }, to: { eni: to }, protocol, port });
    return { text: `${r.summary}\n${hopsText(r).join('\n')}\n`, json: r, reachable: r.verdict === 'reachable' };
  }
  const from = resolveEni(model, fromRef);
  if (port !== undefined) {
    const r = evaluatePath(model, { from: { eni: from }, to: { eni: to }, protocol, port });
    return { text: `${r.summary}\n${hopsText(r).join('\n')}\n`, json: r, reachable: r.verdict === 'reachable' };
  }
  const reach = reachServices(model, from, to);
  const lines = [`From ${name(model, from)} to ${name(model, to)}:`];
  if (!reach.services.length) lines.push('  nothing is reachable.');
  for (const s of reach.services) lines.push(`  ${serviceLine(s)}`);
  return { text: `${lines.join('\n')}\n`, json: reach, reachable: reach.services.some((s) => s.verdict === 'reachable') };
}

function serviceLine(s: ServiceReach): string {
  const tags = [s.name, s.pivot ? 'gives a foothold' : '', s.verdict === 'unknown' ? `unknown: ${s.unknownAt ?? ''}` : '', s.returnPath === 'partial' ? 'responses only for some client ports' : ''].filter(Boolean).join('; ');
  return `${sevTag(s.severity)} ${serviceLabel(s)}${tags ? `  (${tags})` : ''}`;
}

// ------------------------------------------------------------------ blast

export function cutText(c: MinCut): string[] {
  if (!c.before) return [];
  const lines = ['', `Crown jewels: ${c.jewels.map((j) => `${j.name} (${j.reason})`).join('; ')}`];
  if (c.uncuttable) {
    lines.push('Smallest cut: some path to a crown jewel goes through a resource without security groups, so no set of rule removals cuts it.');
    return lines;
  }
  lines.push(`Smallest cut: removing ${c.ruleIds.length} rule(s) leaves no attack path to any crown jewel${c.verified ? ' (verified by re-analysis)' : ` (NOT verified: ${c.after} chain(s) remain)`}.`);
  for (const r of c.rules) lines.push(`  - ${r.id} in ${r.groupId}: ${r.text}`);
  breakLines(c.breaks, '  ').forEach((l) => lines.push(l));
  for (const x of c.cli) lines.push(`  $ ${x}`);
  return lines;
}

export function blastText(model: NetworkModel, b: BlastReport, minSeverity: Severity, cut?: MinCut): string {
  const limit = SEVERITY_ORDER.indexOf(minSeverity);
  const chains = b.chains.filter((c) => SEVERITY_ORDER.indexOf(c.severity) <= limit);
  const lines: string[] = [];
  lines.push(`Blast radius: ${b.entries.length} entry point(s), ${b.chains.length} attack chain(s).`);
  for (const f of b.footprints) {
    lines.push(`  ${f.entry.name}: reaches ${f.reachable.length} other resource(s), ${f.dataStores} data store(s), ${f.takeovers} it can take over. Entry: ${f.entry.how}.`);
  }
  if (b.stats.truncated) lines.push(`  Stopped after ${b.stats.pairsEvaluated} pairs; raise --max-pairs to see everything.`);
  lines.push('');
  for (const c of chains) {
    lines.push(`${sevTag(c.severity)} ${c.steps.map((s, i) => (i ? `--${s.service}${s.serviceName ? ` ${s.serviceName}` : ''}--> ${s.name}` : `internet --> ${s.name}`)).join(' ')}`);
    for (const w of c.why) lines.push(`    ${w}`);
  }
  if (!chains.length) lines.push(`No attack chains at or above ${minSeverity}.`);
  if (cut) lines.push(...cutText(cut));
  return `${lines.join('\n')}\n`;
}

// ------------------------------------------------------------------ across snapshots

export interface AcrossResult {
  keys: string[];
  links: JoinLink[];
  chains: CrossChain[];
  plan: FixPlan;
  /** For each plan step, the snapshot (account and Region) whose resources it changes. */
  stepScopes: (string | undefined)[];
}

/** Joins linked snapshots and finds the attack chains that cross between them, with a plan to cut them. */
export function across(inputs: { key: string; model: NetworkModel }[], depth: number): { across: AcrossResult[]; skipped: JoinResult['skipped'] } {
  const joined = joinSnapshots(inputs);
  return {
    across: joined.estates.map((estate) => {
      const r = crossChains(estate, { maxDepth: depth });
      const ids = new Set(r.chains.map((c) => c.id));
      const plan = planFixes(estate.model, r.exposure, r.blast, { goals: { chain: (c) => ids.has(c.id) } });
      return { keys: estate.keys, links: estate.links, chains: r.chains, plan, stepScopes: plan.steps.map((s) => (s.changes[0] ? changeScope(estate, s.changes[0] as never) : undefined)) };
    }),
    skipped: joined.skipped,
  };
}

export function acrossText(res: { across: AcrossResult[]; skipped: JoinResult['skipped'] }, minSeverity: Severity): string {
  const limit = SEVERITY_ORDER.indexOf(minSeverity);
  const lines: string[] = ['Across snapshots'];
  if (!res.across.length && !res.skipped.length) lines.push('  None of these snapshots are linked by a VPC peering connection or a transit gateway.');
  for (const a of res.across) {
    lines.push('', `${a.keys.join(' + ')}, linked by ${a.links.map((l) => `${l.kind === 'peering' ? 'peering connection' : 'transit gateway'} ${l.id}`).join(', ')}:`);
    const chains = a.chains.filter((c) => SEVERITY_ORDER.indexOf(c.severity) <= limit);
    for (const c of chains) {
      lines.push(`${sevTag(c.severity)} ${c.steps.map((s, i) => (i ? `--${s.service}${s.serviceName ? ` ${s.serviceName}` : ''}--> ${s.name} [${c.scopes[i]}]` : `internet --> ${s.name} [${c.scopes[i]}]`)).join(' ')}`);
      for (const w of c.why) lines.push(`    ${w}`);
    }
    if (!chains.length) lines.push(`  No attack chain crosses between them at or above ${minSeverity}.`);
    if (a.plan.steps.length) {
      lines.push('', `  To cut ${a.plan.before.chains - a.plan.after.chains} of ${a.plan.before.chains} with ${a.plan.steps.length} change(s), verified by re-analysis:`);
      a.plan.steps.forEach((s, i) => {
        lines.push(`  ${i + 1}. ${s.title}${a.stepScopes[i] ? ` (in ${a.stepScopes[i]})` : ''}`);
        for (const c of s.cli) lines.push(`     $ ${c}`);
      });
    }
  }
  for (const s of res.skipped) lines.push('', `Not joined: ${s.keys.join(' + ')}. ${s.reason}`);
  return `${lines.join('\n')}\n`;
}

// ------------------------------------------------------------------ fix

export function fixText(fixes: { label: string; severity: Severity; fixes: FixCandidate[] }[], all: boolean): string {
  const lines: string[] = [];
  for (const f of fixes) {
    lines.push(`${sevTag(f.severity)} ${f.label}`);
    const shown = all ? f.fixes : f.fixes.slice(0, 1);
    if (!shown.length) lines.push('    No fix found automatically.');
    for (const x of shown) {
      lines.push(`  ${x.verified ? (x.safe ? 'Verified, safe' : 'Verified') : 'NOT verified'}: ${x.title}`);
      for (const s of x.steps) lines.push(`    - ${s}`);
      if (x.bonus.length) lines.push(`    Also closes: ${x.bonus.map(delta).join('; ')}`);
      if (x.collateral.length) lines.push(`    Also affects (check these are not wanted): ${x.collateral.map(delta).join('; ')}`);
      if (x.opened.length) lines.push(`    WARNING, opens: ${x.opened.map(delta).join('; ')}`);
      breakLines(x.breaks, '    ').forEach((l) => lines.push(l));
      if (x.stillReachable.length) lines.push(`    Still reachable after a compromise of: ${[...new Set(x.stillReachable.map((c) => c.steps[0]!.name))].join(', ')}`);
      for (const c of x.cli) lines.push(`    $ ${c}`);
    }
    lines.push('');
  }
  if (!fixes.length) lines.push('Nothing to fix at this severity.');
  return `${lines.join('\n')}\n`;
}

/** Wanted traffic a change breaks, then a count of address-range connections it also cuts. */
function breakLines(list: Breakage[], pad: string): string[] {
  const { wanted, network } = summarizeBreaks(list);
  const out = wanted.slice(0, 8).map((b) => `${pad}BREAKS ${describeBreak(b)}`);
  if (wanted.length > 8) out.push(`${pad}... and ${wanted.length - 8} more`);
  if (network.length) {
    const n = new Set(network.map((b) => `${b.flow.from}>${b.flow.to}`)).size;
    out.push(`${pad}Also cuts ${n} connection(s) allowed only by address ranges: ${network.slice(0, 3).map(describeBreak).join('; ')}${network.length > 3 ? '; ...' : ''}`);
  }
  return out;
}

const delta = (d: ExposureDiff['deltas'][number]) => `${d.status} ${d.resourceName} ${d.protocol}${d.ports ? `/${d.ports.from === d.ports.to ? d.ports.from : `${d.ports.from}-${d.ports.to}`}` : ''}`;

export function fixesFor(model: NetworkModel, minSeverity: Severity) {
  const limit = SEVERITY_ORDER.indexOf(minSeverity);
  const report = analyzeExposure(model);
  return report.findings
    .filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= limit)
    .map((f) => ({ label: `${f.resourceName}: ${serviceLabel(f)} from ${f.sources.join(', ')}`, severity: f.severity, finding: f, fixes: findFixes(model, f) }));
}

// ------------------------------------------------------------------ hygiene

export function hygieneText(list: HygieneFinding[]): string {
  if (!list.length) return 'No rule hygiene findings.\n';
  const lines = list.flatMap((h) => [`${sevTag(h.severity)} ${h.title}${h.inExposure ? '  (already an internet exposure)' : ''}`, `    ${h.detail}`, ...(h.cli ?? []).map((x) => `    $ ${x}`)]);
  return `${lines.join('\n')}\n`;
}

export function hygiene(model: NetworkModel) {
  return [...analyzeHygiene(model, analyzeExposure(model)), ...cleanupFindings(model, analyzeCleanup(model))].sort((a, b) => compareSeverity(a.severity, b.severity));
}

// ------------------------------------------------------------------ whatif

export function whatIf(model: NetworkModel, changes: Change[]) {
  const after = applyChanges(model, changes);
  const e0 = analyzeExposure(model);
  const e1 = analyzeExposure(after);
  return diffExposure(e0, e1, { before: analyzeBlastRadius(model, e0), after: analyzeBlastRadius(after, e1) });
}

export function whatIfText(d: ExposureDiff): string {
  const lines: string[] = [];
  lines.push(`Internet exposure: ${d.deltas.length ? `${d.closed} closed, ${d.opened} opened, ${d.deltas.length - d.closed - d.opened} changed` : 'no change'}.`);
  for (const x of d.deltas) lines.push(`  ${sevTag(x.severity)} ${delta(x)}${x.status === 'narrowed' || x.status === 'widened' || x.status === 'changed' ? ` (${x.before.join(', ')} -> ${x.after.join(', ')})` : ''}`);
  lines.push(`Attack chains: ${d.chainsClosed.length} closed, ${d.chainsOpened.length} opened.`);
  for (const c of d.chainsClosed) lines.push(`  closed ${sevTag(c.severity)} ${c.steps.map((s) => s.name).join(' -> ')}`);
  for (const c of d.chainsOpened) lines.push(`  OPENED ${sevTag(c.severity)} ${c.steps.map((s) => s.name).join(' -> ')}`);
  return `${lines.join('\n')}\n`;
}

/** --revoke, --remove-nacl and --remove-public-ip shortcuts, as changes. */
export function shortcutChanges(model: NetworkModel, revoke: string[], removeNacl: string[], removePublic: string[]): Change[] {
  const out: Change[] = revoke.map((ruleId) => ({ kind: 'revoke-sg-rule', ruleId }));
  for (const ref of removeNacl) {
    const m = /^(acl-[\w-]+)#(ingress|egress)#(\d+)$/.exec(ref);
    if (!m) throw new LookupError(`--remove-nacl takes acl-ID#ingress#N or acl-ID#egress#N, not "${ref}".`);
    out.push({ kind: 'remove-nacl-entry', naclId: m[1]!, egress: m[2] === 'egress', ruleNumber: Number(m[3]) });
  }
  for (const ref of removePublic) {
    const eni = [...model.enis.values()].find((e) => e.publicAddresses.some((p) => p.publicIp === ref));
    if (!eni) throw new LookupError(`No interface has public IP ${ref}.`);
    out.push({ kind: 'remove-public-ip', eniId: eni.id, publicIp: ref });
  }
  return out;
}


// ------------------------------------------------------------------ plan

export function plan(model: NetworkModel, protect?: (m: NetworkModel) => number): FixPlan {
  const e = analyzeExposure(model);
  return planFixes(model, e, analyzeBlastRadius(model, e), protect ? { protect } : {});
}

export function planText(p: FixPlan): string {
  if (!p.before.exposures && !p.before.chains) return 'Nothing critical or high to fix.\n';
  const lines = [
    `Fix plan: ${p.steps.length} change(s) close ${p.before.exposures - p.after.exposures} of ${p.before.exposures} critical and high exposures and ${p.before.chains - p.after.chains} of ${p.before.chains} attack chains.`,
    'Each step was applied to a copy of the snapshot and everything re-analysed. Apply them in order.',
    p.steps.length > 1
      ? p.optimality.status === 'optimal'
        ? `No plan with fewer steps exists among the ${p.stats.candidates} candidate changes considered (${p.optimality.searched} smaller plans checked).`
        : `At least ${p.optimality.lowerBound} steps are needed; the search for a shorter plan stopped after ${p.optimality.searched} tries.`
      : '',
    '',
  ];
  p.steps.forEach((s, i) => {
    lines.push(`${i + 1}. ${s.title}`);
    lines.push(`   ${s.rationale}`);
    if (s.closes.length) lines.push(`   Closes: ${s.closes.map(delta).join('; ')}`);
    if (s.chainsCut.length) lines.push(`   Cuts chains: ${s.chainsCut.map((c) => c.steps.map((x) => x.name).join(' -> ')).join('; ')}`);
    if (s.collateral.length) lines.push(`   Also affects (check these are not wanted): ${s.collateral.map(delta).join('; ')}`);
    breakLines(s.breaks, '   ').forEach((l) => lines.push(l));
    for (const c of s.cli) lines.push(`   $ ${c}`);
    lines.push('');
  });
  if (p.unresolved.length) lines.push(`Not closed by any single change: ${p.unresolved.join('; ')}`);
  return `${lines.join('\n')}\n`;
}
