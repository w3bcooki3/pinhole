/**
 * Command-line entry point. `run()` takes argv and an IO object and returns an
 * exit code, so tests can drive it without spawning processes.
 *
 * Exit codes:
 *   0  success (and, with --fail-on, no finding at or above that severity)
 *   1  usage or input error
 *   2  --fail-on threshold reached
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { analyzeExposure, normalize, assertSnapshot, SEVERITY_ORDER, SnapshotError } from '@pinhole/engine';
import type { Severity, Snapshot } from '@pinhole/engine';
import { formatExposureText } from './format-text.js';
import { analyzeBlastRadius, assertChanges, ChangeError } from '@pinhole/engine';
import type { Change } from '@pinhole/engine';
import { blastText, canText, fixesFor, fixText, hygiene, hygieneText, LookupError, plan, planText, shortcutChanges, whatIf, whatIfText } from './advanced.js';
import { VERSION } from './version.js';

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

const USAGE = `pinhole ${VERSION}: what can reach what in an AWS network

Usage:
  pinhole collect  [--profile NAME] [--region REGION] [--out FILE]
  pinhole exposure SNAPSHOT [--format text|json] [--min-severity LEVEL]
                              [--fail-on LEVEL] [--verbose]
  pinhole can      SNAPSHOT --from WHO --to WHO [--port N] [--protocol tcp|udp|icmp]
  pinhole blast    SNAPSHOT [--depth N] [--min-severity LEVEL] [--fail-on LEVEL]
  pinhole fix      SNAPSHOT [--plan] [--min-severity LEVEL] [--all]
  pinhole hygiene  SNAPSHOT [--fail-on LEVEL]
  pinhole whatif   SNAPSHOT [--revoke SGR-ID]... [--remove-nacl ACL#ingress#N]...
                            [--remove-public-ip IP]... [--changes FILE.json]
  pinhole validate SNAPSHOT
  pinhole --version | --help

Every analysis command also takes --format text|json.

collect   Reads the network configuration of one account and region with
          read-only describe calls and writes a snapshot file. Uses the
          standard AWS credential chain, or --profile.
exposure  Reports every interface and load balancer listener reachable from
          the internet, highest risk first, with the exact path and rules.
can       Whether one resource can reach another, and on which services.
          WHO is an interface ID, instance ID, private IP, instance Name tag,
          a public IP, or "internet". Without --port, lists every service.
blast     What an attacker reaches after taking over each internet-exposed
          resource, moving on through remote administration services.
fix       For each finding, the smallest verified change that closes it, as
          AWS CLI commands. With --plan, the fewest changes, in order, that
          close every critical and high exposure and attack chain.
          Nothing is run; review and run the commands yourself.
hygiene   Redundant, shadowed, stale, unused and overly broad rules.
whatif    Exposure and attack chains before and after proposed changes.
validate  Loads a snapshot and prints what it contains and any warnings.

LEVEL is one of: ${SEVERITY_ORDER.join(', ')}.
`;

function readSnapshot(path: string): Snapshot {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new SnapshotError(`Cannot read ${path}: ${(e as Error).message}`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (e) {
    throw new SnapshotError(`${path} is not valid JSON: ${(e as Error).message}`);
  }
  assertSnapshot(value);
  return value;
}

function severityArg(value: string | undefined, flag: string): Severity | undefined {
  if (value === undefined) return undefined;
  if (!(SEVERITY_ORDER as string[]).includes(value)) throw new UsageError(`${flag} must be one of ${SEVERITY_ORDER.join(', ')}`);
  return value as Severity;
}

class UsageError extends Error {}

async function cmdCollect(args: string[], io: Io): Promise<number> {
  const { values } = parseArgs({ args, options: { profile: { type: 'string' }, region: { type: 'string' }, out: { type: 'string' } }, strict: true });
  const region = values.region ?? process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION;
  if (!region) throw new UsageError('No region: pass --region or set AWS_REGION.');
  // Imported lazily so the analysis commands never load the AWS SDK.
  const { collectSnapshot, sdkSender } = await import('@pinhole/collector');
  io.stderr(`Collecting ${region} (read-only)...\n`);
  const snap = await collectSnapshot(sdkSender({ region, ...(values.profile ? { profile: values.profile } : {}) }), {
    region,
    toolVersion: VERSION,
    onProgress: (m) => io.stderr(`  ${m}\n`),
  });
  const out = values.out ?? `pinhole-snapshot-${snap.accountId ?? 'unknown'}-${region}.json`;
  writeFileSync(out, `${JSON.stringify(snap, null, 2)}\n`, { mode: 0o600 });
  io.stderr(`Wrote ${out}\n`);
  if (snap.errors?.length) {
    io.stderr(`warning: ${snap.errors.length} API call(s) failed; see "errors" in the snapshot:\n`);
    for (const e of snap.errors) io.stderr(`  ${e.api}: ${e.message}\n`);
  }
  return 0;
}

function cmdExposure(args: string[], io: Io): number {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      format: { type: 'string', default: 'text' },
      'min-severity': { type: 'string' },
      'fail-on': { type: 'string' },
      verbose: { type: 'boolean', default: false },
    },
    strict: true,
  });
  const [file] = positionals;
  if (!file || positionals.length > 1) throw new UsageError('exposure takes exactly one snapshot file.');
  const minSeverity = severityArg(values['min-severity'], '--min-severity');
  const failOn = severityArg(values['fail-on'], '--fail-on');
  if (values.format !== 'text' && values.format !== 'json') throw new UsageError('--format must be text or json');

  const snap = readSnapshot(file);
  const report = analyzeExposure(normalize(snap));
  if (values.format === 'json') {
    const min = SEVERITY_ORDER.indexOf(minSeverity ?? 'info');
    const findings = report.findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= min);
    io.stdout(
      `${JSON.stringify(
        {
          tool: { name: 'pinhole', version: VERSION },
          snapshot: { accountId: snap.accountId, region: snap.region, collectedAt: snap.collectedAt, source: snap.source },
          summary: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, report.findings.filter((f) => f.severity === s).length])),
          stats: report.stats,
          findings,
          warnings: report.warnings,
        },
        null,
        2,
      )}\n`,
    );
  } else {
    io.stdout(safeForTerminal(formatExposureText(report, snap, { verbose: values.verbose ?? false, ...(minSeverity ? { minSeverity } : {}) })));
  }
  if (failOn) {
    const limit = SEVERITY_ORDER.indexOf(failOn);
    const hits = report.findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= limit).length;
    if (hits > 0) {
      io.stderr(`${hits} finding(s) at or above ${failOn}.\n`);
      return 2;
    }
  }
  return 0;
}

const FORMAT = { format: { type: 'string', default: 'text' } } as const;
function snapshotModel(positionals: string[], cmd: string) {
  const [file] = positionals;
  if (!file || positionals.length > 1) throw new UsageError(`${cmd} takes exactly one snapshot file.`);
  return normalize(readSnapshot(file));
}
function checkFormat(f: string | undefined): 'text' | 'json' {
  if (f !== 'text' && f !== 'json') throw new UsageError('--format must be text or json');
  return f;
}
const json = (v: unknown) => `${JSON.stringify(v, null, 2)}\n`;

function cmdCan(args: string[], io: Io): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, strict: true, options: { ...FORMAT, from: { type: 'string' }, to: { type: 'string' }, port: { type: 'string' }, protocol: { type: 'string', default: 'tcp' } } });
  const format = checkFormat(values.format);
  if (!values.from || !values.to) throw new UsageError('can needs --from and --to.');
  const port = values.port === undefined ? undefined : Number(values.port);
  if (port !== undefined && (!Number.isInteger(port) || port < 0 || port > 65535)) throw new UsageError('--port must be 0-65535.');
  const r = canText(snapshotModel(positionals, 'can'), values.from, values.to, values.protocol ?? 'tcp', port);
  io.stdout(format === 'json' ? json(r.json) : safeForTerminal(r.text));
  return 0;
}

function cmdBlast(args: string[], io: Io): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, strict: true, options: { ...FORMAT, depth: { type: 'string', default: '3' }, 'max-pairs': { type: 'string' }, 'min-severity': { type: 'string' }, 'fail-on': { type: 'string' } } });
  const format = checkFormat(values.format);
  const depth = Number(values.depth);
  if (!Number.isInteger(depth) || depth < 1 || depth > 6) throw new UsageError('--depth must be 1-6.');
  const failOn = severityArg(values['fail-on'], '--fail-on');
  const model = snapshotModel(positionals, 'blast');
  const report = analyzeBlastRadius(model, analyzeExposure(model), { maxDepth: depth, ...(values['max-pairs'] ? { maxPairs: Number(values['max-pairs']) } : {}) });
  io.stdout(format === 'json' ? json(report) : safeForTerminal(blastText(model, report, severityArg(values['min-severity'], '--min-severity') ?? 'info')));
  return failOn && report.chains.some((c) => SEVERITY_ORDER.indexOf(c.severity) <= SEVERITY_ORDER.indexOf(failOn)) ? 2 : 0;
}

function cmdFix(args: string[], io: Io): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, strict: true, options: { ...FORMAT, 'min-severity': { type: 'string' }, all: { type: 'boolean', default: false }, plan: { type: 'boolean', default: false } } });
  const format = checkFormat(values.format);
  if (values.plan) {
    const p = plan(snapshotModel(positionals, 'fix'));
    io.stdout(format === 'json' ? json(p) : safeForTerminal(planText(p)));
    return 0;
  }
  const list = fixesFor(snapshotModel(positionals, 'fix'), severityArg(values['min-severity'], '--min-severity') ?? 'high');
  io.stdout(format === 'json' ? json(list.map(({ finding, fixes }) => ({ finding, fixes }))) : safeForTerminal(fixText(list, values.all ?? false)));
  return 0;
}

function cmdHygiene(args: string[], io: Io): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, strict: true, options: { ...FORMAT, 'fail-on': { type: 'string' } } });
  const format = checkFormat(values.format);
  const failOn = severityArg(values['fail-on'], '--fail-on');
  const list = hygiene(snapshotModel(positionals, 'hygiene'));
  io.stdout(format === 'json' ? json(list) : safeForTerminal(hygieneText(list)));
  return failOn && list.some((h) => SEVERITY_ORDER.indexOf(h.severity) <= SEVERITY_ORDER.indexOf(failOn)) ? 2 : 0;
}

function cmdWhatIf(args: string[], io: Io): number {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    options: { ...FORMAT, revoke: { type: 'string', multiple: true }, 'remove-nacl': { type: 'string', multiple: true }, 'remove-public-ip': { type: 'string', multiple: true }, changes: { type: 'string' } },
  });
  const format = checkFormat(values.format);
  const model = snapshotModel(positionals, 'whatif');
  const changes: Change[] = shortcutChanges(model, values.revoke ?? [], values['remove-nacl'] ?? [], values['remove-public-ip'] ?? []);
  if (values.changes) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(values.changes, 'utf8'));
    } catch (e) {
      throw new UsageError(`Cannot read ${values.changes}: ${(e as Error).message}`);
    }
    try {
      assertChanges(parsed);
    } catch (e) {
      throw new UsageError(`${values.changes}: ${(e as Error).message}`);
    }
    changes.push(...parsed);
  }
  if (!changes.length) throw new UsageError('whatif needs at least one change.');
  const d = whatIf(model, changes);
  io.stdout(format === 'json' ? json(d) : safeForTerminal(whatIfText(d)));
  return 0;
}

function cmdValidate(args: string[], io: Io): number {
  const { positionals } = parseArgs({ args, allowPositionals: true, options: {}, strict: true });
  const [file] = positionals;
  if (!file) throw new UsageError('validate takes a snapshot file.');
  const snap = readSnapshot(file);
  const m = normalize(snap);
  const lines = [
    `Snapshot ${file}: schema ${snap.schemaVersion}, account ${snap.accountId ?? 'unknown'}, region ${snap.region ?? 'unknown'}, source ${snap.source ?? 'unknown'}`,
    `  ${m.vpcs.size} VPCs, ${m.subnets.size} subnets, ${m.routeTables.size} route tables, ${m.nacls.size} network ACLs`,
    `  ${m.securityGroups.size} security groups, ${m.enis.size} network interfaces, ${m.instances.size} instances`,
    `  ${m.peerings.size} peering connections, ${m.transitGateways.size} transit gateways, ${m.tgwRouteTables.size} TGW route tables`,
    `  ${m.loadBalancers.size} load balancers, ${m.listeners.length} listeners, ${m.targetGroups.size} target groups`,
  ];
  const report = analyzeExposure(m);
  if (report.warnings.length) {
    lines.push(`Warnings (${report.warnings.length}):`);
    for (const w of report.warnings) lines.push(`  - [${w.code}] ${w.message}`);
  } else {
    lines.push('No warnings.');
  }
  io.stdout(`${lines.join('\n')}\n`);
  return 0;
}

/**
 * Snapshot text (tags, names) is untrusted. Escape sequences in it could move
 * the cursor or rewrite earlier lines in a terminal, so control characters
 * other than newline and tab are shown as U+FFFD.
 */
export function safeForTerminal(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, '\ufffd');
}

export async function run(argv: string[], io: Io): Promise<number> {
  const [cmd, ...rest] = argv;
  try {
    switch (cmd) {
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        io.stdout(USAGE);
        return cmd === undefined ? 1 : 0;
      case '--version':
      case '-v':
        io.stdout(`${VERSION}\n`);
        return 0;
      case 'collect':
        return await cmdCollect(rest, io);
      case 'exposure':
        return cmdExposure(rest, io);
      case 'validate':
        return cmdValidate(rest, io);
      case 'can':
        return cmdCan(rest, io);
      case 'blast':
        return cmdBlast(rest, io);
      case 'fix':
        return cmdFix(rest, io);
      case 'hygiene':
        return cmdHygiene(rest, io);
      case 'whatif':
        return cmdWhatIf(rest, io);
      default:
        throw new UsageError(`Unknown command "${cmd}".`);
    }
  } catch (e) {
    if (e instanceof LookupError || e instanceof ChangeError) {
      io.stderr(`error: ${e.message}\n`);
      return 1;
    }
    if (e instanceof UsageError || e instanceof SnapshotError || (e as { code?: string }).code?.startsWith('ERR_PARSE_ARGS')) {
      io.stderr(`error: ${(e as Error).message}\n\n${e instanceof UsageError || (e as { code?: string }).code ? USAGE : ''}`);
      return 1;
    }
    io.stderr(`error: ${(e as Error).message ?? String(e)}\n`);
    return 1;
  }
}
