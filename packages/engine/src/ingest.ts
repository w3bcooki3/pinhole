/**
 * Reading what people actually have into snapshots.
 *
 * Accepts, from one file or several loaded together:
 *  - Pinhole snapshots (one per file, an array of them, or several documents
 *    concatenated in one file, such as `cat *.json > all.json`);
 *  - plain AWS CLI JSON output (`aws ec2 describe-security-groups > sg.json`,
 *    describe-instances, describe-route-tables, elbv2 describe-load-balancers,
 *    network-firewall describe-firewall and so on), assembled into one
 *    snapshot per account and Region;
 *  - text in UTF-8 or UTF-16 (what Windows PowerShell's `>` writes), with or
 *    without a byte order mark;
 *  - JSON with comments or trailing commas (files edited by hand), said so.
 *
 * Everything else gets a message naming what the file looks like and what
 * to load instead: AWS CLI text or table output, YAML, ZIP, HTML, Terraform,
 * CloudFormation, an IAM policy.
 *
 * Secrets are removed from every input before anything else: VPN tunnel
 * configuration and pre-shared keys, and anything that looks like an AWS
 * secret key or session token. Snapshots are validated by assertSnapshot as
 * before; this module only finds and shapes the data.
 */
import { assertSnapshot, SNAPSHOT_SCHEMA_VERSION, SnapshotError } from './snapshot.js';
import type { Snapshot } from './snapshot.js';

export interface IngestInput {
  name: string;
  /** Raw bytes (preferred: the encoding is detected), or already decoded text. */
  bytes?: Uint8Array;
  text?: string;
}

export interface IngestedSnapshot {
  snapshot: Snapshot;
  /** A name for the result: the file name, or "N AWS CLI files" for assembled output. */
  name: string;
  /** The files it came from. */
  sources: string[];
}

export interface IngestResult {
  snapshots: IngestedSnapshot[];
  /** Things worth knowing that did not stop the load (comments removed, a file cut short by paging). */
  notes: string[];
  /** One message per input that could not be used. */
  errors: string[];
}

// ------------------------------------------------------------------ bytes to text

/** Decodes bytes as UTF-8 or UTF-16 (detected from a byte order mark or the zero-byte pattern), without a byte order mark. */
export function decodeBytes(b: Uint8Array): string {
  const td = (enc: string, from = 0) => new TextDecoder(enc, { fatal: false }).decode(b.subarray(from));
  if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return td('utf-8', 3);
  if (b[0] === 0xff && b[1] === 0xfe) return td('utf-16le', 2);
  if (b[0] === 0xfe && b[1] === 0xff) return td('utf-16be', 2);
  // UTF-16 without a byte order mark: JSON starts with ASCII, so every other byte is zero.
  if (b.length >= 4) {
    if (b[0] !== 0 && b[1] === 0 && b[2] !== 0 && b[3] === 0) return td('utf-16le');
    if (b[0] === 0 && b[1] !== 0 && b[2] === 0 && b[3] !== 0) return td('utf-16be');
  }
  return td('utf-8');
}

/** What a file's first bytes say it is, when it is not text. */
export function sniffBinary(b: Uint8Array): string | undefined {
  if (b[0] === 0x1f && b[1] === 0x8b) return 'gzip';
  if (b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5)) return 'zip';
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return 'pdf';
  return undefined;
}

// ------------------------------------------------------------------ text to JSON values

/** Line and column of a character offset, for error messages. */
function lineCol(text: string, pos: number): string {
  let line = 1;
  let col = 1;
  for (let i = 0; i < pos && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      col = 1;
    } else col++;
  }
  return `line ${line}, column ${col}`;
}

/**
 * The offset of the first JSON syntax error, found by scanning the text: the
 * same answer in every browser, whatever its error message says.
 */
export function firstJsonError(text: string): number {
  let i = 0;
  const n = text.length;
  const ws = () => {
    while (i < n && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++;
  };
  const fail = (): never => {
    throw i;
  };
  const value = (depth: number): void => {
    if (depth > 10_000) fail();
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      ws();
      if (text[i] === '}') return void i++;
      for (;;) {
        ws();
        if (text[i] !== '"') fail();
        str();
        ws();
        if (text[i] !== ':') fail();
        i++;
        value(depth + 1);
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === '}') return void i++;
        fail();
      }
    }
    if (c === '[') {
      i++;
      ws();
      if (text[i] === ']') return void i++;
      for (;;) {
        value(depth + 1);
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === ']') return void i++;
        fail();
      }
    }
    if (c === '"') return str();
    const m = /^(-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i, i + 400));
    if (!m) fail();
    i += m![0].length;
  };
  const str = () => {
    i++;
    while (i < n && text[i] !== '"') {
      if (text.charCodeAt(i) < 0x20) fail();
      if (text[i] === '\\') {
        i++;
        if (text[i] === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 1, i + 5))) fail();
          i += 4;
        } else if (!'"\\/bfnrt'.includes(text[i] ?? 'x')) fail();
      }
      i++;
    }
    if (i >= n) fail();
    i++;
  };
  try {
    value(0);
    ws();
    return i < n ? i : -1;
  } catch (at) {
    return typeof at === 'number' ? at : 0;
  }
}

/** The offset V8, SpiderMonkey or JavaScriptCore reports for a JSON syntax error. */
function errorOffset(text: string, e: unknown): number | undefined {
  const m = String((e as Error)?.message ?? '');
  const pos = /position (\d+)/.exec(m);
  if (pos) return Number(pos[1]);
  const lc = /line (\d+) column (\d+)/.exec(m);
  if (lc) {
    let line = 1;
    let i = 0;
    while (line < Number(lc[1]) && i < text.length) if (text.charCodeAt(i++) === 10) line++;
    return i + Number(lc[2]) - 1;
  }
  return undefined;
}

/**
 * Removes comments and trailing commas outside strings. Returns undefined
 * when there were none, so a strict parse error stands as it was.
 */
function relax(text: string): string | undefined {
  let out = '';
  let changed = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j;
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
      changed = true;
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end < 0 ? text.length : end + 1;
      changed = true;
      continue;
    }
    if (c === ',') {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j]!)) j++;
      if (text[j] === '}' || text[j] === ']') {
        changed = true;
        continue;
      }
    }
    out += c;
  }
  return changed ? out : undefined;
}

/**
 * Splits text holding several JSON documents one after another (NDJSON, or
 * files joined with cat) into one string per document. Returns undefined
 * when the text is a single document or is not of that form.
 */
function splitDocuments(text: string): string[] | undefined {
  const docs: string[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      i = j;
      continue;
    }
    if (c === '{' || c === '[') {
      if (depth === 0) start = i;
      depth++;
    } else if (c === '}' || c === ']') {
      depth--;
      if (depth < 0) return undefined;
      if (depth === 0) docs.push(text.slice(start, i + 1));
    } else if (depth === 0 && !/\s/.test(c)) return undefined;
  }
  return depth === 0 && docs.length > 1 ? docs : undefined;
}

/** What a non-JSON text looks like, for a helpful message. */
function describeText(t: string): string | undefined {
  const head = t.slice(0, 2000);
  if (/^\s*<(!doctype html|html|head|body)\b/i.test(head)) return 'an HTML page, not a snapshot. Save the JSON file itself, not the page that shows it';
  if (/^[-+|]{3,}/m.test(head) || /^\|\s+\w/m.test(head)) return 'AWS CLI table output. Run the command again with --output json';
  if (/^(VPCS|SUBNETS|SECURITYGROUPS|ROUTETABLES|RESERVATIONS|INSTANCES|NETWORKINTERFACES|IPPERMISSIONS)\t/m.test(head)) return 'AWS CLI text output. Run the command again with --output json';
  if (/^\s*-{3,}\s*$/m.test(head) || /^\s*[A-Za-z][\w-]*:\s*(\n|$)/m.test(head)) {
    if (/AWSTemplateFormatVersion|Resources:\s*\n/.test(head)) return 'a CloudFormation template in YAML. Pinhole reads the collected network, not templates';
    return 'YAML. Run the AWS CLI with --output json, or load the pinhole-snapshot JSON file';
  }
  if (/^\s*(resource|provider|module|variable|terraform)\s+"/m.test(head)) return 'Terraform code. Pinhole reads the collected network; a Terraform plan is checked against a snapshot with `pinhole plan`';
  return undefined;
}

export interface ParsedText {
  values: unknown[];
  notes: string[];
}

/** Parses JSON text into one or more values: strict first, then with comments and trailing commas removed, then as several documents. */
export function parseJsonText(text: string, name: string): ParsedText {
  const t = text.replace(/^﻿/, '');
  if (!t.trim()) throw new SnapshotError(`${name} is empty.`);
  try {
    return { values: [JSON.parse(t)], notes: [] };
  } catch (e) {
    if (e instanceof RangeError) throw new SnapshotError(`${name} is nested too deeply to read.`);
    const relaxed = relax(t);
    if (relaxed !== undefined) {
      try {
        return { values: [JSON.parse(relaxed)], notes: [`${name}: read with its comments and trailing commas left out.`] };
      } catch {
        /* fall through */
      }
    }
    const docs = splitDocuments(relaxed ?? t);
    if (docs) {
      try {
        return { values: docs.map((d) => JSON.parse(d)), notes: [`${name}: read as ${docs.length} JSON documents one after another.`] };
      } catch {
        /* fall through */
      }
    }
    const looks = describeText(t);
    if (looks) throw new SnapshotError(`${name} looks like ${looks}.`);
    const scanned = t.length <= 50_000_000 ? firstJsonError(t) : -1;
    const at = scanned >= 0 ? scanned : errorOffset(t, e);
    throw new SnapshotError(`${name} is not valid JSON${at !== undefined ? ` (problem at ${lineCol(t, at)})` : ''}. Load the pinhole-snapshot-….json file the collector writes, or AWS CLI output saved with --output json.`);
  }
}

// ------------------------------------------------------------------ secrets out

const SECRET_KEY = /^(CustomerGatewayConfiguration|PreSharedKey|SecretAccessKey|SessionToken|Password|PrivateKey)$/i;
/** AWS secret access keys are 40 characters of base64; session tokens are much longer. */
const SECRET_VALUE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9/+]{40}$|^(FwoG|IQoJ)[A-Za-z0-9/+=]{100,}$/;

/** Removes secrets wherever they are, in place. Returns how many were removed. */
export function scrubSecrets(value: unknown): number {
  let n = 0;
  const seen = new Set<object>();
  const walk = (v: unknown, depth: number): void => {
    if (!v || typeof v !== 'object' || depth > 64 || seen.has(v)) return;
    seen.add(v);
    if (Array.isArray(v)) {
      for (const x of v) walk(x, depth + 1);
      return;
    }
    const o = v as Record<string, unknown>;
    for (const k of Object.keys(o)) {
      const x = o[k];
      if (SECRET_KEY.test(k) || (typeof x === 'string' && SECRET_VALUE.test(x) && /key|secret|token|credential/i.test(k))) {
        delete o[k];
        n++;
      } else walk(x, depth + 1);
    }
  };
  walk(value, 0);
  return n;
}

// ------------------------------------------------------------------ raw AWS CLI output

/** Top-level keys of AWS CLI describe output, and where each goes in a snapshot. */
const RAW_EC2: Record<string, string> = {
  Vpcs: 'Vpcs', Subnets: 'Subnets', RouteTables: 'RouteTables', InternetGateways: 'InternetGateways',
  EgressOnlyInternetGateways: 'EgressOnlyInternetGateways', NatGateways: 'NatGateways', Addresses: 'Addresses',
  VpnGateways: 'VpnGateways', VpnConnections: 'VpnConnections', VpcPeeringConnections: 'VpcPeeringConnections',
  TransitGateways: 'TransitGateways', TransitGatewayAttachments: 'TransitGatewayAttachments',
  TransitGatewayVpcAttachments: 'TransitGatewayVpcAttachments', TransitGatewayRouteTables: 'TransitGatewayRouteTables',
  NetworkAcls: 'NetworkAcls', SecurityGroups: 'SecurityGroups', SecurityGroupRules: 'SecurityGroupRules',
  PrefixLists: '', ManagedPrefixLists: 'ManagedPrefixLists', NetworkInterfaces: 'NetworkInterfaces', VpcEndpoints: 'VpcEndpoints',
  ServiceConfigurations: 'VpcEndpointServiceConfigurations', VpcEndpointConnections: 'VpcEndpointConnections',
};
const RAW_ELB: Record<string, string> = { LoadBalancers: 'LoadBalancers', Listeners: 'Listeners', TargetGroups: 'TargetGroups', Rules: 'Rules' };
/** Keys that say what a file is without carrying data Pinhole reads. */
const NOT_NETWORK: [RegExp, string][] = [
  [/^(Statement|Version)$/, 'an IAM policy'],
  [/^(AWSTemplateFormatVersion|Resources)$/, 'a CloudFormation template'],
  [/^(format_version|terraform_version|planned_values|resource_changes)$/, 'a Terraform plan or state. A plan is checked against a snapshot with `pinhole plan SNAPSHOT --terraform plan.json`'],
  [/^(LoadBalancerDescriptions)$/, 'Classic Load Balancer output, which Pinhole does not analyse'],
  [/^(configurationItems|ConfigurationItems)$/, 'AWS Config output. Collect with the Pinhole collector or the CloudShell script instead'],
  [/^(UserId|Account|Arn)$/, 'the output of aws sts get-caller-identity'],
];

const ID_FIELD: Record<string, string> = {
  Vpcs: 'VpcId', Subnets: 'SubnetId', RouteTables: 'RouteTableId', InternetGateways: 'InternetGatewayId',
  EgressOnlyInternetGateways: 'EgressOnlyInternetGatewayId', NatGateways: 'NatGatewayId', Addresses: 'PublicIp',
  VpnGateways: 'VpnGatewayId', VpnConnections: 'VpnConnectionId', VpcPeeringConnections: 'VpcPeeringConnectionId',
  TransitGateways: 'TransitGatewayId', TransitGatewayAttachments: 'TransitGatewayAttachmentId',
  TransitGatewayVpcAttachments: 'TransitGatewayAttachmentId', TransitGatewayRouteTables: 'TransitGatewayRouteTableId',
  NetworkAcls: 'NetworkAclId', SecurityGroups: 'GroupId', SecurityGroupRules: 'SecurityGroupRuleId',
  ManagedPrefixLists: 'PrefixListId', NetworkInterfaces: 'NetworkInterfaceId', VpcEndpoints: 'VpcEndpointId',
  VpcEndpointServiceConfigurations: 'ServiceId', VpcEndpointConnections: 'VpcEndpointId', Instances: 'InstanceId',
  LoadBalancers: 'LoadBalancerArn', Listeners: 'ListenerArn', TargetGroups: 'TargetGroupArn', Rules: 'RuleArn',
};

type Obj = Record<string, unknown>;
const own = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Account and Region a piece of raw output belongs to, from owner IDs, ARNs and zones. */
function scopeOf(v: unknown): { account?: string; region?: string } {
  let account: string | undefined;
  let region: string | undefined;
  let budget = 5000;
  const walk = (x: unknown): void => {
    if (budget-- <= 0 || (account && region)) return;
    if (Array.isArray(x)) {
      for (const y of x) walk(y);
      return;
    }
    if (!isObj(x)) return;
    for (const [k, y] of Object.entries(x)) {
      if (typeof y === 'string') {
        if (!account && (k === 'OwnerId' || k === 'AccountId') && /^\d{12}$/.test(y)) account = y;
        if (!region && k === 'AvailabilityZone') region = /^([a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d+)/.exec(y)?.[1];
        const arn = /^arn:aws[\w-]*:[\w-]+:([a-z]{2}(?:-gov|-iso[a-z]*)?-[a-z]+-\d+):(\d{12}):/.exec(y);
        if (arn) {
          region ??= arn[1];
          account ??= arn[2];
        }
      } else walk(y);
    }
  };
  walk(v);
  return { ...(account ? { account } : {}), ...(region ? { region } : {}) };
}

interface RawPiece {
  name: string;
  ec2: Record<string, unknown[]>;
  elbv2: Record<string, unknown[]>;
  firewalls: Obj[];
  policies: Record<string, Obj>;
  ruleGroups: Record<string, Obj>;
  scope: { account?: string; region?: string };
}

/** Reads one value as raw AWS CLI output, or returns why it is not. */
function rawPiece(v: unknown, name: string, notes: string[]): RawPiece | string {
  if (!isObj(v)) return 'not an object';
  const piece: RawPiece = { name, ec2: {}, elbv2: {}, firewalls: [], policies: {}, ruleGroups: {}, scope: scopeOf(v) };
  let used = 0;
  for (const [k, x] of Object.entries(v)) {
    if (k === 'NextToken' || k === 'Marker' || k === 'NextMarker') {
      if (x) notes.push(`${name} was cut short by paging (it has a ${k}): run the command without --max-items or --page-size, or load every page.`);
      continue;
    }
    if (k === 'Reservations' && Array.isArray(x)) {
      piece.ec2.Instances = x.flatMap((r) => (isObj(r) && Array.isArray(r.Instances) ? r.Instances : []));
      used++;
    } else if (own(RAW_EC2, k) && Array.isArray(x)) {
      if (!RAW_EC2[k]) {
        notes.push(`${name}: AWS-managed prefix lists (describe-prefix-lists) carry no entries; use describe-managed-prefix-lists and get-managed-prefix-list-entries.`);
        continue;
      }
      piece.ec2[RAW_EC2[k]!] = x;
      used++;
    } else if (own(RAW_ELB, k) && Array.isArray(x)) {
      piece.elbv2[RAW_ELB[k]!] = x;
      used++;
    } else if (k === 'TargetHealthDescriptions') {
      notes.push(`${name}: target health output does not say which target group it belongs to, so it was left out. The Pinhole collector and CloudShell script record it per target group.`);
    } else if (k === 'Firewall' && isObj(x)) {
      piece.firewalls.push({ Firewall: x, ...(isObj(v.FirewallStatus) ? { FirewallStatus: v.FirewallStatus } : {}) });
      used++;
    } else if (k === 'FirewallPolicyResponse' && isObj(x) && typeof x.FirewallPolicyArn === 'string') {
      piece.policies[x.FirewallPolicyArn] = { FirewallPolicyResponse: x, FirewallPolicy: v.FirewallPolicy };
      used++;
    } else if (k === 'RuleGroupResponse' && isObj(x) && typeof x.RuleGroupArn === 'string') {
      piece.ruleGroups[x.RuleGroupArn] = { RuleGroupResponse: x, RuleGroup: v.RuleGroup };
      used++;
    }
  }
  if (used) return piece;
  for (const [re, what] of NOT_NETWORK) if (Object.keys(v).some((k) => re.test(k))) return `looks like ${what}`;
  const keys = Object.keys(v).slice(0, 6).join(', ');
  return `has none of the fields Pinhole reads (it has ${keys || 'no fields'})`;
}

/** Adds items to a list, skipping ones whose ID is already there (the same output loaded twice). */
function mergeList(into: unknown[], add: unknown[], idField: string | undefined): void {
  const seen = new Set(idField ? into.map((x) => (isObj(x) ? x[idField] : undefined)).filter((x) => x !== undefined) : []);
  for (const x of add) {
    const id = idField && isObj(x) ? x[idField] : undefined;
    if (id !== undefined && seen.has(id)) continue;
    if (id !== undefined) seen.add(id);
    into.push(x);
  }
}

/** Whether a value is a Pinhole snapshot, perhaps one written before schemaVersion was required. */
function snapshotLike(v: unknown): v is Obj {
  return isObj(v) && (v.schemaVersion !== undefined || ((isObj(v.ec2) || isObj(v.elbv2)) && !('Vpcs' in v)));
}

// ------------------------------------------------------------------ everything together

/**
 * Reads files into snapshots. Snapshots are returned as they are (after
 * validation); raw AWS CLI output from all inputs is assembled into one
 * snapshot per account and Region.
 */
export function ingest(inputs: IngestInput[]): IngestResult {
  const result: IngestResult = { snapshots: [], notes: [], errors: [] };
  const raw: RawPiece[] = [];
  for (const input of inputs) {
    const name = input.name || 'input';
    try {
      if (input.bytes) {
        const bin = sniffBinary(input.bytes);
        if (bin === 'zip') throw new SnapshotError(`${name} is a ZIP archive: unzip it and load the JSON files inside.`);
        if (bin === 'pdf') throw new SnapshotError(`${name} is a PDF, not a snapshot.`);
        if (bin === 'gzip') throw new SnapshotError(`${name} is gzip-compressed: decompress it first.`);
      }
      const text = input.text ?? decodeBytes(input.bytes ?? new Uint8Array());
      const { values, notes } = parseJsonText(text, name);
      result.notes.push(...notes);
      const flat = values.flatMap((v) => (Array.isArray(v) && v.length && v.every(snapshotLike) ? v : [v]));
      let i = 0;
      for (const v of flat) {
        const label = flat.length > 1 ? `${name} (${++i} of ${flat.length})` : name;
        const removed = scrubSecrets(v);
        if (removed) result.notes.push(`${label}: ${removed === 1 ? 'a secret was' : `${removed} secrets were`} removed (VPN tunnel keys or credentials). They are never needed.`);
        if (snapshotLike(v)) {
          if (v.schemaVersion === undefined) {
            v.schemaVersion = SNAPSHOT_SCHEMA_VERSION;
            result.notes.push(`${label} has no schemaVersion; it was read as version ${SNAPSHOT_SCHEMA_VERSION}.`);
          }
          try {
            assertSnapshot(v);
          } catch (e) {
            throw new SnapshotError(`${label}: ${(e as Error).message}`);
          }
          result.snapshots.push({ snapshot: v as unknown as Snapshot, name: label, sources: [name] });
          continue;
        }
        const piece = rawPiece(v, label, result.notes);
        if (typeof piece === 'string') throw new SnapshotError(`${label} ${piece}. Load the pinhole-snapshot-….json file the collector writes, or AWS CLI describe output saved with --output json.`);
        raw.push(piece);
      }
    } catch (e) {
      result.errors.push(e instanceof SnapshotError ? e.message : `${name}: ${(e as Error).message}`);
    }
  }
  if (raw.length) assemble(raw, result);
  return result;
}

/** Joins raw AWS CLI pieces into one snapshot per account and Region. */
function assemble(raw: RawPiece[], result: IngestResult): void {
  const scopes = new Map<string, { account?: string; region?: string; pieces: RawPiece[] }>();
  const known = raw.filter((p) => p.scope.account || p.scope.region);
  const accounts = new Set(known.map((p) => p.scope.account).filter(Boolean));
  const regions = new Set(known.map((p) => p.scope.region).filter(Boolean));
  for (const p of raw) {
    // A piece without an account or Region (route tables, for instance, carry neither zone nor ARN) joins the only one there is.
    const account = p.scope.account ?? (accounts.size === 1 ? [...accounts][0] : undefined);
    const region = p.scope.region ?? (regions.size === 1 ? [...regions][0] : undefined);
    const k = `${account ?? '?'}/${region ?? '?'}`;
    const s = scopes.get(k) ?? scopes.set(k, { ...(account ? { account } : {}), ...(region ? { region } : {}), pieces: [] }).get(k)!;
    s.pieces.push(p);
  }
  if (scopes.size > 1 && scopes.has('?/?')) {
    const loose = scopes.get('?/?')!;
    result.errors.push(`${loose.pieces.map((p) => p.name).join(', ')}: these files do not say which account or Region they belong to, and the other files cover several. Load each account's and Region's files separately.`);
    scopes.delete('?/?');
  }
  for (const s of scopes.values()) {
    const ec2: Record<string, unknown[]> = {};
    const elbv2: Record<string, unknown[]> = {};
    const fw = { Firewalls: [] as Obj[], FirewallPolicies: {} as Record<string, Obj>, RuleGroups: {} as Record<string, Obj> };
    for (const p of s.pieces) {
      for (const [k, list] of Object.entries(p.ec2)) mergeList((ec2[k] ??= []), list, own(ID_FIELD, k) ? ID_FIELD[k] : undefined);
      for (const [k, list] of Object.entries(p.elbv2)) mergeList((elbv2[k] ??= []), list, own(ID_FIELD, k) ? ID_FIELD[k] : undefined);
      fw.Firewalls.push(...p.firewalls);
      for (const [arn, x] of Object.entries(p.policies)) if (!own(fw.FirewallPolicies, arn)) Object.defineProperty(fw.FirewallPolicies, arn, { value: x, enumerable: true, writable: true, configurable: true });
      for (const [arn, x] of Object.entries(p.ruleGroups)) if (!own(fw.RuleGroups, arn)) Object.defineProperty(fw.RuleGroups, arn, { value: x, enumerable: true, writable: true, configurable: true });
    }
    // Rules inside SecurityGroups (IpPermissions) and SecurityGroupRules describe the same thing: keep the rules API, which has IDs.
    const snapshot: Obj = {
      schemaVersion: SNAPSHOT_SCHEMA_VERSION,
      source: 'aws-cli',
      ...(s.account ? { accountId: s.account } : {}),
      ...(s.region ? { region: s.region } : {}),
      ec2,
      ...(Object.keys(elbv2).length ? { elbv2 } : {}),
      ...(fw.Firewalls.length || Object.keys(fw.FirewallPolicies).length ? { networkFirewall: fw } : {}),
    };
    const names = s.pieces.map((p) => p.name);
    const label = `${s.account ?? 'unknown account'} ${s.region ?? 'unknown Region'} (${names.length === 1 ? names[0] : `${names.length} AWS CLI files`})`;
    try {
      assertSnapshot(snapshot);
    } catch (e) {
      result.errors.push(`${names.join(', ')}: ${(e as Error).message}`);
      continue;
    }
    const missing = ['Vpcs', 'Subnets', 'RouteTables', 'SecurityGroups', 'NetworkAcls', 'NetworkInterfaces'].filter((k) => !ec2[k]?.length && !(k === 'SecurityGroups' && ec2.SecurityGroupRules?.length));
    if (missing.length) result.notes.push(`${label}: no ${missing.join(', ')} loaded, so paths through them cannot be followed. Load the matching describe output too, or use the collector.`);
    if (!s.account) result.notes.push(`${label}: no account ID found in these files.`);
    if (!s.region) result.notes.push(`${label}: no Region found in these files.`);
    result.snapshots.push({ snapshot: snapshot as unknown as Snapshot, name: label, sources: names });
  }
}
