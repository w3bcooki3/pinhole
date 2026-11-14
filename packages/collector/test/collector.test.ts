import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, chmodSync, symlinkSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeExposure, normalize } from '@pinhole/engine';
import type { Snapshot } from '@pinhole/engine';
import { collectSnapshot, READ_ONLY_OPERATION } from '../src/collect.js';
import type { Send } from '../src/collect.js';
import { COLLECTOR_OPERATIONS } from '../src/sdk.js';
// @ts-expect-error plain JS test helper
import { respond, AccessDenied } from './fake-aws.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '../../..');
const fixture = (name: string) => JSON.parse(readFileSync(join(repo, 'fixtures', name, 'snapshot.json'), 'utf8')) as Snapshot;

function fakeSend(snap: Snapshot, fail: string[] = []): { send: Send; calls: string[] } {
  const calls: string[] = [];
  const send: Send = async (service, op, input) => {
    calls.push(`${service}:${op}`);
    if (fail.includes(op)) throw new AccessDenied(op);
    return respond(snap, service, op, input, 1);
  };
  return { send, calls };
}

const findingKeys = (s: unknown) =>
  analyzeExposure(normalize(s))
    .findings.map((f) => `${f.resourceId} ${f.protocol}/${f.ports.from}-${f.ports.to} ${f.returnPath} ${(f.targets ?? []).map((t) => `${t.targetId}:${t.verdict}`).join(',')}`)
    .sort();

describe('collectSnapshot', () => {
  for (const name of ['04-blackhole-routes', '07-alb-private-targets', '08-nlb-client-ip-preservation']) {
    it(`reproduces fixture ${name} through paginated API calls`, async () => {
      const original = fixture(name);
      const { send, calls } = fakeSend(original);
      const snap = await collectSnapshot(send, { region: 'us-east-1' });
      expect(snap.errors).toBeUndefined();
      expect(snap.accountId).toBe('111122223333');
      expect(snap.source).toBe('aws-sdk');
      expect(findingKeys(snap)).toEqual(findingKeys(original));
      expect(calls.every((c) => READ_ONLY_OPERATION.test(c.split(':')[1]!))).toBe(true);
      // The normalised models agree on the things paths depend on.
      const a = normalize(snap);
      const b = normalize(original);
      expect([...a.enis.keys()].sort()).toEqual([...b.enis.keys()].sort());
      expect([...a.tgwRouteTables.values()].map((t) => t.routes.length)).toEqual([...b.tgwRouteTables.values()].map((t) => t.routes.length));
    });
  }

  it('leaves out a transit gateway route table with more routes than one call returns', async () => {
    const snap = fixture('04-blackhole-routes');
    const [rtb, routes] = Object.entries(snap.ec2!.TransitGatewayRoutes!)[0]!;
    const many = Array.from({ length: 1001 }, (_, i) => ({ ...(routes as object[])[0], DestinationCidrBlock: `10.${i >> 8}.${i & 255}.0/24` }));
    snap.ec2!.TransitGatewayRoutes![rtb] = many as never;
    const { send } = fakeSend(snap);
    const out = await collectSnapshot(send, { region: 'us-east-1' });
    expect(out.ec2?.TransitGatewayRoutes?.[rtb]).toBeUndefined();
    expect(out.errors).toEqual([{ api: 'ec2:SearchTransitGatewayRoutes', message: expect.stringContaining('more than 1000 routes') }]);
    expect(analyzeExposure(normalize(out)).warnings.some((w) => w.code === 'tgw-routes-missing')).toBe(true);
  });

  it('records a failed API call and keeps going', async () => {
    const { send } = fakeSend(fixture('07-alb-private-targets'), ['DescribeNetworkAcls']);
    const snap = await collectSnapshot(send, { region: 'us-east-1' });
    expect(snap.errors).toEqual([{ api: 'ec2:DescribeNetworkAcls', message: expect.stringContaining('not authorized') }]);
    expect(snap.ec2?.NetworkAcls).toBeUndefined();
    expect(snap.ec2?.SecurityGroups?.length).toBeGreaterThan(0);
    const model = normalize(snap);
    expect(model.warnings.some((w) => w.code === 'collection-error')).toBe(true);
  });

  it('refuses operations that are not read-only', async () => {
    const send: Send = async () => ({});
    // Only Describe/Get/Search names pass the guard.
    expect(READ_ONLY_OPERATION.test('DescribeVpcs')).toBe(true);
    expect(READ_ONLY_OPERATION.test('SearchTransitGatewayRoutes')).toBe(true);
    expect(READ_ONLY_OPERATION.test('CreateVpc')).toBe(false);
    expect(READ_ONLY_OPERATION.test('AuthorizeSecurityGroupIngress')).toBe(false);
    expect(READ_ONLY_OPERATION.test('Describe')).toBe(false);
    await expect(collectSnapshot(send, { region: 'us-east-1' })).resolves.toBeDefined();
  });
});

describe('IAM policy', () => {
  const policy = JSON.parse(readFileSync(join(repo, 'docs/iam-policy.json'), 'utf8'));
  const actions: string[] = policy.Statement.flatMap((s: { Action: string[] }) => s.Action);
  const prefix = { ec2: 'ec2', elbv2: 'elasticloadbalancing', sts: 'sts' } as const;

  it('grants every operation the collector can call (sts:GetCallerIdentity needs no permission)', () => {
    for (const { service, operation } of COLLECTOR_OPERATIONS) {
      if (service === 'sts') continue;
      expect(actions, `${service}:${operation}`).toContain(`${prefix[service]}:${operation}`);
    }
  });

  it('grants nothing else, and nothing that is not read-only', () => {
    const expected = COLLECTOR_OPERATIONS.filter((o) => o.service !== 'sts').map((o) => `${prefix[o.service]}:${o.operation}`);
    expect([...actions].sort()).toEqual([...expected].sort());
    for (const a of actions) expect(a.split(':')[1]).toMatch(READ_ONLY_OPERATION);
  });
});

describe('scripts/cloudshell-collect.sh', () => {
  const hasJq = (() => {
    try {
      execFileSync('jq', ['--version']);
      return true;
    } catch {
      return false;
    }
  })();

  function runScript(name: string, fail = '') {
    const bin = mkdtempSync(join(tmpdir(), 'pinhole-fakeaws-'));
    const aws = join(bin, 'aws');
    if (!existsSync(aws)) symlinkSync(join(here, 'fake-aws.mjs'), aws);
    chmodSync(join(here, 'fake-aws.mjs'), 0o755);
    const out = join(bin, 'snapshot.json');
    const log = join(bin, 'calls.log');
    writeFileSync(log, '');
    execFileSync('bash', [join(repo, 'scripts/cloudshell-collect.sh'), 'us-east-1', out], {
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_AWS_SNAPSHOT: join(repo, 'fixtures', name, 'snapshot.json'), FAKE_AWS_FAIL: fail, FAKE_AWS_LOG: log },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    return { snap: JSON.parse(readFileSync(out, 'utf8')) as Snapshot, calls: readFileSync(log, 'utf8').trim().split('\n') };
  }

  for (const name of ['04-blackhole-routes', '07-alb-private-targets', '08-nlb-client-ip-preservation']) {
    it.skipIf(!hasJq)(`builds an equivalent snapshot for ${name}`, () => {
      const { snap, calls } = runScript(name);
      expect(snap.source).toBe('aws-cli');
      expect(snap.region).toBe('us-east-1');
      expect(findingKeys(snap)).toEqual(findingKeys(fixture(name)));
      for (const c of calls) expect(c.split(':')[1]).toMatch(READ_ONLY_OPERATION);
    });
  }

  it.skipIf(!hasJq)('writes the snapshot readable only by its owner', () => {
    const bin = mkdtempSync(join(tmpdir(), 'pinhole-mode-'));
    symlinkSync(join(here, 'fake-aws.mjs'), join(bin, 'aws'));
    const out = join(bin, 'snap.json');
    execFileSync('bash', [join(repo, 'scripts/cloudshell-collect.sh'), 'us-east-1', out], {
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_AWS_SNAPSHOT: join(repo, 'fixtures/07-alb-private-targets/snapshot.json'), FAKE_AWS_FAIL: '', FAKE_AWS_LOG: join(bin, 'log') },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    expect(statSync(out).mode & 0o777).toBe(0o600);
  });

  it.skipIf(!hasJq)('rejects a region that is not a region name', () => {
    const bin = mkdtempSync(join(tmpdir(), 'pinhole-region-'));
    symlinkSync(join(here, 'fake-aws.mjs'), join(bin, 'aws'));
    expect(() =>
      execFileSync('bash', [join(repo, 'scripts/cloudshell-collect.sh'), '../../tmp/x'], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, stdio: ['ignore', 'ignore', 'pipe'] }),
    ).toThrow(/not a region name/);
  });

  it.skipIf(!hasJq)('records failures in "errors" and still writes a snapshot', () => {
    const { snap } = runScript('07-alb-private-targets', 'DescribeNetworkAcls');
    expect(snap.errors?.[0]?.api).toBe('ec2:describe-network-acls');
    expect(snap.ec2?.NetworkAcls).toEqual([]);
  });
});
