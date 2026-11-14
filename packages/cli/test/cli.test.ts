import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { run, VERSION } from '../src/index.js';
import { safeForTerminal } from '../src/cli.js';

const here = dirname(fileURLToPath(import.meta.url));
const fx = (name: string) => join(here, '../../../fixtures', name, 'snapshot.json');

async function cli(...argv: string[]) {
  let stdout = '';
  let stderr = '';
  const code = await run(argv, { stdout: (s) => (stdout += s), stderr: (s) => (stderr += s) });
  return { code, stdout, stderr };
}

describe('pinhole CLI', () => {
  it('reports its version, matching package.json', async () => {
    const pkg = JSON.parse(readFileSync(join(here, '../package.json'), 'utf8'));
    expect(VERSION).toBe(pkg.version);
    expect((await cli('--version')).stdout.trim()).toBe(VERSION);
  });

  it('prints usage and fails without a command', async () => {
    const r = await cli();
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/Usage:/);
  });

  it('rejects unknown commands and flags', async () => {
    expect((await cli('frobnicate')).code).toBe(1);
    expect((await cli('exposure', fx('06-public-ip-without-igw-route'), '--nope')).code).toBe(1);
    expect((await cli('exposure', fx('06-public-ip-without-igw-route'), '--fail-on', 'severe')).code).toBe(1);
  });

  it('explains a bad snapshot file', async () => {
    const r = await cli('exposure', join(here, '../package.json'));
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/schemaVersion/);
    expect((await cli('exposure', '/no/such/file.json')).stderr).toMatch(/Cannot read/);
  });

  it('prints a text report with the rule IDs on the path', async () => {
    const r = await cli('exposure', fx('06-public-ip-without-igw-route'));
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/\[CRITICAL\] tcp\/22 \(SSH \(22\)\)/);
    expect(r.stdout).toMatch(/i-public \(eni-public\)/);
    expect(r.stdout).toMatch(/sgr-ssh-world/);
    expect(r.stdout).toMatch(/acl-default inbound rule 100 allows tcp\/22/);
    expect(r.stdout).toMatch(/rtb-public: 0\.0\.0\.0\/0 -> igw-1/);
    expect(r.stdout).not.toMatch(/eni-private-eip/);
  });

  it('does not pass terminal escape sequences from snapshot text through', async () => {
    const snap = JSON.parse(readFileSync(fx('06-public-ip-without-igw-route'), 'utf8'));
    snap.ec2.Instances = [{ InstanceId: 'i-public', Tags: [{ Key: 'Name', Value: 'web\u001b[2J\u001b]0;owned\u0007' }], NetworkInterfaces: [{ NetworkInterfaceId: 'eni-public', Attachment: { DeviceIndex: 0 } }] }];
    const file = join(mkdtempSync(join(tmpdir(), 'pinhole-cli-')), 'snap.json');
    writeFileSync(file, JSON.stringify(snap));
    const r = await cli('exposure', file);
    // Control characters in free text are replaced when the snapshot is read.
    expect(r.stdout).toMatch(/web\ufffd\[2J/);
    // eslint-disable-next-line no-control-regex
    expect(r.stdout + r.stderr).not.toMatch(/[\u001b\u0007]/);
    // The output filter still applies to anything that gets through another way.
    expect(safeForTerminal('web\u001b[2J')).toBe('web\ufffd[2J');
  });

  it('shows load balancer targets in the text report', async () => {
    const r = await cli('exposure', fx('07-alb-private-targets'));
    expect(r.stdout).toMatch(/target i-app1 \(10\.0\.10\.11\) port 8080: reachable \(2\/2 load balancer nodes\)/);
    expect(r.stdout).toMatch(/target i-app2 \(10\.0\.10\.12\) port 8080: blocked/);
  });

  it('emits JSON with a severity summary', async () => {
    const r = await cli('exposure', fx('01-nacl-ephemeral-return'), '--format', 'json');
    const j = JSON.parse(r.stdout);
    expect(j.tool.version).toBe(VERSION);
    expect(j.summary.low).toBe(2);
    expect(j.findings.map((f: { resourceId: string }) => f.resourceId).sort()).toEqual(['eni-full', 'eni-linux']);
  });

  it('filters by --min-severity', async () => {
    const r = await cli('exposure', fx('01-nacl-ephemeral-return'), '--format', 'json', '--min-severity', 'high');
    expect(JSON.parse(r.stdout).findings).toEqual([]);
  });

  it('exits 2 when --fail-on is reached, 0 otherwise', async () => {
    expect((await cli('exposure', fx('06-public-ip-without-igw-route'), '--fail-on', 'critical')).code).toBe(2);
    expect((await cli('exposure', fx('01-nacl-ephemeral-return'), '--fail-on', 'high')).code).toBe(0);
  });

  it('validates a snapshot', async () => {
    const r = await cli('validate', fx('04-blackhole-routes'));
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/2 VPCs, 5 subnets/);
  });

  describe('0.2 analysis commands', () => {
    const f9 = fx('09-lateral-movement');
    it('can: lists services between two resources, by name or ID', async () => {
      const r = await cli('can', f9, '--from', 'bastion', '--to', 'i-db');
      expect(r.code).toBe(0);
      expect(r.stdout).toContain('[CRITICAL] tcp/22  (SSH; gives a foothold)');
      const blocked = await cli('can', f9, '--from', 'eni-bastion', '--to', 'eni-cache', '--port', '6379');
      expect(blocked.stdout).toMatch(/blocked at dest-nacl-ingress/);
      expect((await cli('can', f9, '--from', 'nobody', '--to', 'web')).stderr).toMatch(/not an interface ID/);
    });
    it('blast: ranks chains and fails the build on request', async () => {
      const r = await cli('blast', f9, '--fail-on', 'critical');
      expect(r.code).toBe(2);
      expect(r.stdout.split('\n').find((l) => l.startsWith('[')) ?? '').toMatch(/^\[CRITICAL\] internet --> bastion .*--> app .*--> (orders-db|session-cache)/);
      const j = JSON.parse((await cli('blast', f9, '--format', 'json')).stdout);
      expect(j.entries.map((e: { eniId: string }) => e.eniId).sort()).toEqual(['eni-bastion', 'eni-web']);
    });
    it('fix: prints the verified fix as an AWS CLI command', async () => {
      const r = await cli('fix', f9);
      expect(r.stdout).toContain('Verified: Remove sgr-bastion-ssh-world');
      expect(r.stdout).toContain('$ aws ec2 revoke-security-group-ingress --region us-east-1 --group-id sg-bastion --security-group-rule-ids sgr-bastion-ssh-world');
      const all = await cli('fix', f9, '--all');
      expect(all.stdout).toContain('Verified: Allow tcp/22 on sgr-bastion-ssh-world only from inside vpc-1');
      expect(all.stdout).toContain('Still reachable after a compromise of: web');
      expect(all.stdout).toContain(`$ aws ec2 modify-security-group-rules --region us-east-1 --group-id sg-bastion --security-group-rules '[{"SecurityGroupRuleId":"sgr-bastion-ssh-world","SecurityGroupRule":{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"CidrIpv4":"10.0.0.0/16","Description":"SSH from anywhere"}}]'`);
    });
    it('fix --plan: an ordered plan that closes everything critical and high', async () => {
      const r = await cli('fix', f9, '--plan');
      expect(r.stdout).toMatch(/^Fix plan: 2 change\(s\) close 1 of 1 critical and high exposures and 5 of 5 attack chains\./);
      expect(r.stdout).toMatch(/1\. Remove sgr-bastion-ssh-world/);
      expect(r.stdout).toMatch(/2\. Remove sgr-db-ssh-vpc/);
    });
    it('hygiene: lists findings and exits 2 with --fail-on', async () => {
      const r = await cli('hygiene', f9, '--fail-on', 'medium');
      expect(r.code).toBe(2);
      expect(r.stdout).toMatch(/acl-data inbound rule 120 can never match/);
    });
    it('whatif: diffs exposure and attack chains', async () => {
      const r = await cli('whatif', f9, '--revoke', 'sgr-db-ssh-vpc', '--remove-nacl', 'acl-data#ingress#120');
      expect(r.code).toBe(0);
      expect(r.stdout).toMatch(/Internet exposure: no change\./);
      expect(r.stdout).toMatch(/Attack chains: 1 closed, 0 opened\./);
      expect((await cli('whatif', f9, '--revoke', 'sgr-nope')).stderr).toMatch(/sgr-nope is not in the snapshot/);
      expect((await cli('whatif', f9)).stderr).toMatch(/at least one change/);
    });
  });
});
