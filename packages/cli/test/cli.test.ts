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

  it('writes SARIF 2.1.0 for code scanning, with stable fingerprints and severities', async () => {
    const f9 = fx('09-lateral-movement');
    const r = await cli('exposure', f9, '--format', 'sarif');
    expect(r.code).toBe(0);
    const sarif = JSON.parse(r.stdout);
    expect(sarif.version).toBe('2.1.0');
    const run0 = sarif.runs[0];
    expect(run0.tool.driver.name).toBe('Pinhole');
    expect(run0.tool.driver.rules.map((x: { id: string }) => x.id)).toContain('pinhole/admin');
    const ssh = run0.results.find((x: { ruleId: string }) => x.ruleId === 'pinhole/admin');
    expect(ssh.level).toBe('error');
    expect(ssh.properties['security-severity']).toBe('9.5');
    expect(ssh.message.text).toBe('Anyone on the internet can open SSH (tcp/22) on bastion (i-bastion, eni-bastion) at 52.0.0.10. Allowed by acl-default #100, sgr-bastion-ssh-world.');
    expect(ssh.locations[0].logicalLocations[0].fullyQualifiedName).toBe('111122223333/us-east-1/vpc-1/eni-bastion');
    // Every result points at a rule that exists, by index too.
    for (const x of run0.results) expect(run0.tool.driver.rules[x.ruleIndex].id).toBe(x.ruleId);
    const again = JSON.parse((await cli('exposure', f9, '--format', 'sarif')).stdout);
    expect(again.runs[0].results[0].partialFingerprints).toEqual(run0.results[0].partialFingerprints);
    const high = JSON.parse((await cli('exposure', f9, '--format', 'sarif', '--min-severity', 'high')).stdout);
    expect(high.runs[0].results).toHaveLength(1);
  });

  it('writes a Markdown table', async () => {
    const r = await cli('exposure', fx('09-lateral-movement'), '--format', 'markdown');
    expect(r.stdout).toMatch(/\*\*2 services reachable from the internet:\*\* 1 critical, 0 high, 0 medium, 1 low\./);
    expect(r.stdout).toMatch(/\| critical \| bastion \(i-bastion, eni-bastion\) \| tcp\/22 SSH \| any address \| acl-default #100, sgr-bastion-ssh-world \|/);
  });

  it('checks collect regions before calling AWS', async () => {
    const bad = await cli('collect', '--region', 'us-east-1,us east 1');
    expect(bad.code).toBe(1);
    expect(bad.stderr).toMatch(/"us east 1" is not a region name/);
    const two = await cli('collect', '--region', 'us-east-1,eu-west-1', '--out', 'x.json');
    expect(two.code).toBe(1);
    expect(two.stderr).toMatch(/with several regions use --out-dir/);
  });

  describe('plan', () => {
    const f9 = fx('09-lateral-movement');
    const tf = join(here, '../../../fixtures/plans/09-plan.json');

    it('shows what a Terraform plan would open and close, and what it could not check', async () => {
      const r = await cli('plan', f9, tf);
      expect(r.code).toBe(0);
      expect(r.stdout).toMatch(/Analysed: 4 changes from 3 resources\./);
      expect(r.stdout).toMatch(/aws_vpc_security_group_ingress_rule\.web_8443 \(create\)\n    Add inbound rule to sg-web \(web\): tcp 8443 from 0\.0\.0\.0\/0/);
      expect(r.stdout).toMatch(/\[HIGH\] NEW web .* tcp\/8443 from 0\.0\.0\.0\/0/);
      expect(r.stdout).toMatch(/narrower bastion .* tcp\/22: now 203\.0\.113\.0\/24 \(was 0\.0\.0\.0\/0\)/);
      expect(r.stdout).toMatch(/closed web .* tcp\/443/);
      expect(r.stdout).toMatch(/Not analysed: 2\. Check these yourself\./);
      expect(r.stdout).toMatch(/This plan opens 1 new or wider internet exposure and 0 new attack chains\./);
    });

    it('fails a pipeline at a level, and writes Markdown and JSON', async () => {
      expect((await cli('plan', f9, tf, '--fail-on', 'high')).code).toBe(2);
      expect((await cli('plan', f9, tf, '--fail-on', 'critical')).code).toBe(0);
      const md = (await cli('plan', f9, tf, '--format', 'markdown')).stdout;
      expect(md).toMatch(/\*\*This plan opens 1 new or wider internet exposure and 0 new attack chains\.\*\*/);
      expect(md).toMatch(/2 resource changes not analysed/);
      const j = JSON.parse((await cli('plan', f9, tf, '--format', 'json')).stdout);
      expect(j.mapping.changes).toHaveLength(4);
      expect(j.exposure.opened).toBe(1);
    });

    it('explains a file that is not plan JSON', async () => {
      const r = await cli('plan', f9, f9);
      expect(r.code).toBe(1);
      expect(r.stderr).toMatch(/no "resource_changes"/);
    });
  });

  describe('diff', () => {
    const f9 = fx('09-lateral-movement');
    const changed = () => {
      const s = JSON.parse(readFileSync(f9, 'utf8'));
      s.ec2.SecurityGroupRules = s.ec2.SecurityGroupRules.filter((r: { SecurityGroupRuleId: string }) => r.SecurityGroupRuleId !== 'sgr-bastion-ssh-world');
      s.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: 'sgr-web-8443', GroupId: 'sg-web', IsEgress: false, IpProtocol: 'tcp', FromPort: 8443, ToPort: 8443, CidrIpv4: '0.0.0.0/0', Description: 'a | b <script>' });
      const file = join(mkdtempSync(join(tmpdir(), 'pinhole-diff-')), 'after.json');
      writeFileSync(file, JSON.stringify(s));
      return file;
    };

    it('lists new and closed exposure, closed chains and the rule changes', async () => {
      const r = await cli('diff', f9, changed());
      expect(r.code).toBe(0);
      expect(r.stdout).toMatch(/\[HIGH\] NEW web \(i-web, eni-web\) tcp\/8443 from 0\.0\.0\.0\/0/);
      expect(r.stdout).toMatch(/\[CRITICAL\] closed bastion .* tcp\/22/);
      expect(r.stdout).toMatch(/Attack chains: 0 new, 3 closed\./);
      expect(r.stdout).toMatch(/added +security group rule sgr-web-8443 in sg-web \(web\): tcp\/8443 from 0\.0\.0\.0\/0/);
      expect(r.stdout).toMatch(/removed security group rule sgr-bastion-ssh-world/);
    });

    it('fails a pipeline on new exposure at or above a level', async () => {
      expect((await cli('diff', f9, changed(), '--fail-on', 'high')).code).toBe(2);
      expect((await cli('diff', f9, changed(), '--fail-on', 'critical')).code).toBe(0);
      expect((await cli('diff', f9, f9, '--fail-on', 'low')).code).toBe(0);
    });

    it('says so when nothing changed', async () => {
      expect((await cli('diff', f9, f9)).stdout).toMatch(/No changes\./);
    });

    it('writes Markdown with table cells escaped, and JSON', async () => {
      const md = (await cli('diff', f9, changed(), '--format', 'markdown')).stdout;
      expect(md).toMatch(/\*\*1 new or wider internet exposure and 0 new attack chains\.\*\*/);
      expect(md).toMatch(/\| high \| opened \| web \(i-web, eni-web\) \| tcp\/8443 \| 0\.0\.0\.0\/0 \| nobody \|/);
      expect(md).toMatch(/bastion → app → orders-db/);
      const j = JSON.parse((await cli('diff', f9, changed(), '--format', 'json')).stdout);
      expect(j.exposure.opened).toBe(1);
      expect(j.config).toHaveLength(2);
    });

    it('refuses snapshots of different regions, and wrong arguments', async () => {
      const s = JSON.parse(readFileSync(f9, 'utf8'));
      s.region = 'eu-west-1';
      const file = join(mkdtempSync(join(tmpdir(), 'pinhole-diff-')), 'eu.json');
      writeFileSync(file, JSON.stringify(s));
      const r = await cli('diff', f9, file);
      expect(r.code).toBe(1);
      expect(r.stderr).toMatch(/different regions/);
      expect((await cli('diff', f9)).code).toBe(1);
      expect((await cli('diff', f9, f9, '--format', 'xml')).code).toBe(1);
    });
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
