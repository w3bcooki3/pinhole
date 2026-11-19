import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeExposure, applyChanges, ChangeError, cliFor, describeChange, diffExposure, normalize, reachServices, serviceLabel } from '../src/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const model = () => normalize(JSON.parse(readFileSync(join(root, 'fixtures/09-lateral-movement/snapshot.json'), 'utf8')));

describe('applyChanges', () => {
  it('leaves the original model untouched', () => {
    const m = model();
    const before = JSON.stringify([...m.securityGroups.values()]);
    applyChanges(m, [{ kind: 'revoke-sg-rule', ruleId: 'sgr-bastion-ssh-world' }, { kind: 'remove-nacl-entry', naclId: 'acl-data', egress: false, ruleNumber: 120 }]);
    expect(JSON.stringify([...m.securityGroups.values()])).toBe(before);
    expect(m.nacls.get('acl-data')!.entries.some((e) => e.ruleNumber === 120 && !e.egress)).toBe(true);
  });

  it('rejects changes that do not fit the snapshot', () => {
    const m = model();
    expect(() => applyChanges(m, [{ kind: 'revoke-sg-rule', ruleId: 'sgr-nope' }])).toThrow(ChangeError);
    expect(() => applyChanges(m, [{ kind: 'add-nacl-entry', naclId: 'acl-data', egress: false, ruleNumber: 100, action: 'deny', protocol: 'tcp', cidr: '0.0.0.0/0', fromPort: 22 }])).toThrow(/already has inbound rule 100/);
    expect(() => applyChanges(m, [{ kind: 'edit-sg-rule', ruleId: 'sgr-web-https', fromPort: 500, toPort: 400 }])).toThrow(/empty/);
  });

  it('an added rule opens a path, and the diff says so', () => {
    const m = model();
    const after = applyChanges(m, [{ kind: 'add-sg-rule', groupId: 'sg-web', egress: false, protocol: 'tcp', fromPort: 3389, cidr: '0.0.0.0/0' }]);
    const d = diffExposure(analyzeExposure(m), analyzeExposure(after));
    expect(d.deltas).toEqual([expect.objectContaining({ status: 'opened', resourceId: 'eni-web', protocol: 'tcp', ports: { from: 3389, to: 3389 }, severity: 'critical' })]);
  });

  it('a NACL deny ahead of the allow blocks lateral traffic too', () => {
    const m = model();
    const after = applyChanges(m, [{ kind: 'add-nacl-entry', naclId: 'acl-data', egress: false, ruleNumber: 105, action: 'deny', protocol: 'tcp', cidr: '10.0.0.0/16', fromPort: 22, toPort: 22 }]);
    expect(reachServices(m, 'eni-bastion', 'eni-db').services.map(serviceLabel)).toEqual(['tcp/22']);
    expect(reachServices(after, 'eni-bastion', 'eni-db').services).toEqual([]);
  });
});

describe('AWS CLI output', () => {
  const m = model();
  it('revokes by rule ID, in the snapshot region', () => {
    expect(cliFor(m, { kind: 'revoke-sg-rule', ruleId: 'sgr-db-ssh-vpc' })).toEqual(['aws ec2 revoke-security-group-ingress --region us-east-1 --group-id sg-db --security-group-rule-ids sgr-db-ssh-vpc']);
  });
  it('modifies a rule in place, keeping its description', () => {
    expect(cliFor(m, { kind: 'edit-sg-rule', ruleId: 'sgr-db-ssh-vpc', cidr: '10.0.1.10/32' })).toEqual([
      `aws ec2 modify-security-group-rules --region us-east-1 --group-id sg-db --security-group-rules '[{"SecurityGroupRuleId":"sgr-db-ssh-vpc","SecurityGroupRule":{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"CidrIpv4":"10.0.1.10/32","Description":"SSH from the whole VPC"}}]'`,
    ]);
  });
  it('a hostile rule description cannot change what the command sets or break out of the shell quoting', () => {
    const m2 = model();
    const rule = [...m2.securityGroups.values()].flatMap((g) => g.ingress).find((r) => r.id === 'sgr-db-ssh-vpc')!;
    (rule as { description?: string }).description = "x},SecurityGroupRule={CidrIpv4=0.0.0.0/0}' ; rm -rf ~ ; echo '";
    const cmd = cliFor(m2, { kind: 'edit-sg-rule', ruleId: 'sgr-db-ssh-vpc', cidr: '10.0.1.10/32' })[0]!;
    const arg = cmd.slice(cmd.indexOf('--security-group-rules ') + 23);
    // Undo POSIX single quoting exactly as a shell would.
    expect(arg.startsWith("'") && arg.endsWith("'")).toBe(true);
    const parsed = JSON.parse(arg.slice(1, -1).replaceAll("'\\''", "'"));
    expect(parsed[0].SecurityGroupRule.CidrIpv4).toBe('10.0.1.10/32');
    expect(parsed[0].SecurityGroupRule.Description).toBe(rule.description);
  });
  it('keeps comment lines on one line', () => {
    const m2 = model();
    const lines = cliFor(m2, { kind: 'remove-public-ip', eniId: 'eni-x', publicIp: '1.2.3.4\nrm -rf ~' });
    expect(lines.every((l) => l.startsWith('#') || l.startsWith('aws '))).toBe(true);
    expect(lines.join('\n').split('\n').every((l) => l.startsWith('#') || l.startsWith('aws '))).toBe(true);
  });
  it('creates and deletes NACL entries', () => {
    expect(cliFor(m, { kind: 'add-nacl-entry', naclId: 'acl-data', egress: false, ruleNumber: 90, action: 'deny', protocol: 'tcp', cidr: '0.0.0.0/0', fromPort: 22, toPort: 22 })).toEqual([
      'aws ec2 create-network-acl-entry --region us-east-1 --network-acl-id acl-data --ingress --rule-number 90 --protocol 6 --port-range From=22,To=22 --cidr-block 0.0.0.0/0 --rule-action deny',
    ]);
    expect(cliFor(m, { kind: 'remove-nacl-entry', naclId: 'acl-data', egress: false, ruleNumber: 120 })).toEqual(['aws ec2 delete-network-acl-entry --region us-east-1 --network-acl-id acl-data --ingress --rule-number 120']);
  });
  it('describes changes in words', () => {
    expect(describeChange(m, { kind: 'revoke-sg-rule', ruleId: 'sgr-db-ssh-vpc' })).toBe('Remove inbound rule sgr-db-ssh-vpc (tcp/22 from 10.0.0.0/16) from sg-db (db)');
  });
});

describe('chokepoints', () => {
  it('ranks rules by the attack chains their removal cuts, proven by re-analysis', async () => {
    const { analyzeBlastRadius, findChokepoints } = await import('../src/index.js');
    const m = model();
    const ex = analyzeExposure(m);
    const b = analyzeBlastRadius(m, ex);
    const cps = findChokepoints(m, ex, b);
    expect(cps[0]!.ruleId).toBe('sgr-bastion-ssh-world');
    expect(cps[0]!.chainsClosed.length).toBe(3);
    expect(b.chains.length).toBe(5);
    // The partner rule still exposes 443, so removing the main HTTPS rule cuts no chain.
    const https = cps.find((c) => c.ruleId === 'sgr-web-https')!;
    expect(https.chainsClosed).toEqual([]);
    expect(https.exposureClosed.map((d) => d.status)).toEqual(['narrowed']);
  });
});

describe('fix plan', () => {
  it('closes every critical and high exposure and chain in fixture 09 with two verified changes', async () => {
    const { analyzeBlastRadius, planFixes } = await import('../src/index.js');
    const m = model();
    const ex = analyzeExposure(m);
    const p = planFixes(m, ex, analyzeBlastRadius(m, ex));
    expect(p.before).toEqual({ exposures: 1, chains: 5 });
    expect(p.after).toEqual({ exposures: 0, chains: 0 });
    expect(p.steps.map((s) => s.changes)).toEqual([[{ kind: 'revoke-sg-rule', ruleId: 'sgr-bastion-ssh-world' }], [{ kind: 'revoke-sg-rule', ruleId: 'sgr-db-ssh-vpc' }]]);
    expect(p.steps.every((s) => s.collateral.length === 0)).toBe(true);
  });
});

describe('IPv6 changes', () => {
  const m10 = () => normalize(JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures/10-ipv6-exposure/snapshot.json'), 'utf8')));

  it('applies IPv6 rules, ACL entries and routes to the IPv6 side of the model', () => {
    const after = applyChanges(m10(), [
      { kind: 'add-sg-rule', groupId: 'sg-dual', egress: false, protocol: 'tcp', fromPort: 25, toPort: 25, cidr: '2001:DB8::1/32' },
      { kind: 'add-nacl-entry', naclId: 'acl-dual', egress: false, ruleNumber: 140, action: 'deny', protocol: 'tcp', cidr: '::/0', fromPort: 25, toPort: 25 },
      { kind: 'add-route', routeTableId: 'rtb-dual', destination: '2001:db8:1::/48', targetId: 'eigw-1' },
    ]);
    expect(after.securityGroups.get('sg-dual')!.ingress.at(-1)).toMatchObject({ ipv6CidrText: '2001:db8::/32' });
    expect(after.securityGroups.get('sg-dual')!.ingress.at(-1)!.cidr).toBeUndefined();
    expect(after.nacls.get('acl-dual')!.entries.find((e) => e.ruleNumber === 140)).toMatchObject({ ipv6CidrText: '::/0', action: 'deny' });
    expect(after.routeTables.get('rtb-dual')!.routes6!.at(-1)).toMatchObject({ destination: '2001:db8:1::/48', target: { type: 'eigw', id: 'eigw-1' } });
    expect(() => applyChanges(m10(), [{ kind: 'remove-route', routeTableId: 'rtb-dual', destination: '2001:db8:9::/48' }])).toThrow(ChangeError);
  });

  it('prints the IPv6 form of each AWS CLI command', () => {
    const m = m10();
    expect(cliFor(m, { kind: 'add-sg-rule', groupId: 'sg-dual', egress: false, protocol: 'tcp', fromPort: 22, toPort: 22, cidr: '::/0' })[0]).toContain('"Ipv6Ranges":[{"CidrIpv6":"::/0"}]');
    expect(cliFor(m, { kind: 'edit-sg-rule', ruleId: 'sgr-https-v6', cidr: '2001:db8::/32' })[0]).toContain('"CidrIpv6":"2001:db8::/32"');
    expect(cliFor(m, { kind: 'add-nacl-entry', naclId: 'acl-dual', egress: false, ruleNumber: 99, action: 'deny', protocol: 'tcp', cidr: '::/0', fromPort: 22, toPort: 22 })[0]).toContain('--ipv6-cidr-block ::/0');
    expect(cliFor(m, { kind: 'remove-route', routeTableId: 'rtb-dual', destination: '::/0' })[0]).toContain('--destination-ipv6-cidr-block ::/0');
  });
});

describe('commands built from free text cannot run anything', () => {
  it('quotes descriptions and names so bash passes them to aws as one literal argument', async () => {
    const { execFileSync } = await import('node:child_process');
    const { existsSync, mkdtempSync, readFileSync: read } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join: j } = await import('node:path');
    const E = await import('../src/index.js');
    const dir = mkdtempSync(j(tmpdir(), 'pinhole-sh-'));
    const m = E.normalize(JSON.parse(read(j(__dirname, '../../../fixtures/07-alb-private-targets/snapshot.json'), 'utf8')));
    const g = [...m.securityGroups.values()][0]!;
    const nasty = [`x'; touch ${dir}/p1; echo '`, `$(touch ${dir}/p2)`, `\`touch ${dir}/p3\``, 'a"b}c,d', `x\\$(touch ${dir}/p4)`];
    const cmds: string[] = [];
    for (const d of nasty) {
      cmds.push(...E.cliFor(m, { kind: 'add-sg-rule', groupId: g.id, egress: false, protocol: 'tcp', fromPort: 22, toPort: 22, cidr: '10.0.0.0/8', description: d }));
      cmds.push(...E.cliFor(m, { kind: 'create-sg', groupId: 'sg-new1', vpcId: g.vpcId, name: d }));
    }
    const out = execFileSync('bash', ['-c', `aws(){ printf 'ARG<%s>\\n' "$@"; }\n${cmds.join('\n')}`], { encoding: 'utf8' });
    for (const p of ['p1', 'p2', 'p3', 'p4']) expect(existsSync(j(dir, p)), p).toBe(false);
    // Each hostile description reached aws as data (a new group's name goes in a comment line, which bash never runs;
    // names cannot hold a newline to leave it).
    expect(out.match(/touch /g)?.length).toBe(4);
    expect(out).toContain('a\\"b}c,d');
  });
});
