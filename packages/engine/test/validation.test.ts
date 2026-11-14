import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { assertChanges, assertSnapshot, SnapshotError } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const load = (name: string) => JSON.parse(readFileSync(join(here, '../../../fixtures', name, 'snapshot.json'), 'utf8'));
const refuse = (mutate: (s: any) => void, message: RegExp) => {
  const s = load('09-lateral-movement');
  mutate(s);
  expect(() => assertSnapshot(s)).toThrow(SnapshotError);
  expect(() => assertSnapshot(s)).toThrow(message);
};

describe('snapshot validation', () => {
  it('accepts every fixture', () => {
    for (const f of ['01-nacl-ephemeral-return', '02-sg-to-sg-reference', '03-longest-prefix-routes', '04-blackhole-routes', '05-peering-no-return-route', '06-public-ip-without-igw-route', '07-alb-private-targets', '08-nlb-client-ip-preservation', '09-lateral-movement']) {
      expect(() => assertSnapshot(load(f))).not.toThrow();
    }
  });
  it('refuses a port given as text, which would compare wrongly', () => {
    refuse((s) => { s.ec2.SecurityGroupRules[0].FromPort = '22'; }, /SecurityGroupRules\[0\]\.FromPort" must be a port number/);
  });
  it('refuses out-of-range ports and rule numbers', () => {
    refuse((s) => { s.ec2.SecurityGroupRules[0].ToPort = 70000; }, /ToPort/);
    refuse((s) => { s.ec2.NetworkAcls[0].Entries[0].RuleNumber = '100; rm -rf ~'; }, /RuleNumber" must be a rule number/);
  });
  it('refuses control characters, which could reach a terminal or a command', () => {
    refuse((s) => { s.ec2.SecurityGroupRules[0].CidrIpv4 = '0.0.0.0/0\n'; }, /contains control characters/);
  });
  it('keeps free text but replaces its control characters, so one odd tag does not block an account', () => {
    const s = load('09-lateral-movement');
    s.ec2.SecurityGroups[0].GroupName = 'db\u001b]0;owned\u0007';
    s.ec2.SecurityGroupRules[0].Description = 'line one\nrm -rf ~';
    assertSnapshot(s);
    expect(s.ec2.SecurityGroups[0].GroupName).toBe('db\ufffd]0;owned\ufffd');
    expect(s.ec2.SecurityGroupRules[0].Description).toBe('line one\ufffdrm -rf ~');
  });
  it('refuses IDs and metadata of the wrong shape', () => {
    refuse((s) => { s.ec2.SecurityGroups[0].GroupId = "sg-x'; rm -rf ~"; }, /must be an ID starting with "sg-"/);
    refuse((s) => { s.region = 'us-east-1 --profile prod'; }, /must be an AWS region name/);
    refuse((s) => { s.accountId = '12345'; }, /12-digit AWS account ID/);
  });
  it('refuses reserved keys in keyed maps', () => {
    refuse((s) => { s.elbv2 = { TargetHealth: JSON.parse('{"__proto__": []}') }; }, /invalid key/);
  });
  it('refuses missing required fields and wrong container types', () => {
    refuse((s) => { delete s.ec2.SecurityGroupRules[0].IsEgress; }, /IsEgress" is missing/);
    refuse((s) => { s.ec2.NetworkAcls[0].Entries = {}; }, /must be a list/);
  });
});

describe('changes validation', () => {
  it('accepts well-formed changes', () => {
    expect(() => assertChanges([{ kind: 'revoke-sg-rule', ruleId: 'sgr-1' }, { kind: 'add-nacl-entry', naclId: 'acl-1', egress: false, ruleNumber: 90, action: 'deny', protocol: 'tcp', cidr: '0.0.0.0/0', fromPort: 22, toPort: 22 }])).not.toThrow();
  });
  it('refuses anything that could alter a generated command', () => {
    expect(() => assertChanges({})).toThrow(/JSON array/);
    expect(() => assertChanges([{ kind: 'revoke-sg-rule', ruleId: 'sgr-1; rm -rf ~' }])).toThrow(/Change 1: "ruleId"/);
    expect(() => assertChanges([{ kind: 'remove-nacl-entry', naclId: 'acl-1', egress: true, ruleNumber: '1 && curl x' }])).toThrow(/ruleNumber/);
    expect(() => assertChanges([{ kind: 'add-nacl-entry', naclId: 'acl-1', egress: false, ruleNumber: 90, action: 'allow; x', protocol: 'tcp', cidr: '0.0.0.0/0' }])).toThrow(/action/);
    expect(() => assertChanges([{ kind: 'add-sg-rule', groupId: 'sg-1', egress: false, protocol: 'tcp', cidr: '10.0.0.0/8', description: 'a\nb' }])).toThrow(/description/);
    expect(() => assertChanges([{ kind: 'drop-table' }])).toThrow(/unknown "kind"/);
  });
});
