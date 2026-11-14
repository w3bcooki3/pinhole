import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { assertSnapshot, diffSnapshots, DriftError, normalize } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const raw = () => JSON.parse(readFileSync(join(here, '../../../fixtures/09-lateral-movement/snapshot.json'), 'utf8'));
const model = (s: unknown) => {
  assertSnapshot(s);
  return normalize(s);
};

describe('snapshot diff', () => {
  it('reports nothing for the same snapshot', () => {
    const d = diffSnapshots(model(raw()), model(raw()));
    expect(d.exposure.deltas).toEqual([]);
    expect(d.exposure.chainsOpened).toEqual([]);
    expect(d.config).toEqual([]);
  });

  it('finds a newly opened port, the chains it closes, and the rule changes that explain both', () => {
    const after = raw();
    // Someone closes SSH to the bastion from the internet...
    after.ec2.SecurityGroupRules = after.ec2.SecurityGroupRules.filter((r: { SecurityGroupRuleId: string }) => r.SecurityGroupRuleId !== 'sgr-bastion-ssh-world');
    // ...and opens 8443 on the web server to everyone.
    after.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: 'sgr-web-8443', GroupId: 'sg-web', IsEgress: false, IpProtocol: 'tcp', FromPort: 8443, ToPort: 8443, CidrIpv4: '0.0.0.0/0' });
    const d = diffSnapshots(model(raw()), model(after));

    const opened = d.exposure.deltas.filter((x) => x.status === 'opened');
    const closed = d.exposure.deltas.filter((x) => x.status === 'closed');
    expect(opened.map((x) => [x.resourceId, x.protocol, x.ports])).toEqual([['eni-web', 'tcp', { from: 8443, to: 8443 }]]);
    expect(closed.map((x) => [x.resourceId, x.ports])).toEqual([['eni-bastion', { from: 22, to: 22 }]]);
    expect(d.exposure.chainsClosed.length).toBeGreaterThan(0);
    expect(d.exposure.chainsClosed.every((c) => c.entries.some((e) => e.eniId === 'eni-bastion'))).toBe(true);

    expect(d.config).toContainEqual(expect.objectContaining({ kind: 'security group rule', change: 'added', id: 'sgr-web-8443', after: 'tcp/8443 from 0.0.0.0/0' }));
    expect(d.config).toContainEqual(expect.objectContaining({ kind: 'security group rule', change: 'removed', id: 'sgr-bastion-ssh-world', before: 'tcp/22 from 0.0.0.0/0' }));
    // Added changes are listed first.
    expect(d.config[0]!.change).toBe('added');
  });

  it('reports a widened source range as widened, not as opened', () => {
    const after = raw();
    const r = after.ec2.SecurityGroupRules.find((x: { SecurityGroupRuleId: string }) => x.SecurityGroupRuleId === 'sgr-web-https-partner');
    r.CidrIpv4 = '0.0.0.0/0';
    after.ec2.SecurityGroupRules = after.ec2.SecurityGroupRules.filter((x: { SecurityGroupRuleId: string }) => x.SecurityGroupRuleId !== 'sgr-web-https');
    const before = raw();
    before.ec2.SecurityGroupRules = before.ec2.SecurityGroupRules.filter((x: { SecurityGroupRuleId: string }) => x.SecurityGroupRuleId !== 'sgr-web-https');
    const d = diffSnapshots(model(before), model(after));
    expect(d.exposure.deltas.map((x) => [x.resourceId, x.status])).toEqual([['eni-web', 'widened']]);
    expect(d.config).toContainEqual(expect.objectContaining({ id: 'sgr-web-https-partner', change: 'changed', before: 'tcp/443 from 203.0.113.0/24', after: 'tcp/443 from 0.0.0.0/0' }));
  });

  it('refuses snapshots of different accounts or regions', () => {
    const other = raw();
    other.region = 'eu-west-1';
    expect(() => diffSnapshots(model(raw()), model(other))).toThrow(DriftError);
    other.region = raw().region;
    other.accountId = '999999999999';
    expect(() => diffSnapshots(model(raw()), model(other))).toThrow(/different accounts/);
  });
});

describe('snapshot diff with IPv6', () => {
  const raw10 = () => JSON.parse(readFileSync(join(here, '../../../fixtures/10-ipv6-exposure/snapshot.json'), 'utf8'));
  it('reports a narrowed IPv6 source range as narrower, and keeps IPv4 and IPv6 apart', () => {
    const after = raw10();
    after.ec2.SecurityGroupRules.find((r: { SecurityGroupRuleId: string }) => r.SecurityGroupRuleId === 'sgr-https-v6').CidrIpv6 = '2001:db8::/32';
    const d = diffSnapshots(model(raw10()), model(after));
    expect(d.exposure.deltas.map((x) => [x.resourceId, x.protocol, x.ports?.from, x.status, x.family])).toEqual([['eni-dual', 'tcp', 443, 'narrowed', 'ipv6']]);
    expect(d.exposure.deltas[0]!.after).toEqual(['2001:db8::/32']);
  });
});
