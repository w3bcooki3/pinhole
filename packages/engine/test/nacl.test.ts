// Network ACL semantics.
// https://docs.aws.amazon.com/vpc/latest/userguide/nacl-rules.html
// https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html
import { describe, expect, it } from 'vitest';
import { evaluateNacl, evaluateNaclPortRange } from '../src/nacl.js';
import { parseIpv4 } from '../src/ipv4.js';
import { nacl, naclEntry, TCP, UDP, ICMP, ALL } from './helpers.js';

const ip = parseIpv4;

describe('evaluateNacl', () => {
  it('applies the lowest-numbered matching rule (first match wins)', () => {
    const acl = nacl('acl-1', [
      naclEntry(100, false, 'deny', TCP, '203.0.113.0/24', [22, 22]),
      naclEntry(200, false, 'allow', TCP, '0.0.0.0/0', [22, 22]),
    ]);
    const d1 = evaluateNacl(acl, false, ip('203.0.113.5'), { protocol: TCP, port: 22 });
    expect(d1.action).toBe('deny');
    expect(d1.entry.ruleNumber).toBe(100);

    const d2 = evaluateNacl(acl, false, ip('198.51.100.5'), { protocol: TCP, port: 22 });
    expect(d2.action).toBe('allow');
    expect(d2.entry.ruleNumber).toBe(200);
  });

  it('orders by rule number, not by position in the input', () => {
    const acl = nacl('acl-1', [
      naclEntry(300, false, 'allow', TCP, '0.0.0.0/0', [443, 443]),
      naclEntry(50, false, 'deny', ALL, '0.0.0.0/0'),
    ]);
    expect(evaluateNacl(acl, false, ip('8.8.8.8'), { protocol: TCP, port: 443 }).entry.ruleNumber).toBe(50);
  });

  it('falls through to the * rule and denies', () => {
    const acl = nacl('acl-1', [naclEntry(100, false, 'allow', TCP, '0.0.0.0/0', [443, 443])]);
    const d = evaluateNacl(acl, false, ip('8.8.8.8'), { protocol: TCP, port: 139 });
    expect(d.action).toBe('deny');
    expect(d.entry.ruleNumber).toBe(32767);
  });

  it('keeps inbound and outbound rules separate', () => {
    const acl = nacl('acl-1', [naclEntry(100, true, 'allow', ALL, '0.0.0.0/0')]);
    expect(evaluateNacl(acl, true, ip('8.8.8.8'), { protocol: TCP, port: 80 }).action).toBe('allow');
    expect(evaluateNacl(acl, false, ip('8.8.8.8'), { protocol: TCP, port: 80 }).action).toBe('deny');
  });

  it('matches protocol exactly: a TCP rule does not admit UDP', () => {
    const acl = nacl('acl-1', [naclEntry(100, false, 'allow', TCP, '0.0.0.0/0', [53, 53])]);
    expect(evaluateNacl(acl, false, ip('8.8.8.8'), { protocol: UDP, port: 53 }).action).toBe('deny');
  });

  it('protocol -1 matches every protocol and port', () => {
    const acl = nacl('acl-1', [naclEntry(100, false, 'allow', ALL, '10.0.0.0/8')]);
    expect(evaluateNacl(acl, false, ip('10.9.9.9'), { protocol: UDP, port: 5000 }).action).toBe('allow');
    expect(evaluateNacl(acl, false, ip('10.9.9.9'), { protocol: ICMP, icmpType: 8, icmpCode: 0 }).action).toBe('allow');
  });

  it('matches ICMP type and code, with -1 as a wildcard', () => {
    const acl = nacl('acl-1', [
      { ...naclEntry(100, false, 'allow', ICMP, '0.0.0.0/0'), icmp: { type: 8, code: -1 } },
    ]);
    expect(evaluateNacl(acl, false, ip('8.8.8.8'), { protocol: ICMP, icmpType: 8, icmpCode: 0 }).action).toBe('allow');
    expect(evaluateNacl(acl, false, ip('8.8.8.8'), { protocol: ICMP, icmpType: 0, icmpCode: 0 }).action).toBe('deny');
  });

  it('ignores IPv6 entries when evaluating IPv4 traffic', () => {
    const acl = nacl('acl-1', [
      { ruleNumber: 90, egress: false, action: 'deny', protocol: ALL, ipv6CidrText: '::/0' },
      naclEntry(100, false, 'allow', ALL, '0.0.0.0/0'),
    ]);
    expect(evaluateNacl(acl, false, ip('8.8.8.8'), { protocol: TCP, port: 1 }).entry.ruleNumber).toBe(100);
  });
});

describe('evaluateNaclPortRange (return traffic on ephemeral ports)', () => {
  it('splits a port range into allowed and denied segments by first match', () => {
    // Outbound: allow only the Linux ephemeral range.
    const acl = nacl('acl-1', [naclEntry(100, true, 'allow', TCP, '0.0.0.0/0', [32768, 61000])]);
    const segs = evaluateNaclPortRange(acl, true, ip('8.8.8.8'), TCP, { from: 1024, to: 65535 });
    expect(segs.map((s) => [s.range.from, s.range.to, s.action, s.entry.ruleNumber])).toEqual([
      [1024, 32767, 'deny', 32767],
      [32768, 61000, 'allow', 100],
      [61001, 65535, 'deny', 32767],
    ]);
  });

  it('lets an earlier deny carve a hole out of a later allow', () => {
    const acl = nacl('acl-1', [
      naclEntry(90, true, 'deny', TCP, '0.0.0.0/0', [50000, 50010]),
      naclEntry(100, true, 'allow', TCP, '0.0.0.0/0', [1024, 65535]),
    ]);
    const segs = evaluateNaclPortRange(acl, true, ip('8.8.8.8'), TCP, { from: 49152, to: 65535 });
    expect(segs.map((s) => [s.range.from, s.range.to, s.action])).toEqual([
      [49152, 49999, 'allow'],
      [50000, 50010, 'deny'],
      [50011, 65535, 'allow'],
    ]);
  });
});
