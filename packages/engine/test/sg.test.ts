// Security group semantics.
// https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
import { describe, expect, it } from 'vitest';
import { evaluateSg } from '../src/sg.js';
import { parseCidr, parseIpv4 } from '../src/ipv4.js';
import type { PrefixList } from '../src/types.js';
import { sg, sgRule, TCP, UDP, ICMP, ALL } from './helpers.js';

const ip = parseIpv4;
const noLists = new Map<string, PrefixList>();
const external = (addr: string) => ({ ip: ip(addr), relation: { kind: 'external' as const } });

describe('evaluateSg', () => {
  it('denies by default when no rule matches (allow-only model)', () => {
    const g = sg('sg-a', [sgRule('sg-a', false, TCP, 443, 443, { cidr: parseCidr('0.0.0.0/0') })]);
    const d = evaluateSg([g], 'ingress', external('8.8.8.8'), { protocol: TCP, port: 22 }, noLists);
    expect(d.allowed).toBe(false);
    expect(d.matched).toEqual([]);
  });

  it('ORs rules across every group attached to the interface and reports all matches', () => {
    const a = sg('sg-a', [sgRule('sg-a', false, TCP, 22, 22, { cidr: parseCidr('203.0.113.0/24') })]);
    const b = sg('sg-b', [sgRule('sg-b', false, TCP, 0, 65535, { cidr: parseCidr('0.0.0.0/0') })]);
    const d = evaluateSg([a, b], 'ingress', external('203.0.113.9'), { protocol: TCP, port: 22 }, noLists);
    expect(d.allowed).toBe(true);
    expect(d.matched.map((r) => r.groupId).sort()).toEqual(['sg-a', 'sg-b']);
  });

  it('protocol -1 rules cover every protocol', () => {
    const g = sg('sg-a', [sgRule('sg-a', false, ALL, undefined, undefined, { cidr: parseCidr('10.0.0.0/8') })]);
    expect(evaluateSg([g], 'ingress', external('10.1.1.1'), { protocol: UDP, port: 9999 }, noLists).allowed).toBe(true);
  });

  it('matches ICMP by type, with code -1 meaning any code', () => {
    const g = sg('sg-a', [sgRule('sg-a', false, ICMP, 8, -1, { cidr: parseCidr('0.0.0.0/0') })]);
    expect(evaluateSg([g], 'ingress', external('8.8.8.8'), { protocol: ICMP, icmpType: 8, icmpCode: 0 }, noLists).allowed).toBe(true);
    expect(evaluateSg([g], 'ingress', external('8.8.8.8'), { protocol: ICMP, icmpType: 3, icmpCode: 4 }, noLists).allowed).toBe(false);
  });

  it('expands prefix lists', () => {
    const lists = new Map<string, PrefixList>([
      ['pl-1', { id: 'pl-1', name: 'office', entries: [parseCidr('198.51.100.0/24')], entriesKnown: true, hasIpv6Entries: false }],
    ]);
    const g = sg('sg-a', [sgRule('sg-a', false, TCP, 22, 22, { prefixListId: 'pl-1' })]);
    expect(evaluateSg([g], 'ingress', external('198.51.100.20'), { protocol: TCP, port: 22 }, lists).allowed).toBe(true);
    expect(evaluateSg([g], 'ingress', external('8.8.8.8'), { protocol: TCP, port: 22 }, lists).allowed).toBe(false);
  });

  it('flags a prefix list whose entries are unknown instead of guessing', () => {
    const g = sg('sg-a', [sgRule('sg-a', false, TCP, 22, 22, { prefixListId: 'pl-missing' })]);
    const d = evaluateSg([g], 'ingress', external('8.8.8.8'), { protocol: TCP, port: 22 }, noLists);
    expect(d.allowed).toBe(false);
    expect(d.unknownPrefixLists).toEqual(['pl-missing']);
  });

  describe('security group references', () => {
    const db = sg('sg-db', [sgRule('sg-db', false, TCP, 5432, 5432, { referencedGroupId: 'sg-web' })]);

    it('match an interface that is a member of the referenced group', () => {
      const peer = { ip: ip('10.0.1.10'), groupIds: ['sg-web'], relation: { kind: 'same-vpc' as const } };
      expect(evaluateSg([db], 'ingress', peer, { protocol: TCP, port: 5432 }, noLists).allowed).toBe(true);
    });

    it('do not match an interface outside the group, even in the same subnet', () => {
      const peer = { ip: ip('10.0.1.11'), groupIds: ['sg-other'], relation: { kind: 'same-vpc' as const } };
      expect(evaluateSg([db], 'ingress', peer, { protocol: TCP, port: 5432 }, noLists).allowed).toBe(false);
    });

    it('never match internet traffic, because they match private IPs of member interfaces', () => {
      // A public client has no ENI and therefore no group membership.
      expect(evaluateSg([db], 'ingress', external('8.8.8.8'), { protocol: TCP, port: 5432 }, noLists).allowed).toBe(false);
    });

    it('match across VPC peering', () => {
      const peer = { ip: ip('10.1.1.10'), groupIds: ['sg-web'], relation: { kind: 'peering' as const } };
      expect(evaluateSg([db], 'ingress', peer, { protocol: TCP, port: 5432 }, noLists).allowed).toBe(true);
    });

    it('match inbound across a transit gateway only when referencing support is enabled', () => {
      const on = { ip: ip('10.2.1.10'), groupIds: ['sg-web'], relation: { kind: 'tgw' as const, sgReferencing: true } };
      const off = { ...on, relation: { kind: 'tgw' as const, sgReferencing: false } };
      expect(evaluateSg([db], 'ingress', on, { protocol: TCP, port: 5432 }, noLists).allowed).toBe(true);
      expect(evaluateSg([db], 'ingress', off, { protocol: TCP, port: 5432 }, noLists).allowed).toBe(false);
    });

    it('do not match outbound across a transit gateway (only same VPC or peered VPC)', () => {
      const web = sg('sg-web', [], [sgRule('sg-web', true, TCP, 5432, 5432, { referencedGroupId: 'sg-db' })]);
      const peer = { ip: ip('10.2.1.20'), groupIds: ['sg-db'], relation: { kind: 'tgw' as const, sgReferencing: true } };
      expect(evaluateSg([web], 'egress', peer, { protocol: TCP, port: 5432 }, noLists).allowed).toBe(false);
    });
  });
});
