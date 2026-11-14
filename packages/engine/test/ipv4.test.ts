import { describe, expect, it } from 'vitest';
import {
  parseIpv4,
  formatIpv4,
  parseCidr,
  rangeContains,
  RangeSet,
  rangeToCidrs,
  INTERNET,
  isIpv4Cidr,
} from '../src/ipv4.js';

describe('parseIpv4 / formatIpv4', () => {
  it('round-trips addresses', () => {
    for (const a of ['0.0.0.0', '10.0.1.5', '255.255.255.255', '203.0.113.7']) {
      expect(formatIpv4(parseIpv4(a))).toBe(a);
    }
  });

  it('rejects malformed input', () => {
    for (const a of ['1.2.3', '1.2.3.256', '01.2.3.4', 'a.b.c.d', '1.2.3.4.5', '']) {
      expect(() => parseIpv4(a)).toThrow();
    }
  });
});

describe('parseCidr', () => {
  it('parses a /24 into an inclusive range', () => {
    const c = parseCidr('10.0.1.0/24');
    expect(formatIpv4(c.start)).toBe('10.0.1.0');
    expect(formatIpv4(c.end)).toBe('10.0.1.255');
    expect(c.prefixLength).toBe(24);
  });

  it('handles /0 and /32', () => {
    const all = parseCidr('0.0.0.0/0');
    expect(all.start).toBe(0);
    expect(all.end).toBe(0xffffffff);
    const one = parseCidr('198.51.100.9/32');
    expect(one.start).toBe(one.end);
  });

  it('masks host bits the way AWS normalises them', () => {
    // AWS stores the network address; a stray host bit must not shift the range.
    const c = parseCidr('10.0.1.7/24');
    expect(formatIpv4(c.start)).toBe('10.0.1.0');
  });

  it('distinguishes IPv4 from IPv6 CIDRs', () => {
    expect(isIpv4Cidr('10.0.0.0/8')).toBe(true);
    expect(isIpv4Cidr('::/0')).toBe(false);
    expect(isIpv4Cidr('2001:db8::/32')).toBe(false);
  });
});

describe('RangeSet', () => {
  const r = (cidr: string) => parseCidr(cidr);

  it('merges overlapping and adjacent ranges', () => {
    const s = RangeSet.of([r('10.0.0.0/25'), r('10.0.0.128/25'), r('10.0.0.64/26')]);
    expect(s.ranges).toHaveLength(1);
    expect(rangeToCidrs(s.ranges[0]!)).toEqual(['10.0.0.0/24']);
  });

  it('subtracts a hole out of the middle', () => {
    const s = RangeSet.of([r('10.0.0.0/24')]).subtract(RangeSet.of([r('10.0.0.128/26')]));
    expect(s.toCidrs()).toEqual(['10.0.0.0/25', '10.0.0.192/26']);
  });

  it('intersects', () => {
    const a = RangeSet.of([r('10.0.0.0/16')]);
    const b = RangeSet.of([r('10.0.5.0/24'), r('192.168.0.0/16')]);
    expect(a.intersect(b).toCidrs()).toEqual(['10.0.5.0/24']);
  });

  it('reports containment', () => {
    const s = RangeSet.of([r('172.16.0.0/12')]);
    expect(s.containsIp(parseIpv4('172.31.255.255'))).toBe(true);
    expect(s.containsIp(parseIpv4('172.32.0.0'))).toBe(false);
    expect(rangeContains(r('172.16.0.0/12'), parseIpv4('172.20.1.1'))).toBe(true);
  });
});

describe('INTERNET address set', () => {
  it('excludes RFC 1918, loopback, link-local, CGNAT and multicast', () => {
    for (const a of ['10.1.2.3', '172.16.0.1', '192.168.1.1', '127.0.0.1', '169.254.169.254', '100.64.0.1', '224.0.0.1']) {
      expect(INTERNET.containsIp(parseIpv4(a)), a).toBe(false);
    }
  });

  it('includes ordinary public addresses and the documentation ranges', () => {
    // Documentation ranges (RFC 5737) are kept so fixtures can use them as
    // stand-ins for real internet clients.
    for (const a of ['8.8.8.8', '203.0.113.10', '198.51.100.1', '52.94.1.1']) {
      expect(INTERNET.containsIp(parseIpv4(a)), a).toBe(true);
    }
  });
});

describe('rangeToCidrs', () => {
  it('splits a non-aligned range into the minimal CIDR list', () => {
    expect(rangeToCidrs({ start: parseIpv4('10.0.0.1'), end: parseIpv4('10.0.0.6') })).toEqual([
      '10.0.0.1/32',
      '10.0.0.2/31',
      '10.0.0.4/31',
      '10.0.0.6/32',
    ]);
  });

  it('returns 0.0.0.0/0 for the whole space', () => {
    expect(rangeToCidrs({ start: 0, end: 0xffffffff })).toEqual(['0.0.0.0/0']);
  });
});
