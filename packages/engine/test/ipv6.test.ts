import { describe, expect, it } from 'vitest';
import { formatIpv6, INTERNET6, parseCidr6, parseIpv6, RangeSet6 } from '../src/ipv6.js';

describe('IPv6 addresses', () => {
  it('parses full, compressed and mixed-case forms', () => {
    expect(parseIpv6('::')).toBe(0n);
    expect(parseIpv6('::1')).toBe(1n);
    expect(parseIpv6('2001:db8::1')).toBe(parseIpv6('2001:0DB8:0000:0000:0000:0000:0000:0001'));
    expect(parseIpv6('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')).toBe((1n << 128n) - 1n);
  });

  it('refuses malformed addresses', () => {
    for (const bad of ['', ':', '1::2::3', '12345::', 'g::1', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7', '::ffff:1.2.3.4']) expect(() => parseIpv6(bad), bad).toThrow(/Invalid IPv6/);
  });

  it('formats in the shortest form (RFC 5952)', () => {
    expect(formatIpv6(parseIpv6('2001:db8:0:0:0:0:0:1'))).toBe('2001:db8::1');
    expect(formatIpv6(0n)).toBe('::');
    expect(formatIpv6(parseIpv6('2001:db8:0:1:0:0:0:0'))).toBe('2001:db8:0:1::');
    expect(formatIpv6(parseIpv6('2001:0:0:1:0:0:0:1'))).toBe('2001:0:0:1::1');
    expect(formatIpv6(parseIpv6('2001:0:0:1:0:0:1:1'))).toBe('2001::1:0:0:1:1');
  });

  it('parses CIDRs, masking host bits', () => {
    const c = parseCidr6('2001:db8:1234::5/48');
    expect(formatIpv6(c.start)).toBe('2001:db8:1234::');
    expect(c.end - c.start).toBe((1n << 80n) - 1n);
    expect(c.text).toBe('2001:db8:1234::/48');
    expect(() => parseCidr6('2001:db8::/129')).toThrow(/Invalid IPv6 CIDR/);
  });
});

describe('IPv6 range sets', () => {
  const s = (...c: string[]) => RangeSet6.fromCidrs(c);
  it('unions, intersects and subtracts exactly', () => {
    const a = s('2001:db8::/32');
    const b = s('2001:db8:8000::/33');
    expect(a.subtract(b).toCidrs()).toEqual(['2001:db8::/33']);
    expect(a.intersect(b).toCidrs()).toEqual(['2001:db8:8000::/33']);
    expect(s('2001:db8::/33').union(s('2001:db8:8000::/33')).toCidrs()).toEqual(['2001:db8::/32']);
    expect(a.subtract(a).isEmpty()).toBe(true);
    expect(a.equals(s('2001:db8::/33', '2001:db8:8000::/33'))).toBe(true);
    expect(a.contains(parseIpv6('2001:db8:ffff::1'))).toBe(true);
  });

  it('treats global unicast (2000::/3) as the IPv6 internet', () => {
    expect(INTERNET6.toCidrs()).toEqual(['2000::/3']);
    expect(s('::/0').intersect(INTERNET6).equals(INTERNET6)).toBe(true);
    expect(s('fd00::/8').intersect(INTERNET6).isEmpty()).toBe(true);
  });
});
