/**
 * IPv4 address arithmetic and address sets.
 *
 * Addresses are held as unsigned 32-bit integers in ordinary JS numbers
 * (0 .. 2^32-1). Bitwise operators in JS work on signed 32-bit values, so every
 * mask is converted back with `>>> 0`.
 */
import type { Cidr, IpRange } from './types.js';

const MAX = 0xffffffff;

export function parseIpv4(text: string): number {
  const parts = text.split('.');
  if (parts.length !== 4) throw new Error(`Invalid IPv4 address: "${text}"`);
  let value = 0;
  for (const p of parts) {
    // Reject empty parts, signs, and leading zeros (ambiguous octal notation).
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) throw new Error(`Invalid IPv4 address: "${text}"`);
    const n = Number(p);
    if (n > 255) throw new Error(`Invalid IPv4 address: "${text}"`);
    value = value * 256 + n;
  }
  return value;
}

export function formatIpv4(value: number): string {
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

export function isIpv4Cidr(text: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(text);
}

function maskFor(prefixLength: number): number {
  return prefixLength === 0 ? 0 : (MAX << (32 - prefixLength)) >>> 0;
}

/**
 * Parses "a.b.c.d/n". Host bits are cleared, which matches how AWS stores
 * CIDRs, so a rule written as 10.0.1.7/24 covers 10.0.1.0-10.0.1.255.
 * A bare address is treated as /32.
 */
export function parseCidr(text: string): Cidr {
  const [addr, len] = text.includes('/') ? text.split('/') : [text, '32'];
  const prefixLength = Number(len);
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32 || !/^\d+$/.test(len ?? '')) {
    throw new Error(`Invalid IPv4 CIDR: "${text}"`);
  }
  const mask = maskFor(prefixLength);
  const start = (parseIpv4(addr ?? '') & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return { start, end, prefixLength, text: `${formatIpv4(start)}/${prefixLength}` };
}

export function rangeContains(range: IpRange, ip: number): boolean {
  return ip >= range.start && ip <= range.end;
}

/** Splits an arbitrary inclusive range into the smallest list of CIDR blocks. */
export function rangeToCidrs(range: IpRange): string[] {
  const out: string[] = [];
  let cur = range.start;
  while (cur <= range.end) {
    // Largest block aligned at `cur` that does not run past `end`.
    let len = 32;
    while (len > 0) {
      const next = len - 1;
      const size = 2 ** (32 - next);
      if (cur % size !== 0 || cur + size - 1 > range.end) break;
      len = next;
    }
    out.push(`${formatIpv4(cur)}/${len}`);
    cur += 2 ** (32 - len);
    if (cur > MAX) break;
  }
  return out;
}

/**
 * An immutable, normalised set of IPv4 addresses: sorted, non-overlapping,
 * non-adjacent inclusive ranges.
 */
export class RangeSet {
  readonly ranges: readonly IpRange[];

  private constructor(ranges: IpRange[]) {
    this.ranges = ranges;
  }

  static empty(): RangeSet {
    return new RangeSet([]);
  }

  static of(ranges: Iterable<IpRange>): RangeSet {
    const sorted = [...ranges].map((r) => ({ start: r.start, end: r.end })).sort((a, b) => a.start - b.start);
    const merged: IpRange[] = [];
    for (const r of sorted) {
      const last = merged[merged.length - 1];
      if (last && r.start <= last.end + 1) {
        last.end = Math.max(last.end, r.end);
      } else {
        merged.push(r);
      }
    }
    return new RangeSet(merged);
  }

  static fromCidrs(cidrs: Iterable<string>): RangeSet {
    return RangeSet.of([...cidrs].map(parseCidr));
  }

  isEmpty(): boolean {
    return this.ranges.length === 0;
  }

  containsIp(ip: number): boolean {
    // Sets are small; a linear scan is clearer than a binary search here.
    return this.ranges.some((r) => rangeContains(r, ip));
  }

  /** Number of addresses in the set. */
  size(): number {
    return this.ranges.reduce((n, r) => n + (r.end - r.start + 1), 0);
  }

  union(other: RangeSet): RangeSet {
    return RangeSet.of([...this.ranges, ...other.ranges]);
  }

  intersect(other: RangeSet): RangeSet {
    const out: IpRange[] = [];
    for (const a of this.ranges) {
      for (const b of other.ranges) {
        const start = Math.max(a.start, b.start);
        const end = Math.min(a.end, b.end);
        if (start <= end) out.push({ start, end });
      }
    }
    return RangeSet.of(out);
  }

  subtract(other: RangeSet): RangeSet {
    let current: IpRange[] = this.ranges.map((r) => ({ ...r }));
    for (const hole of other.ranges) {
      const next: IpRange[] = [];
      for (const r of current) {
        if (hole.end < r.start || hole.start > r.end) {
          next.push(r);
          continue;
        }
        if (hole.start > r.start) next.push({ start: r.start, end: hole.start - 1 });
        if (hole.end < r.end) next.push({ start: hole.end + 1, end: r.end });
      }
      current = next;
    }
    return RangeSet.of(current);
  }

  /** True when both sets hold exactly the same addresses. */
  equals(other: RangeSet): boolean {
    if (this === other) return true;
    if (this.ranges.length !== other.ranges.length) return false;
    return this.ranges.every((r, i) => r.start === other.ranges[i]!.start && r.end === other.ranges[i]!.end);
  }

  private cidrs?: string[];
  toCidrs(): string[] {
    // Sets are immutable, so the CIDR split is computed once.
    this.cidrs ??= this.ranges.flatMap(rangeToCidrs);
    return this.cidrs;
  }
}

/**
 * Address space that is not routable on the public internet (RFC 6890 special
 * purpose blocks that matter here). Traffic from these can never arrive through
 * an internet gateway.
 *
 * The RFC 5737 documentation blocks (192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24) are deliberately NOT excluded: they appear in AWS examples and
 * in our fixtures as stand-ins for real internet clients.
 */
export const NON_INTERNET = RangeSet.fromCidrs([
  '0.0.0.0/8', // "this network"
  '10.0.0.0/8', // RFC 1918
  '100.64.0.0/10', // carrier-grade NAT, RFC 6598
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local (includes the instance metadata service)
  '172.16.0.0/12', // RFC 1918
  '192.0.0.0/24', // IETF protocol assignments
  '192.168.0.0/16', // RFC 1918
  '198.18.0.0/15', // benchmarking
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved, includes broadcast
]);

/** Every IPv4 address a client on the internet could have. */
export const INTERNET = RangeSet.of([{ start: 0, end: MAX }]).subtract(NON_INTERNET);
