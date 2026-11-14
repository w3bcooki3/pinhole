/**
 * IPv6 addresses and exact address sets, as 128-bit BigInt ranges.
 *
 * The IPv6 internet is taken to be global unicast space, 2000::/3, which is
 * where all IANA allocations for the public internet sit
 * (https://www.iana.org/assignments/ipv6-unicast-address-assignments). Unique
 * local (fc00::/7), link-local (fe80::/10), multicast and the special ranges
 * below 2000:: are never internet sources. The documentation range
 * 2001:db8::/32 is inside 2000::/3, so fixtures can use it for clients, the
 * same way IPv4 fixtures use the RFC 5737 ranges.
 */

const BITS = 128n;
const MAX = (1n << BITS) - 1n;

export interface Cidr6 {
  start: bigint;
  end: bigint;
  prefixLength: number;
  text: string;
}

export function parseIpv6(text: string): bigint {
  const bad = () => new Error(`Invalid IPv6 address: "${text}"`);
  if (typeof text !== 'string' || !/^[0-9a-fA-F:]+$/.test(text) || text.length > 39) throw bad();
  const halves = text.split('::');
  if (halves.length > 2) throw bad();
  const groups = (s: string) => (s === '' ? [] : s.split(':'));
  const head = groups(halves[0]!);
  const tail = halves.length === 2 ? groups(halves[1]!) : [];
  const all = halves.length === 2 ? [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail] : head;
  if (all.length !== 8 || (halves.length === 2 && head.length + tail.length > 7)) throw bad();
  let v = 0n;
  for (const g of all) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) throw bad();
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  return v;
}

/** Shortest text form: lower case, no leading zeros, longest run of zero groups as "::". */
export function formatIpv6(v: bigint): string {
  const g: number[] = [];
  for (let i = 7; i >= 0; i--) g.push(Number((v >> BigInt(i * 16)) & 0xffffn));
  let best = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) {
      best = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (best < 0) return hex.join(':');
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

export function isIpv6Cidr(text: string): boolean {
  return /^[0-9a-fA-F:]+\/\d{1,3}$/.test(text);
}

export function parseCidr6(text: string): Cidr6 {
  const [addr, len] = text.includes('/') ? text.split('/') : [text, '128'];
  const prefixLength = Number(len);
  if (!/^\d{1,3}$/.test(len ?? '') || prefixLength > 128) throw new Error(`Invalid IPv6 CIDR: "${text}"`);
  const hostBits = BITS - BigInt(prefixLength);
  const mask = prefixLength === 0 ? 0n : (MAX >> hostBits) << hostBits;
  const start = parseIpv6(addr ?? '') & mask;
  const end = start | (MAX ^ mask);
  return { start, end, prefixLength, text: `${formatIpv6(start)}/${prefixLength}` };
}

interface R {
  start: bigint;
  end: bigint;
}

/** An exact set of IPv6 addresses: sorted, non-overlapping, non-adjacent ranges. */
export class RangeSet6 {
  private constructor(private readonly ranges: readonly R[]) {}

  static empty(): RangeSet6 {
    return new RangeSet6([]);
  }

  static of(input: Iterable<R>): RangeSet6 {
    const list = [...input].map((r) => ({ start: r.start, end: r.end })).sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
    const out: R[] = [];
    for (const r of list) {
      const last = out[out.length - 1];
      if (last && r.start <= last.end + 1n) {
        if (r.end > last.end) last.end = r.end;
      } else out.push({ ...r });
    }
    return new RangeSet6(out);
  }

  static fromCidrs(cidrs: Iterable<string>): RangeSet6 {
    return RangeSet6.of([...cidrs].map(parseCidr6));
  }

  isEmpty(): boolean {
    return this.ranges.length === 0;
  }

  contains(ip: bigint): boolean {
    return this.ranges.some((r) => r.start <= ip && ip <= r.end);
  }

  /** The ranges, for walking boundaries. */
  list(): readonly R[] {
    return this.ranges;
  }

  union(other: RangeSet6): RangeSet6 {
    return RangeSet6.of([...this.ranges, ...other.ranges]);
  }

  intersect(other: RangeSet6): RangeSet6 {
    const out: R[] = [];
    let i = 0;
    let j = 0;
    while (i < this.ranges.length && j < other.ranges.length) {
      const a = this.ranges[i]!;
      const b = other.ranges[j]!;
      const start = a.start > b.start ? a.start : b.start;
      const end = a.end < b.end ? a.end : b.end;
      if (start <= end) out.push({ start, end });
      if (a.end < b.end) i++;
      else j++;
    }
    return new RangeSet6(out);
  }

  subtract(other: RangeSet6): RangeSet6 {
    const out: R[] = [];
    for (const r of this.ranges) {
      let pieces: R[] = [{ ...r }];
      for (const o of other.ranges) {
        if (o.start > r.end) break;
        const next: R[] = [];
        for (const p of pieces) {
          if (o.end < p.start || o.start > p.end) {
            next.push(p);
            continue;
          }
          if (p.start < o.start) next.push({ start: p.start, end: o.start - 1n });
          if (o.end < p.end) next.push({ start: o.end + 1n, end: p.end });
        }
        pieces = next;
      }
      out.push(...pieces);
    }
    return new RangeSet6(out);
  }

  equals(other: RangeSet6): boolean {
    return this.ranges.length === other.ranges.length && this.ranges.every((r, i) => r.start === other.ranges[i]!.start && r.end === other.ranges[i]!.end);
  }

  toCidrs(): string[] {
    const out: string[] = [];
    for (const r of this.ranges) {
      let start = r.start;
      while (start <= r.end) {
        // Largest aligned block that starts here and fits.
        let size = 0n;
        while (size < BITS) {
          const next = size + 1n;
          const block = 1n << next;
          if (start % block !== 0n || start + block - 1n > r.end) break;
          size = next;
        }
        out.push(`${formatIpv6(start)}/${Number(BITS - size)}`);
        start += 1n << size;
        if (start === 0n) break;
      }
    }
    return out;
  }
}

export const ALL6 = RangeSet6.of([{ start: 0n, end: MAX }]);
export const INTERNET6 = RangeSet6.fromCidrs(['2000::/3']);
