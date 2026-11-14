// Route selection.
// https://docs.aws.amazon.com/vpc/latest/userguide/route-tables-priority.html
import { describe, expect, it } from 'vitest';
import { lookupRoute, lookupTgwRoute } from '../src/routes.js';
import { parseCidr, parseIpv4 } from '../src/ipv4.js';
import type { PrefixList, TgwRouteTable } from '../src/types.js';
import { route, routeTable } from './helpers.js';

const ip = parseIpv4;
const noLists = new Map<string, PrefixList>();

describe('lookupRoute', () => {
  const rt = routeTable('rtb-1', [
    route('10.0.0.0/16', 'local', 'local'),
    route('0.0.0.0/0', 'igw', 'igw-1'),
    route('10.1.0.0/16', 'pcx', 'pcx-1'),
    route('10.1.5.0/24', 'tgw', 'tgw-1'),
  ]);

  it('picks the longest matching prefix', () => {
    expect(lookupRoute(rt, ip('10.1.5.9'), noLists)?.route.target.id).toBe('tgw-1');
    expect(lookupRoute(rt, ip('10.1.6.9'), noLists)?.route.target.id).toBe('pcx-1');
    expect(lookupRoute(rt, ip('8.8.8.8'), noLists)?.route.target.id).toBe('igw-1');
    expect(lookupRoute(rt, ip('10.0.3.3'), noLists)?.route.target.type).toBe('local');
  });

  it('returns undefined when nothing matches (no default route)', () => {
    const t = routeTable('rtb-2', [route('10.0.0.0/16', 'local', 'local')]);
    expect(lookupRoute(t, ip('8.8.8.8'), noLists)).toBeUndefined();
  });

  it('returns a blackhole route when it is the best match, so the caller can drop the packet', () => {
    const t = routeTable('rtb-3', [
      route('10.0.0.0/16', 'local', 'local'),
      route('10.9.0.0/16', 'pcx', 'pcx-deleted', { state: 'blackhole' }),
      route('0.0.0.0/0', 'nat', 'nat-1'),
    ]);
    const m = lookupRoute(t, ip('10.9.1.1'), noLists);
    expect(m?.route.state).toBe('blackhole');
  });

  it('on an exact tie prefers static over prefix-list over propagated routes', () => {
    const lists = new Map<string, PrefixList>([
      ['pl-1', { id: 'pl-1', name: 'x', entries: [parseCidr('172.16.0.0/16')], entriesKnown: true, hasIpv6Entries: false }],
    ]);
    const propagatedOnly = routeTable('rtb-4', [
      route('172.16.0.0/16', 'vgw', 'vgw-1', { origin: 'propagated' }),
      { target: { type: 'tgw', id: 'tgw-1' }, destinationPrefixListId: 'pl-1', state: 'active', origin: 'static' },
    ]);
    expect(lookupRoute(propagatedOnly, ip('172.16.1.1'), lists)?.route.target.id).toBe('tgw-1');

    const withStatic = routeTable('rtb-5', [...propagatedOnly.routes, route('172.16.0.0/16', 'pcx', 'pcx-1')]);
    expect(lookupRoute(withStatic, ip('172.16.1.1'), lists)?.route.target.id).toBe('pcx-1');
  });

  it('a more specific propagated route still beats a less specific static route', () => {
    const t = routeTable('rtb-6', [route('172.16.0.0/12', 'pcx', 'pcx-1'), route('172.16.0.0/16', 'vgw', 'vgw-1', { origin: 'propagated' })]);
    expect(lookupRoute(t, ip('172.16.1.1'), noLists)?.route.target.id).toBe('vgw-1');
  });

  it('uses the matching prefix-list entry length for longest-prefix comparison', () => {
    const lists = new Map<string, PrefixList>([
      ['pl-1', { id: 'pl-1', name: 'x', entries: [parseCidr('10.50.1.0/24')], entriesKnown: true, hasIpv6Entries: false }],
    ]);
    const t = routeTable('rtb-7', [
      route('10.50.0.0/16', 'pcx', 'pcx-1'),
      { target: { type: 'tgw', id: 'tgw-1' }, destinationPrefixListId: 'pl-1', state: 'active', origin: 'static' },
    ]);
    expect(lookupRoute(t, ip('10.50.1.1'), lists)?.route.target.id).toBe('tgw-1');
    expect(lookupRoute(t, ip('10.50.2.1'), lists)?.route.target.id).toBe('pcx-1');
  });
});

describe('lookupTgwRoute', () => {
  const table: TgwRouteTable = {
    id: 'tgw-rtb-1',
    tgwId: 'tgw-1',
    routesKnown: true,
    routes: [
      { destination: parseCidr('10.2.0.0/16'), attachmentIds: ['tgw-attach-c'], type: 'propagated', state: 'active' },
      { destination: parseCidr('10.2.9.0/24'), attachmentIds: [], type: 'static', state: 'blackhole' },
      { destination: parseCidr('10.3.0.0/16'), attachmentIds: ['tgw-attach-x'], type: 'propagated', state: 'active' },
      { destination: parseCidr('10.3.0.0/16'), attachmentIds: ['tgw-attach-y'], type: 'static', state: 'active' },
    ],
  };

  it('uses longest prefix, including blackhole routes', () => {
    expect(lookupTgwRoute(table, ip('10.2.1.1'), noLists)?.attachmentIds).toEqual(['tgw-attach-c']);
    expect(lookupTgwRoute(table, ip('10.2.9.1'), noLists)?.state).toBe('blackhole');
  });

  it('prefers static over propagated for the same prefix', () => {
    expect(lookupTgwRoute(table, ip('10.3.1.1'), noLists)?.attachmentIds).toEqual(['tgw-attach-y']);
  });
});
