/**
 * Route selection for VPC and transit gateway route tables.
 *
 * VPC (https://docs.aws.amazon.com/vpc/latest/userguide/route-tables-priority.html):
 *  1. Longest prefix match, regardless of route type.
 *  2. On an exact tie: static routes, then prefix-list routes, then propagated
 *     routes. (Finer VPN/Direct Connect ordering among propagated routes is not
 *     modelled; such targets are reported as out of scope anyway.)
 *  A matching route in the "blackhole" state is still the selected route; the
 *  packet is dropped. The caller reports that.
 *
 * Transit gateway (https://docs.aws.amazon.com/vpc/latest/tgw/how-transit-gateways-work.html,
 * "Route evaluation order"): longest prefix first; for the same prefix, static
 * routes, then prefix-list routes, then propagated routes. Ordering among
 * propagated route types (VPC, Direct Connect, VPN, BGP attributes) is not
 * modelled because v1 only follows VPC attachments.
 */
import { rangeContains } from './ipv4.js';
import type { Cidr, PrefixList, Route, RouteTable, TgwRoute, TgwRouteTable } from './types.js';

export interface RouteMatch {
  route: Route;
  /** The CIDR that matched: the route's own, or the prefix-list entry. */
  matchedCidr: Cidr;
}

/** Ranking within equal prefix lengths; lower wins. */
function tieRank(route: Route): number {
  if (route.destinationPrefixListId) return 1;
  if (route.origin === 'propagated') return 2;
  return 0; // local and static
}

function bestPrefixListEntry(listId: string, ip: number, lists: Map<string, PrefixList>): Cidr | undefined {
  const pl = lists.get(listId);
  if (!pl) return undefined;
  let best: Cidr | undefined;
  for (const c of pl.entries) {
    if (rangeContains(c, ip) && (!best || c.prefixLength > best.prefixLength)) best = c;
  }
  return best;
}

export function lookupRoute(table: RouteTable, ip: number, prefixLists: Map<string, PrefixList>): RouteMatch | undefined {
  let best: RouteMatch | undefined;
  for (const route of table.routes) {
    const cidr = route.destination
      ? rangeContains(route.destination, ip)
        ? route.destination
        : undefined
      : route.destinationPrefixListId
        ? bestPrefixListEntry(route.destinationPrefixListId, ip, prefixLists)
        : undefined;
    if (!cidr) continue;
    if (
      !best ||
      cidr.prefixLength > best.matchedCidr.prefixLength ||
      (cidr.prefixLength === best.matchedCidr.prefixLength && tieRank(route) < tieRank(best.route))
    ) {
      best = { route, matchedCidr: cidr };
    }
  }
  return best;
}

export interface TgwRouteMatch extends TgwRoute {
  matchedCidr: Cidr;
}

export function lookupTgwRoute(table: TgwRouteTable, ip: number, prefixLists: Map<string, PrefixList>): TgwRouteMatch | undefined {
  let best: TgwRouteMatch | undefined;
  // Same prefix: static, then prefix-list routes, then propagated.
  const rank = (r: TgwRoute) => (r.prefixListId ? 1 : r.type === 'static' ? 0 : 2);
  for (const route of table.routes) {
    const cidr = route.destination
      ? rangeContains(route.destination, ip)
        ? route.destination
        : undefined
      : route.prefixListId
        ? bestPrefixListEntry(route.prefixListId, ip, prefixLists)
        : undefined;
    if (!cidr) continue;
    if (
      !best ||
      cidr.prefixLength > best.matchedCidr.prefixLength ||
      (cidr.prefixLength === best.matchedCidr.prefixLength && rank(route) < rank(best))
    ) {
      best = { ...route, matchedCidr: cidr };
    }
  }
  return best;
}
