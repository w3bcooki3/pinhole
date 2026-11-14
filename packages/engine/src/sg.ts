/**
 * Security group evaluation.
 *
 * Documented behaviour (https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html):
 *  - Rules only allow; anything not allowed is denied.
 *  - All rules of all groups on an interface are aggregated into one set.
 *  - A source/destination is a CIDR, a prefix list, or a security group.
 *  - A security group reference matches traffic by the PRIVATE IP addresses of
 *    the interfaces that belong to the referenced group. Internet clients have
 *    no interface in the account, so they never match a reference.
 *  - Inbound references may point to the same VPC, a peered VPC, or a VPC
 *    attached to the same transit gateway; outbound references only to the same
 *    or a peered VPC.
 *  - Groups are stateful, so callers evaluate only the direction that opens
 *    the connection (https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html).
 *
 * Transit gateway references additionally require the referencing support
 * option on the transit gateway and the VPC attachment
 * (https://docs.aws.amazon.com/vpc/latest/tgw/tgw-vpc-attachments.html).
 */
import { rangeContains } from './ipv4.js';
import { hasPorts, icmpMatches, protocolMatches } from './packet.js';
import { PROTO_ICMP } from './types.js';
import type { Packet, PrefixList, SecurityGroup, SgRule } from './types.js';

/** How the peer reaches (or is reached from) the interface being evaluated. */
export type PeerRelation =
  | { kind: 'same-vpc' }
  /** crossRegion: references to groups across an inter-Region peering do not work. */
  | { kind: 'peering'; crossRegion?: boolean }
  | { kind: 'tgw'; sgReferencing: boolean }
  | { kind: 'external' };

export interface SgPeer {
  ip: number;
  /** Groups of the peer interface, when the peer is an interface we know. */
  groupIds?: string[];
  relation: PeerRelation;
}

export interface SgDecision {
  allowed: boolean;
  /** Every rule that admits the packet; all of them, since rules are OR'ed. */
  matched: SgRule[];
  /** Prefix lists referenced by candidate rules whose entries we could not read. */
  unknownPrefixLists: string[];
}

function portOrIcmpMatches(rule: SgRule, pkt: Packet): boolean {
  if (rule.protocol === '-1') return true;
  if (hasPorts(rule.protocol)) {
    // The API reports -1/-1 for "all ports" on some rules.
    if (rule.fromPort === undefined || rule.fromPort === -1) return true;
    return pkt.port !== undefined && pkt.port >= rule.fromPort && pkt.port <= (rule.toPort ?? rule.fromPort);
  }
  if (rule.protocol === PROTO_ICMP) return icmpMatches(rule.fromPort, rule.toPort, pkt);
  return true;
}

function referenceAllowed(direction: 'ingress' | 'egress', relation: PeerRelation): boolean {
  switch (relation.kind) {
    case 'same-vpc':
      return true;
    case 'peering':
      // https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-security-groups.html
      return relation.crossRegion !== true;
    case 'tgw':
      return direction === 'ingress' && relation.sgReferencing;
    case 'external':
      return false;
  }
}

type PeerMatch = 'match' | 'no-match' | 'unknown';

function peerMatches(rule: SgRule, direction: 'ingress' | 'egress', peer: SgPeer, prefixLists: Map<string, PrefixList>): PeerMatch {
  if (rule.cidr) return rangeContains(rule.cidr, peer.ip) ? 'match' : 'no-match';
  if (rule.prefixListId) {
    const pl = prefixLists.get(rule.prefixListId);
    if (!pl || !pl.entriesKnown) return 'unknown';
    return pl.entries.some((c) => rangeContains(c, peer.ip)) ? 'match' : 'no-match';
  }
  if (rule.referencedGroupId) {
    if (!peer.groupIds?.includes(rule.referencedGroupId)) return 'no-match';
    return referenceAllowed(direction, peer.relation) ? 'match' : 'no-match';
  }
  // IPv6-only rule: never matches IPv4 traffic.
  return 'no-match';
}

export function evaluateSg(
  groups: SecurityGroup[],
  direction: 'ingress' | 'egress',
  peer: SgPeer,
  pkt: Packet,
  prefixLists: Map<string, PrefixList>,
): SgDecision {
  const matched: SgRule[] = [];
  const unknown = new Set<string>();
  for (const g of groups) {
    for (const rule of direction === 'ingress' ? g.ingress : g.egress) {
      if (!protocolMatches(rule.protocol, pkt.protocol)) continue;
      if (!portOrIcmpMatches(rule, pkt)) continue;
      const m = peerMatches(rule, direction, peer, prefixLists);
      if (m === 'match') matched.push(rule);
      else if (m === 'unknown' && rule.prefixListId) unknown.add(rule.prefixListId);
    }
  }
  return { allowed: matched.length > 0, matched, unknownPrefixLists: [...unknown] };
}
