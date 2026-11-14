/**
 * Network ACL evaluation.
 *
 * Documented behaviour this file implements
 * (https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html,
 *  https://docs.aws.amazon.com/vpc/latest/userguide/nacl-rules.html):
 *  - Inbound and outbound rules are evaluated separately.
 *  - Rules are evaluated starting with the lowest rule number; the first match
 *    decides, whether it allows or denies.
 *  - The `*` rule (reported by the API as rule number 32767) denies anything
 *    that matched no other rule.
 *  - NACLs are stateless: return traffic is evaluated as its own packet.
 *  - IPv4 rules never apply to IPv6 traffic and vice versa.
 *
 * Callers decide whether a NACL applies at all; traffic between two interfaces
 * in the same subnet does not cross a subnet boundary and is not filtered.
 */
import { rangeContains } from './ipv4.js';
import { hasPorts, icmpMatches, portInRange, protocolMatches } from './packet.js';
import { PROTO_ICMP } from './types.js';
import type { Nacl, NaclEntry, Packet, PortRange, ProtocolNumber } from './types.js';

export interface NaclDecision {
  action: 'allow' | 'deny';
  entry: NaclEntry;
}

/** The API always returns the `*` rules, but a hand-written snapshot may not. */
const IMPLICIT_STAR = (egress: boolean): NaclEntry => ({
  ruleNumber: 32767,
  egress,
  action: 'deny',
  protocol: '-1',
  cidr: { start: 0, end: 0xffffffff, prefixLength: 0, text: '0.0.0.0/0' },
});

function orderedEntries(nacl: Nacl, egress: boolean): NaclEntry[] {
  return nacl.entries.filter((e) => e.egress === egress && e.cidr !== undefined).sort((a, b) => a.ruleNumber - b.ruleNumber);
}

function entryMatches(entry: NaclEntry, peerIp: number, pkt: Packet): boolean {
  if (!entry.cidr || !rangeContains(entry.cidr, peerIp)) return false;
  if (!protocolMatches(entry.protocol, pkt.protocol)) return false;
  if (entry.protocol === '-1') return true;
  if (hasPorts(entry.protocol)) return portInRange(pkt.port, entry.portRange);
  if (entry.protocol === PROTO_ICMP) return icmpMatches(entry.icmp?.type, entry.icmp?.code, pkt);
  return true;
}

/**
 * Evaluates one packet.
 * @param egress  true for outbound rules (packet leaving the subnet)
 * @param peerIp  the address on the other side: the source for inbound
 *                traffic, the destination for outbound traffic
 */
export function evaluateNacl(nacl: Nacl, egress: boolean, peerIp: number, pkt: Packet): NaclDecision {
  for (const entry of orderedEntries(nacl, egress)) {
    if (entryMatches(entry, peerIp, pkt)) return { action: entry.action, entry };
  }
  return { action: 'deny', entry: IMPLICIT_STAR(egress) };
}

export interface NaclSegment {
  range: PortRange;
  action: 'allow' | 'deny';
  entry: NaclEntry;
}

/**
 * Evaluates a whole port range at once (used for return traffic, whose
 * destination port is a client-chosen ephemeral port). The result covers the
 * input range exactly, in ascending order, with each segment labelled by the
 * rule that decided it.
 */
export function evaluateNaclPortRange(
  nacl: Nacl,
  egress: boolean,
  peerIp: number,
  protocol: ProtocolNumber,
  range: PortRange,
): NaclSegment[] {
  let pending: PortRange[] = [{ ...range }];
  const decided: NaclSegment[] = [];
  const entries = [...orderedEntries(nacl, egress), IMPLICIT_STAR(egress)];

  for (const entry of entries) {
    if (pending.length === 0) break;
    if (!entry.cidr || !rangeContains(entry.cidr, peerIp)) continue;
    if (!protocolMatches(entry.protocol, protocol)) continue;
    const ruleRange: PortRange = entry.protocol !== '-1' && hasPorts(entry.protocol) && entry.portRange ? entry.portRange : { from: 0, to: 65535 };

    const stillPending: PortRange[] = [];
    for (const p of pending) {
      const from = Math.max(p.from, ruleRange.from);
      const to = Math.min(p.to, ruleRange.to);
      if (from > to) {
        stillPending.push(p);
        continue;
      }
      decided.push({ range: { from, to }, action: entry.action, entry });
      if (p.from < from) stillPending.push({ from: p.from, to: from - 1 });
      if (to < p.to) stillPending.push({ from: to + 1, to: p.to });
    }
    pending = stillPending;
  }
  return decided.sort((a, b) => a.range.from - b.range.from);
}
