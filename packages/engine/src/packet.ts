/**
 * Protocol names and the rule/packet matching shared by NACLs and SGs.
 */
import { PROTO_ALL, PROTO_ICMP, PROTO_TCP, PROTO_UDP } from './types.js';
import type { Packet, PortRange, ProtocolNumber } from './types.js';

const NAMES: Record<string, ProtocolNumber> = {
  all: PROTO_ALL,
  '-1': PROTO_ALL,
  tcp: PROTO_TCP,
  udp: PROTO_UDP,
  icmp: PROTO_ICMP,
  icmpv6: '58',
};

/**
 * Converts any protocol spelling the EC2 API uses ("tcp", "6", "-1", "all")
 * into the numeric string form.
 */
export function normalizeProtocol(value: string | number | undefined): ProtocolNumber {
  if (value === undefined) return PROTO_ALL;
  const s = String(value).toLowerCase();
  const named = NAMES[s];
  if (named) return named;
  if (/^\d+$/.test(s)) return String(Number(s));
  throw new Error(`Unknown IP protocol: "${value}"`);
}

export function protocolName(p: ProtocolNumber): string {
  switch (p) {
    case PROTO_ALL:
      return 'all';
    case PROTO_TCP:
      return 'tcp';
    case PROTO_UDP:
      return 'udp';
    case PROTO_ICMP:
      return 'icmp';
    default:
      return `proto-${p}`;
  }
}

/** True for protocols whose rules carry a port range. */
export function hasPorts(p: ProtocolNumber): boolean {
  return p === PROTO_TCP || p === PROTO_UDP;
}

export function protocolMatches(ruleProtocol: ProtocolNumber, packetProtocol: ProtocolNumber): boolean {
  return ruleProtocol === PROTO_ALL || ruleProtocol === packetProtocol;
}

export function portInRange(port: number | undefined, range: PortRange | undefined): boolean {
  if (range === undefined) return true;
  if (port === undefined) return false;
  return port >= range.from && port <= range.to;
}

/** ICMP type/code match where -1 is a wildcard on the rule side. */
export function icmpMatches(ruleType: number | undefined, ruleCode: number | undefined, pkt: Packet): boolean {
  if (ruleType !== undefined && ruleType !== -1 && ruleType !== pkt.icmpType) return false;
  if (ruleCode !== undefined && ruleCode !== -1 && ruleCode !== pkt.icmpCode) return false;
  return true;
}

export function describePacket(pkt: Packet): string {
  if (hasPorts(pkt.protocol)) return `${protocolName(pkt.protocol)}/${pkt.port}`;
  if (pkt.protocol === PROTO_ICMP) return `icmp type ${pkt.icmpType ?? 'any'}`;
  return protocolName(pkt.protocol);
}
