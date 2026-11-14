// Small builders so unit tests read like the AWS console rather than like JSON.
import { parseCidr } from '../src/ipv4.js';
import type { Nacl, NaclEntry, Route, RouteTable, SecurityGroup, SgRule } from '../src/types.js';

export const TCP = '6';
export const UDP = '17';
export const ICMP = '1';
export const ALL = '-1';

export function naclEntry(
  ruleNumber: number,
  egress: boolean,
  action: 'allow' | 'deny',
  protocol: string,
  cidr: string,
  ports?: [number, number],
): NaclEntry {
  return {
    ruleNumber,
    egress,
    action,
    protocol,
    cidr: parseCidr(cidr),
    ...(ports ? { portRange: { from: ports[0], to: ports[1] } } : {}),
  };
}

/** Builds a NACL and appends the `*` deny rules the API reports as 32767. */
export function nacl(id: string, entries: NaclEntry[]): Nacl {
  const star = (egress: boolean): NaclEntry => naclEntry(32767, egress, 'deny', ALL, '0.0.0.0/0');
  return {
    id,
    vpcId: 'vpc-1',
    isDefault: false,
    entries: [...entries, star(false), star(true)].sort((a, b) => a.ruleNumber - b.ruleNumber),
    subnetIds: [],
  };
}

let ruleSeq = 0;
export function sgRule(groupId: string, egress: boolean, protocol: string, from: number | undefined, to: number | undefined, source: Partial<SgRule>): SgRule {
  ruleSeq += 1;
  return {
    id: `sgr-${groupId.replace('sg-', '')}${egress ? 'e' : 'i'}${ruleSeq}`,
    groupId,
    egress,
    protocol,
    ...(from !== undefined ? { fromPort: from } : {}),
    ...(to !== undefined ? { toPort: to } : {}),
    ...source,
  };
}

export function sg(id: string, ingress: SgRule[], egress: SgRule[] = []): SecurityGroup {
  return { id, name: id, vpcId: 'vpc-1', ingress, egress };
}

export function route(dest: string, type: Route['target']['type'], id: string, extra: Partial<Route> = {}): Route {
  return {
    destination: parseCidr(dest),
    target: { type, id },
    state: 'active',
    origin: type === 'local' ? 'local' : 'static',
    ...extra,
  };
}

export function routeTable(id: string, routes: Route[]): RouteTable {
  return { id, vpcId: 'vpc-1', isMain: false, subnetIds: [], gatewayIds: [], routes };
}
