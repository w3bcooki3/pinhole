/**
 * On-premises networks: what AWS can see of the far side of Site-to-Site VPN
 * and Direct Connect.
 *
 * Traffic reaches a VPC from on-premises through a virtual private gateway
 * attached to the VPC, or through a VPN or Direct Connect gateway attachment
 * of a transit gateway (https://docs.aws.amazon.com/vpn/latest/s2svpn/how_it_works.html,
 * https://docs.aws.amazon.com/vpc/latest/tgw/tgw-vpn-attachments.html).
 * The on-premises address ranges are what AWS routes there: VPC routes to a
 * virtual private gateway (static or propagated from BGP), transit gateway
 * routes to a VPN or Direct Connect attachment, and the static routes of VPN
 * connections. On-premises routers and firewalls are not visible to AWS, so
 * every path through these links carries that as a caveat.
 */
import { RangeSet } from './ipv4.js';
import type { IpRange, NetworkModel, TgwAttachment, VpnConnection } from './types.js';

export interface OnPremLink {
  /** vgw-... for a virtual private gateway, the attachment ID for a transit gateway. */
  id: string;
  kind: 'vpn' | 'direct-connect' | 'vpn-or-direct-connect';
  /** The virtual private gateway, or the transit gateway. */
  gateway: string;
  attachment?: TgwAttachment;
  /** VPCs a virtual private gateway is attached to. */
  vpcIds: string[];
  connections: VpnConnection[];
  /** Every tunnel of every VPN connection on the link was down when the snapshot was taken. */
  down: boolean;
}

export interface OnPremNetwork {
  range: IpRange;
  /** Links AWS routes this range to. */
  links: string[];
  /** Where the range was learned: route tables and VPN connections. */
  from: string[];
}

const live = (c: VpnConnection) => c.state !== 'deleted' && c.state !== 'deleting';
const isDown = (cs: VpnConnection[]) => cs.length > 0 && cs.every((c) => c.state !== 'available' || (c.tunnels > 0 && c.tunnelsUp === 0));

export function onPremLinks(model: NetworkModel): OnPremLink[] {
  const out: OnPremLink[] = [];
  const vgwIds = new Set<string>(model.vpnGateways.keys());
  for (const rt of model.routeTables.values()) for (const r of rt.routes) if (r.target.type === 'vgw') vgwIds.add(r.target.id);
  for (const id of vgwIds) {
    const connections = [...model.vpnConnections.values()].filter((c) => c.vgwId === id && live(c));
    const vgw = model.vpnGateways.get(id);
    const vpcIds = vgw ? vgw.vpcIds : [...new Set([...model.routeTables.values()].filter((rt) => rt.routes.some((r) => r.target.type === 'vgw' && r.target.id === id)).map((rt) => rt.vpcId))];
    out.push({ id, kind: connections.length ? 'vpn' : 'vpn-or-direct-connect', gateway: id, vpcIds, connections, down: isDown(connections) });
  }
  for (const a of model.tgwAttachments.values()) {
    if (a.resourceType !== 'vpn' && a.resourceType !== 'direct-connect-gateway') continue;
    if (a.state === 'deleted' || a.state === 'deleting') continue;
    const connections = a.resourceType === 'vpn' ? [...model.vpnConnections.values()].filter((c) => c.id === a.resourceId && live(c)) : [];
    out.push({ id: a.id, kind: a.resourceType === 'vpn' ? 'vpn' : 'direct-connect', gateway: a.tgwId, attachment: a, vpcIds: [], connections, down: isDown(connections) });
  }
  return out;
}

/** The link a walk that left through `target` (and, for a transit gateway, `attachment`) uses, if it is one. */
export function linkOf(model: NetworkModel, target: { type: string; id: string }, attachment?: TgwAttachment): OnPremLink | undefined {
  const id = target.type === 'vgw' ? target.id : target.type === 'tgw' && attachment ? attachment.id : undefined;
  return id ? onPremLinks(model).find((l) => l.id === id) : undefined;
}

export function onPremNetworks(model: NetworkModel): OnPremNetwork[] {
  const acc = new Map<string, OnPremNetwork>();
  const add = (range: IpRange, link: string, from: string) => {
    const k = `${range.start}-${range.end}`;
    const cur = acc.get(k) ?? acc.set(k, { range, links: [], from: [] }).get(k)!;
    if (!cur.links.includes(link)) cur.links.push(link);
    if (!cur.from.includes(from)) cur.from.push(from);
  };
  const ranges = (cidr: IpRange | undefined, pl: string | undefined): IpRange[] => (cidr ? [cidr] : pl ? model.prefixLists.get(pl)?.entries ?? [] : []);
  for (const rt of model.routeTables.values()) {
    if (rt.gatewayIds.length) continue;
    for (const r of rt.routes) if (r.target.type === 'vgw' && r.state === 'active') for (const c of ranges(r.destination, r.destinationPrefixListId)) add(c, r.target.id, rt.id);
  }
  const onPremAtt = new Map([...model.tgwAttachments.values()].filter((a) => a.resourceType === 'vpn' || a.resourceType === 'direct-connect-gateway').map((a) => [a.id, a]));
  for (const t of model.tgwRouteTables.values()) {
    for (const r of t.routes) {
      if (r.state !== 'active') continue;
      for (const id of r.attachmentIds) if (onPremAtt.has(id)) for (const c of ranges(r.destination, r.prefixListId)) add(c, id, t.id);
    }
  }
  for (const v of model.vpnConnections.values()) {
    if (!live(v)) continue;
    const link = v.vgwId ?? [...onPremAtt.values()].find((a) => a.resourceId === v.id)?.id;
    if (link) for (const c of v.staticRoutes) add(c, link, v.id);
  }
  return [...acc.values()].sort((a, b) => a.range.start - b.range.start || b.range.end - a.range.end);
}

/** Every address AWS routes to an on-premises link. */
export function onPremSpace(model: NetworkModel): RangeSet {
  return RangeSet.of(onPremNetworks(model).map((n) => n.range));
}

export function describeLink(l: OnPremLink): string {
  const what = l.kind === 'vpn' ? 'Site-to-Site VPN' : l.kind === 'direct-connect' ? 'Direct Connect' : 'VPN or Direct Connect';
  const conns = l.connections.map((c) => `${c.id}${c.tunnels ? `, ${c.tunnelsUp} of ${c.tunnels} tunnels up` : ''}`);
  const on = l.attachment ? `${l.attachment.id} on ${l.gateway}` : l.gateway;
  return `${what} through ${on}${conns.length ? ` (${conns.join('; ')})` : ''}`;
}

export const ONPREM_CAVEAT = 'On-premises routers and firewalls are not visible to AWS; this assumes the on-premises network routes the traffic over this link and lets it through.';
