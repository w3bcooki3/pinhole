/**
 * Follows the routing of one packet from a subnet towards a destination IPv4
 * address, across VPC peering and transit gateways, and records every NACL
 * that the packet crosses, in the order it crosses them.
 *
 * The walk does not evaluate NACL rules itself. It returns NACL checkpoints
 * (subnet, direction, peer address) so that the same walk serves the forward
 * packet (one port) and the return traffic (a range of ephemeral ports).
 *
 * Documented behaviour used here:
 * - Route selection: routes.ts.
 * - Traffic between two interfaces in the same subnet does not cross a subnet
 *   boundary, so no NACL applies
 *   (https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html:
 *   NACLs control traffic entering and leaving a subnet).
 * - Peering is not transitive and has no edge-to-edge routing: the destination
 *   must be inside the peer VPC's CIDRs
 *   (https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html).
 * - Transit gateway: the VPC attachment's associated route table decides; only
 *   resources in AZs with an attachment subnet can reach the TGW; inside the
 *   destination VPC, traffic enters through the attachment subnet and is routed
 *   by that subnet's route table
 *   (https://docs.aws.amazon.com/vpc/latest/tgw/how-transit-gateways-work.html).
 * - TGW NACL evaluation by subnet layout
 *   (https://docs.aws.amazon.com/vpc/latest/tgw/tgw-nacls.html):
 *     instance -> TGW: instance subnet outbound (dest IP), TGW subnet inbound
 *       (source IP). If they are the same subnet, that subnet's outbound and
 *       inbound rules are both evaluated.
 *     TGW -> instance: TGW subnet outbound (dest IP), instance subnet inbound
 *       (source IP). If they are the same subnet, no NACL is evaluated.
 */
import { DOCS } from './docs.js';
import { formatIpv4, INTERNET, rangeContains } from './ipv4.js';
import { lookupRoute, lookupTgwRoute } from './routes.js';
import type { PeerRelation } from './sg.js';
import { attachedIgw, routeTableForSubnet, subnetContaining, vpcContains } from './topology.js';
import type { NetworkModel, Route, Subnet, TgwAttachment } from './types.js';

export type Stage =
  | 'resolve'
  | 'source-sg-egress'
  | 'source-nacl-egress'
  | 'route'
  | 'peering'
  | 'tgw-attachment'
  | 'tgw-route'
  | 'tgw-nacl'
  | 'dest-vpc-route'
  | 'public-ip'
  | 'igw'
  | 'dest-nacl-ingress'
  | 'dest-sg-ingress'
  | 'return-route'
  | 'return-nacl'
  | 'scope';

export interface Hop {
  stage: Stage;
  decision: 'pass' | 'block' | 'unknown' | 'info';
  /** The AWS resource this step is about (route table, NACL, SG, pcx-, tgw-...). */
  resourceId: string;
  detail: string;
  /** NACL rule numbers or SG rule IDs that decided this step. */
  ruleIds?: string[];
  /** Other resources this step involves, e.g. the target of a route. */
  relatedIds?: string[];
  docUrl?: string;
}

export interface NaclCheckpoint {
  subnetId: string;
  egress: boolean;
  /** Address on the far side: destination for outbound, source for inbound. */
  peerIp: number;
  stage: Stage;
}

export type WalkStep = { kind: 'hop'; hop: Hop } | { kind: 'nacl'; check: NaclCheckpoint };

export type WalkEnd =
  | { kind: 'delivered'; vpcId: string; subnet: Subnet; relation: PeerRelation }
  /** Left the modelled network through a gateway (internet, NAT, VPN...). */
  | { kind: 'egress'; vpcId: string; target: Route['target'] }
  | { kind: 'blocked'; stage: Stage; resourceId: string; detail: string; docUrl?: string }
  | { kind: 'unknown'; stage: Stage; resourceId: string; detail: string; docUrl?: string };

export interface Walk {
  steps: WalkStep[];
  end: WalkEnd;
}

const hop = (h: Hop): WalkStep => ({ kind: 'hop', hop: h });
const nacl = (check: NaclCheckpoint): WalkStep => ({ kind: 'nacl', check });

function routeDetail(rtId: string, route: Route, matched: string): string {
  const dest = route.destinationPrefixListId ? `${route.destinationPrefixListId} (entry ${matched})` : matched;
  return `${rtId}: ${dest} -> ${route.target.id}${route.origin === 'propagated' ? ' (propagated)' : ''}`;
}

/** Picks the attachment subnet in `az`, if the attachment has one there. */
function attachmentSubnetInAz(model: NetworkModel, att: TgwAttachment, az: string): Subnet | undefined {
  for (const id of att.subnetIds) {
    const s = model.subnets.get(id);
    if (s && s.availabilityZone === az) return s;
  }
  return undefined;
}

/**
 * Delivers a packet that has arrived in `vpcId` (from a peering connection or
 * a TGW attachment ENI) to the subnet holding `dstIp`.
 */
function deliverInVpc(model: NetworkModel, vpcId: string, dstIp: number): Subnet | undefined {
  return subnetContaining(model, vpcId, dstIp);
}

export function walkRoute(model: NetworkModel, from: Subnet, srcIp: number, dstIp: number): Walk {
  const steps: WalkStep[] = [];
  const srcEgress: NaclCheckpoint = { subnetId: from.id, egress: true, peerIp: dstIp, stage: 'source-nacl-egress' };
  steps.push(nacl(srcEgress));
  const dstText = formatIpv4(dstIp);

  const end = (e: WalkEnd): Walk => ({ steps, end: e });

  const rt = routeTableForSubnet(model, from);
  if (!rt) {
    return end({ kind: 'unknown', stage: 'route', resourceId: from.id, detail: `No route table found for ${from.id} (no association and no main table in the snapshot).` });
  }
  const match = lookupRoute(rt, dstIp, model.prefixLists);
  if (!match) {
    return end({ kind: 'blocked', stage: 'route', resourceId: rt.id, detail: `${rt.id} has no route matching ${dstText}.`, docUrl: DOCS.routePriority });
  }
  const r = match.route;
  if (r.state === 'blackhole') {
    steps.push(hop({ stage: 'route', decision: 'block', resourceId: rt.id, relatedIds: [r.target.id], detail: `${routeDetail(rt.id, r, match.matchedCidr.text)} is a blackhole route`, docUrl: DOCS.routePriority }));
    return end({ kind: 'blocked', stage: 'route', resourceId: rt.id, detail: `Best route for ${dstText} in ${rt.id} is a blackhole (${r.target.id}).`, docUrl: DOCS.routePriority });
  }
  steps.push(hop({ stage: 'route', decision: 'pass', resourceId: rt.id, relatedIds: [r.target.id], detail: routeDetail(rt.id, r, match.matchedCidr.text), docUrl: DOCS.routePriority }));

  switch (r.target.type) {
    case 'local': {
      const dst = subnetContaining(model, from.vpcId, dstIp);
      if (!dst) {
        return end({ kind: 'blocked', stage: 'route', resourceId: from.vpcId, detail: `${dstText} is inside ${from.vpcId} but in no subnet.` });
      }
      if (dst.id === from.id) {
        // Same subnet: drop the outbound NACL checkpoint we added optimistically.
        steps.splice(steps.findIndex((s) => s.kind === 'nacl' && s.check === srcEgress), 1);
        steps.push(hop({ stage: 'route', decision: 'info', resourceId: dst.id, detail: `Source and destination are both in ${dst.id}; network ACLs are not evaluated.`, docUrl: DOCS.naclBasics }));
      } else {
        steps.push(nacl({ subnetId: dst.id, egress: false, peerIp: srcIp, stage: 'dest-nacl-ingress' }));
      }
      return end({ kind: 'delivered', vpcId: from.vpcId, subnet: dst, relation: { kind: 'same-vpc' } });
    }

    case 'pcx': {
      const pcx = model.peerings.get(r.target.id);
      if (!pcx) {
        return end({ kind: 'unknown', stage: 'peering', resourceId: r.target.id, detail: `Peering connection ${r.target.id} is not in the snapshot.` });
      }
      if (pcx.status !== 'active') {
        steps.push(hop({ stage: 'peering', decision: 'block', resourceId: pcx.id, detail: `${pcx.id} is ${pcx.status}, not active.`, docUrl: DOCS.peeringBasics }));
        return end({ kind: 'blocked', stage: 'peering', resourceId: pcx.id, detail: `${pcx.id} is ${pcx.status}.`, docUrl: DOCS.peeringBasics });
      }
      const outbound = pcx.requesterVpcId === from.vpcId;
      const peerVpcId = outbound ? pcx.accepterVpcId : pcx.requesterVpcId;
      const peerCidrs = outbound ? pcx.accepterCidrs : pcx.requesterCidrs;
      if (pcx.requesterVpcId !== from.vpcId && pcx.accepterVpcId !== from.vpcId) {
        return end({ kind: 'blocked', stage: 'peering', resourceId: pcx.id, detail: `${pcx.id} does not connect ${from.vpcId}.`, docUrl: DOCS.peeringBasics });
      }
      if (!peerCidrs.some((c) => rangeContains(c, dstIp))) {
        steps.push(hop({ stage: 'peering', decision: 'block', resourceId: pcx.id, detail: `${dstText} is not in peer ${peerVpcId} (${peerCidrs.map((c) => c.text).join(', ')}); peering is not transitive.`, docUrl: DOCS.peeringBasics }));
        return end({ kind: 'blocked', stage: 'peering', resourceId: pcx.id, detail: `${dstText} is outside ${peerVpcId}; VPC peering does not forward to other networks.`, docUrl: DOCS.peeringBasics });
      }
      steps.push(hop({ stage: 'peering', decision: 'pass', resourceId: pcx.id, detail: `${pcx.id} to ${peerVpcId}`, docUrl: DOCS.peeringBasics }));
      if (!model.vpcs.has(peerVpcId)) {
        return end({ kind: 'unknown', stage: 'peering', resourceId: peerVpcId, detail: `Peer ${peerVpcId} is in another account or Region and not in this snapshot.` });
      }
      const dst = deliverInVpc(model, peerVpcId, dstIp);
      if (!dst) return end({ kind: 'blocked', stage: 'peering', resourceId: peerVpcId, detail: `${dstText} is in no subnet of ${peerVpcId}.` });
      steps.push(nacl({ subnetId: dst.id, egress: false, peerIp: srcIp, stage: 'dest-nacl-ingress' }));
      const crossRegion = !!pcx.requesterRegion && !!pcx.accepterRegion && pcx.requesterRegion !== pcx.accepterRegion;
      return end({ kind: 'delivered', vpcId: peerVpcId, subnet: dst, relation: { kind: 'peering', crossRegion } });
    }

    case 'tgw': {
      const tgwId = r.target.id;
      const srcAtt = [...model.tgwAttachments.values()].find((a) => a.tgwId === tgwId && a.resourceType === 'vpc' && a.resourceId === from.vpcId);
      if (!srcAtt || srcAtt.state !== 'available') {
        return end({ kind: 'blocked', stage: 'tgw-attachment', resourceId: tgwId, detail: `${from.vpcId} has no available attachment to ${tgwId}.`, docUrl: DOCS.tgwVpcAttachments });
      }
      const srcTgwSubnet = attachmentSubnetInAz(model, srcAtt, from.availabilityZone);
      if (!srcTgwSubnet) {
        steps.push(hop({ stage: 'tgw-attachment', decision: 'block', resourceId: srcAtt.id, detail: `${srcAtt.id} has no subnet in ${from.availabilityZone}.`, docUrl: DOCS.tgwHowItWorks }));
        return end({ kind: 'blocked', stage: 'tgw-attachment', resourceId: srcAtt.id, detail: `Resources in ${from.availabilityZone} cannot reach ${tgwId}: ${srcAtt.id} has no subnet in that AZ.`, docUrl: DOCS.tgwHowItWorks });
      }
      steps.push(hop({ stage: 'tgw-attachment', decision: 'pass', resourceId: srcAtt.id, relatedIds: [tgwId], detail: `${srcAtt.id} via ${srcTgwSubnet.id}`, docUrl: DOCS.tgwVpcAttachments }));
      // instance -> TGW: TGW subnet inbound, using the source IP.
      steps.push(nacl({ subnetId: srcTgwSubnet.id, egress: false, peerIp: srcIp, stage: 'tgw-nacl' }));

      const tgwRtbId = srcAtt.associatedRouteTableId;
      const tgwRtb = tgwRtbId ? model.tgwRouteTables.get(tgwRtbId) : undefined;
      if (!tgwRtbId) {
        return end({ kind: 'blocked', stage: 'tgw-route', resourceId: srcAtt.id, detail: `${srcAtt.id} is not associated with a transit gateway route table.`, docUrl: DOCS.tgwRouteTables });
      }
      if (!tgwRtb || !tgwRtb.routesKnown) {
        return end({ kind: 'unknown', stage: 'tgw-route', resourceId: tgwRtbId, detail: `Routes of ${tgwRtbId} are not in the snapshot (shared transit gateway or missing permission).` });
      }
      const tr = lookupTgwRoute(tgwRtb, dstIp, model.prefixLists);
      if (!tr) {
        return end({ kind: 'blocked', stage: 'tgw-route', resourceId: tgwRtb.id, detail: `${tgwRtb.id} has no route matching ${dstText}.`, docUrl: DOCS.tgwRouteTables });
      }
      if (tr.state === 'blackhole') {
        steps.push(hop({ stage: 'tgw-route', decision: 'block', resourceId: tgwRtb.id, detail: `${tgwRtb.id}: ${tr.matchedCidr.text} is a ${tr.type} blackhole route`, docUrl: DOCS.tgwRouteTables }));
        return end({ kind: 'blocked', stage: 'tgw-route', resourceId: tgwRtb.id, detail: `Best route for ${dstText} in ${tgwRtb.id} is a blackhole.`, docUrl: DOCS.tgwRouteTables });
      }
      const dstAttId = tr.attachmentIds[0];
      const dstAtt = dstAttId ? model.tgwAttachments.get(dstAttId) : undefined;
      steps.push(hop({
        stage: 'tgw-route',
        decision: 'pass',
        resourceId: tgwRtb.id,
        relatedIds: [tgwId, ...tr.attachmentIds],
        detail: `${tgwRtb.id}: ${tr.matchedCidr.text} -> ${tr.attachmentIds.join(', ')} (${tr.type})${tr.attachmentIds.length > 1 ? '; ECMP, first attachment followed' : ''}`,
        docUrl: DOCS.tgwRouteTables,
      }));
      if (!dstAtt) {
        return end({ kind: 'unknown', stage: 'tgw-route', resourceId: dstAttId ?? tgwRtb.id, detail: `Attachment ${dstAttId ?? '(none)'} is not in the snapshot.` });
      }
      steps.push(hop({ stage: 'tgw-route', decision: 'pass', resourceId: dstAtt.id, detail: `${dstAtt.id} (${dstAtt.resourceType} ${dstAtt.resourceId})` }));
      if (dstAtt.resourceType !== 'vpc') {
        return end({ kind: 'unknown', stage: 'scope', resourceId: dstAtt.id, detail: `Transit gateway forwards to a ${dstAtt.resourceType} attachment; v1 only follows VPC attachments.`, docUrl: DOCS.tgwHowItWorks });
      }
      const dstVpcId = dstAtt.resourceId;
      if (!model.vpcs.has(dstVpcId)) {
        return end({ kind: 'unknown', stage: 'tgw-route', resourceId: dstVpcId, detail: `${dstVpcId} is in another account and not in this snapshot.` });
      }
      if (!vpcContains(model, dstVpcId, dstIp)) {
        return end({ kind: 'unknown', stage: 'scope', resourceId: dstVpcId, detail: `${dstText} is not inside ${dstVpcId}; onward routing from the attachment subnet is not modelled in v1.` });
      }
      const dstSubnet = deliverInVpc(model, dstVpcId, dstIp);
      if (!dstSubnet) return end({ kind: 'blocked', stage: 'tgw-route', resourceId: dstVpcId, detail: `${dstText} is in no subnet of ${dstVpcId}.` });

      // The TGW uses its interface in the destination's AZ when there is one,
      // otherwise an interface in another AZ (how-transit-gateways-work).
      const dstTgwSubnet = attachmentSubnetInAz(model, dstAtt, dstSubnet.availabilityZone) ?? dstAtt.subnetIds.map((id) => model.subnets.get(id)).find((s): s is Subnet => !!s);
      if (!dstTgwSubnet) {
        return end({ kind: 'unknown', stage: 'tgw-attachment', resourceId: dstAtt.id, detail: `Subnets of ${dstAtt.id} are not in the snapshot.` });
      }
      // Inside the destination VPC the attachment subnet's route table decides.
      const dstRt = routeTableForSubnet(model, dstTgwSubnet);
      const inner = dstRt ? lookupRoute(dstRt, dstIp, model.prefixLists) : undefined;
      if (!dstRt || !inner) {
        return end({ kind: 'blocked', stage: 'dest-vpc-route', resourceId: dstRt?.id ?? dstTgwSubnet.id, detail: `No route for ${dstText} from attachment subnet ${dstTgwSubnet.id}.` });
      }
      if (inner.route.target.type !== 'local' || inner.route.state !== 'active') {
        return end({
          kind: 'unknown',
          stage: 'scope',
          resourceId: dstRt.id,
          detail: `Attachment subnet ${dstTgwSubnet.id} routes ${dstText} to ${inner.route.target.id} (middlebox or inspection path); not modelled in v1.`,
          docUrl: DOCS.gwlbRouting,
        });
      }
      steps.push(hop({ stage: 'dest-vpc-route', decision: 'pass', resourceId: dstRt.id, detail: `${routeDetail(dstRt.id, inner.route, inner.matchedCidr.text)} from attachment subnet ${dstTgwSubnet.id}` }));

      const tgw = model.transitGateways.get(tgwId);
      const relation: PeerRelation = { kind: 'tgw', sgReferencing: !!tgw?.sgReferencing && srcAtt.sgReferencing && dstAtt.sgReferencing };
      if (dstTgwSubnet.id !== dstSubnet.id) {
        // TGW -> instance in different subnets: TGW subnet outbound, then instance subnet inbound.
        steps.push(nacl({ subnetId: dstTgwSubnet.id, egress: true, peerIp: dstIp, stage: 'tgw-nacl' }));
        steps.push(nacl({ subnetId: dstSubnet.id, egress: false, peerIp: srcIp, stage: 'dest-nacl-ingress' }));
      } else {
        steps.push(hop({ stage: 'tgw-nacl', decision: 'info', resourceId: dstSubnet.id, detail: `Destination shares ${dstSubnet.id} with the TGW attachment; NACLs are not evaluated for TGW -> instance.`, docUrl: DOCS.tgwNacls }));
      }
      return end({ kind: 'delivered', vpcId: dstVpcId, subnet: dstSubnet, relation });
    }

    case 'igw': {
      const igw = model.internetGateways.get(r.target.id);
      if (!igw || igw.vpcId !== from.vpcId) {
        return end({ kind: 'blocked', stage: 'route', resourceId: r.target.id, detail: `${r.target.id} is not attached to ${from.vpcId}.`, docUrl: DOCS.igw });
      }
      if (!INTERNET.containsIp(dstIp)) {
        return end({ kind: 'blocked', stage: 'route', resourceId: r.target.id, detail: `${dstText} is not an internet address; an internet gateway does not forward it.`, docUrl: DOCS.igw });
      }
      return end({ kind: 'egress', vpcId: from.vpcId, target: r.target });
    }

    default:
      // NAT gateway, VPN gateway, endpoint, interface/instance (middlebox), etc.
      return end({ kind: 'egress', vpcId: from.vpcId, target: r.target });
  }
}

/** Convenience: true if the subnet's route for `ip` leads to the VPC's attached IGW. */
export function routesToIgw(model: NetworkModel, subnet: Subnet, ip: number): boolean {
  const rt = routeTableForSubnet(model, subnet);
  const m = rt ? lookupRoute(rt, ip, model.prefixLists) : undefined;
  return !!m && m.route.state === 'active' && m.route.target.type === 'igw' && m.route.target.id === attachedIgw(model, subnet.vpcId);
}
