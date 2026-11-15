/**
 * Detects configuration that v1 does not model, so reports can say where
 * results may be incomplete instead of silently being wrong.
 *
 * Out of scope: the rules inside third-party appliances behind Gateway Load
 * Balancer endpoints (followed, assumed to pass, and marked), routes to
 * instances or interfaces acting as appliances, Global Accelerator,
 * CloudFront, Classic Load Balancers, and the on-premises side of VPN and
 * Direct Connect (followed up to the AWS gateway, then assumed to pass).
 */
import { DOCS } from './docs.js';
import type { NetworkModel, Warning } from './types.js';

export function detectOutOfScope(model: NetworkModel): Warning[] {
  const out: Warning[] = [];
  const add = (w: Warning) => out.push(w);

  const middlebox: string[] = [];
  const unknownVpce: string[] = [];
  const gwlbVpce: string[] = [];
  const vgw: string[] = [];
  for (const rt of model.routeTables.values()) {
    for (const r of rt.routes) {
      const t = r.target;
      if (t.type === 'eni' || t.type === 'instance') middlebox.push(`${rt.id} -> ${t.id}`);
      if (t.type === 'vpce') {
        const fw = [...model.firewalls.values()].some((f) => f.endpoints.some((e) => e.endpointId === t.id));
        const ep = model.vpcEndpoints.get(t.id);
        if (fw) continue;
        if (!ep) unknownVpce.push(`${rt.id} -> ${t.id}`);
        else if (ep.type === 'GatewayLoadBalancer') gwlbVpce.push(`${rt.id} -> ${t.id}`);
      }
      if (t.type === 'vgw') vgw.push(`${rt.id} -> ${t.id}`);
    }
    const unfollowed = rt.routes.filter((r) => r.target.type !== 'local' && !(r.target.type === 'vpce' && (model.vpcEndpoints.get(r.target.id)?.type === 'GatewayLoadBalancer' || [...model.firewalls.values()].some((f) => f.endpoints.some((e) => e.endpointId === r.target.id)))));
    if (rt.gatewayIds.length && unfollowed.length) {
      add({
        code: 'gateway-route-table',
        message: `${rt.id} is a gateway route table for ${rt.gatewayIds.join(', ')} and sends traffic to ${unfollowed.map((r) => r.target.id).join(', ')}, which Pinhole does not follow; exposure through it is reported as unknown.`,
        resourceIds: [rt.id, ...rt.gatewayIds],
        docUrl: DOCS.gatewayRouteTables,
      });
    }
  }
  if (middlebox.length) {
    add({ code: 'middlebox-route', message: `Routes send traffic to a network interface or instance (appliance or NAT instance); paths through them are not followed: ${middlebox.join('; ')}.`, resourceIds: middlebox, docUrl: DOCS.gwlbRouting });
  }
  if (unknownVpce.length) {
    add({ code: 'network-firewall-or-unknown-endpoint', message: `Routes target VPC endpoints that are not in the snapshot; these are usually AWS Network Firewall endpoints, collected with the network-firewall permissions. Paths through them are not followed: ${unknownVpce.join('; ')}.`, resourceIds: unknownVpce, docUrl: DOCS.networkFirewall });
  }
  if (gwlbVpce.length) {
    add({ code: 'third-party-appliance', message: `Routes send traffic to third-party appliances through Gateway Load Balancer endpoints. Paths through them are followed, but their rules are not visible to AWS APIs, so they are assumed to pass and marked on every path: ${gwlbVpce.join('; ')}.`, resourceIds: gwlbVpce, docUrl: DOCS.gwlbRouting });
  }
  if (vgw.length) {
    add({ code: 'vpn-or-direct-connect', message: `Routes target virtual private gateways (VPN / Direct Connect). Paths to and from on-premises are followed up to the gateway; on-premises routers and firewalls are not visible to AWS, so those paths assume they pass: ${vgw.join('; ')}.`, resourceIds: vgw, docUrl: DOCS.vpn });
  }

  const onPremAtt = [...model.tgwAttachments.values()].filter((a) => a.resourceType === 'vpn' || a.resourceType === 'direct-connect-gateway');
  if (onPremAtt.length) {
    add({ code: 'vpn-or-direct-connect', message: `Transit gateway attachments lead on-premises. Paths over them are followed up to the transit gateway; on-premises routers and firewalls are not visible to AWS, so those paths assume they pass: ${onPremAtt.map((a) => `${a.id} (${a.resourceType})`).join('; ')}.`, resourceIds: onPremAtt.map((a) => a.id), docUrl: DOCS.tgwVpn });
  }

  const gwlbs = [...model.loadBalancers.values()].filter((l) => l.type === 'gateway');
  if (gwlbs.length) {
    add({ code: 'gateway-load-balancer', message: 'Gateway Load Balancers are present; the appliances behind them are not analysed.', resourceIds: gwlbs.map((l) => l.arn), docUrl: DOCS.gwlbRouting });
  }
  const ga = [...model.enis.values()].filter((e) => e.interfaceType === 'global_accelerator_managed');
  if (ga.length) {
    add({ code: 'global-accelerator', message: 'Global Accelerator interfaces are present; internet reachability through accelerators is not modelled.', resourceIds: ga.map((e) => e.id), docUrl: DOCS.globalAccelerator });
  }
  // Classic Load Balancer nodes carry the description "ELB <name>"; v2 nodes
  // use "ELB app/...", "ELB net/..." or "ELB gwy/...". Classic ones are not collected.
  const classic = new Map<string, string[]>();
  for (const e of model.enis.values()) {
    const m = /^ELB ([^/]+)$/.exec(e.description);
    if (m) classic.set(m[1]!, [...(classic.get(m[1]!) ?? []), e.id]);
  }
  if (classic.size) {
    add({ code: 'classic-load-balancer', message: `Classic Load Balancers are present and not analysed: ${[...classic.keys()].join(', ')}. Their listeners may be reachable from the internet.`, resourceIds: [...classic.values()].flat(), docUrl: DOCS.classicElb });
  }
  const cf = [...model.prefixLists.values()].filter((p) => p.name.includes('cloudfront'));
  const cfUsed = cf.filter((p) => [...model.securityGroups.values()].some((g) => g.ingress.some((r) => r.prefixListId === p.id)));
  if (cfUsed.length) {
    add({ code: 'cloudfront', message: 'Security groups allow the CloudFront origin-facing prefix list. These origins are reachable from CloudFront edge addresses; CloudFront distributions themselves are not modelled.', resourceIds: cfUsed.map((p) => p.id), docUrl: DOCS.cloudfrontPrefixList });
  }

  // Dual-stack listeners are analysed over IPv6 too. Only a snapshot that does not record the
  // load balancer's IP address type (collected before this was read) leaves it open.
  const ipv6 = [...model.loadBalancers.values()].filter((lb) => lb.scheme === 'internet-facing' && !lb.ipAddressType && model.vpcs.get(lb.vpcId)?.ipv6CidrTexts.length).map((lb) => lb.name);
  if (ipv6.length) {
    add({ code: 'ipv6-load-balancer', message: 'The snapshot does not say whether these internet-facing load balancers are dual-stack, so they are analysed for IPv4 only. Collect again to include IPv6.', resourceIds: ipv6 });
  }

  for (const t of model.tgwRouteTables.values()) {
    if (!t.routesKnown) {
      add({ code: 'tgw-routes-missing', message: `Routes of ${t.id} were not collected; paths through it are reported as unknown.`, resourceIds: [t.id] });
    }
  }
  for (const p of model.peerings.values()) {
    for (const v of [p.requesterVpcId, p.accepterVpcId]) {
      if (v && !model.vpcs.has(v)) {
        add({ code: 'peer-outside-snapshot', message: `${p.id} connects to ${v}, which is in another account or Region; paths into it are reported as unknown.`, resourceIds: [p.id, v] });
      }
    }
  }
  return out;
}
