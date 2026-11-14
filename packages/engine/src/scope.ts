/**
 * Detects configuration that v1 does not model, so reports can say where
 * results may be incomplete instead of silently being wrong.
 *
 * Out of scope for v1: AWS Network Firewall, Gateway Load Balancer, IPv6
 * (including egress-only internet gateways), Global Accelerator, CloudFront,
 * Classic Load Balancers, VPN/Direct Connect paths, and ingress routing
 * through appliances.
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
        const ep = model.vpcEndpoints.get(t.id);
        if (!ep) unknownVpce.push(`${rt.id} -> ${t.id}`);
        else if (ep.type === 'GatewayLoadBalancer') gwlbVpce.push(`${rt.id} -> ${t.id}`);
      }
      if (t.type === 'vgw') vgw.push(`${rt.id} -> ${t.id}`);
    }
    if (rt.gatewayIds.length) {
      add({
        code: 'gateway-route-table',
        message: `${rt.id} is a gateway route table for ${rt.gatewayIds.join(', ')}. Traffic entering through that gateway may be steered through an appliance; exposure through it is reported as unknown.`,
        resourceIds: [rt.id, ...rt.gatewayIds],
        docUrl: DOCS.gatewayRouteTables,
      });
    }
  }
  if (middlebox.length) {
    add({ code: 'middlebox-route', message: `Routes send traffic to a network interface or instance (appliance or NAT instance); paths through them are not followed: ${middlebox.join('; ')}.`, resourceIds: middlebox, docUrl: DOCS.gwlbRouting });
  }
  if (unknownVpce.length) {
    add({ code: 'network-firewall-or-unknown-endpoint', message: `Routes target VPC endpoints that are not in the snapshot; these are usually AWS Network Firewall endpoints. Inspection is not modelled: ${unknownVpce.join('; ')}.`, resourceIds: unknownVpce, docUrl: DOCS.networkFirewall });
  }
  if (gwlbVpce.length) {
    add({ code: 'gateway-load-balancer', message: `Routes target Gateway Load Balancer endpoints; inspection is not modelled: ${gwlbVpce.join('; ')}.`, resourceIds: gwlbVpce, docUrl: DOCS.gwlbRouting });
  }
  if (vgw.length) {
    add({ code: 'vpn-or-direct-connect', message: `Routes target virtual private gateways (VPN / Direct Connect); on-premises paths are not modelled: ${vgw.join('; ')}.`, resourceIds: vgw, docUrl: DOCS.vpn });
  }

  const gwlbEnis = [...model.enis.values()].filter((e) => e.interfaceType === 'gateway_load_balancer' || e.interfaceType === 'gateway_load_balancer_endpoint');
  const gwlbs = [...model.loadBalancers.values()].filter((l) => l.type === 'gateway');
  if (gwlbEnis.length || gwlbs.length) {
    add({ code: 'gateway-load-balancer', message: 'Gateway Load Balancers or their endpoints are present; traffic inspection through them is not modelled.', resourceIds: [...gwlbs.map((l) => l.arn), ...gwlbEnis.map((e) => e.id)], docUrl: DOCS.gwlbRouting });
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

  const ipv6 = [...model.loadBalancers.values()].filter((lb) => lb.scheme === 'internet-facing' && model.vpcs.get(lb.vpcId)?.ipv6CidrTexts.length).map((lb) => lb.name);
  if (ipv6.length) {
    add({ code: 'ipv6-load-balancer', message: 'Internet-facing load balancers in VPCs with IPv6 are analysed for IPv4 only; dual-stack listeners may also be reachable over IPv6.', resourceIds: ipv6 });
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
