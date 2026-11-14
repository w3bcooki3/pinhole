/**
 * Lookups over the model that several evaluators need: which route table and
 * NACL govern a subnet, which subnet holds an address, which interface owns an
 * address.
 */
import { formatIpv4, parseIpv4, rangeContains } from './ipv4.js';
import type { Eni, Nacl, NetworkModel, RouteTable, Subnet } from './types.js';

/**
 * A subnet uses its explicitly associated route table, or else the VPC's main
 * route table (https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html).
 */
export function routeTableForSubnet(model: NetworkModel, subnet: Subnet): RouteTable | undefined {
  let main: RouteTable | undefined;
  for (const rt of model.routeTables.values()) {
    if (rt.subnetIds.includes(subnet.id)) return rt;
    if (rt.vpcId === subnet.vpcId && rt.isMain) main = rt;
  }
  return main;
}

/**
 * A subnet is always associated with exactly one NACL; without an explicit
 * association it uses the VPC's default NACL
 * (https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html).
 */
export function naclForSubnet(model: NetworkModel, subnet: Subnet): Nacl | undefined {
  let fallback: Nacl | undefined;
  for (const n of model.nacls.values()) {
    if (n.subnetIds.includes(subnet.id)) return n;
    if (n.vpcId === subnet.vpcId && n.isDefault) fallback = n;
  }
  return fallback;
}

export function subnetContaining(model: NetworkModel, vpcId: string, ip: number): Subnet | undefined {
  for (const s of model.subnets.values()) {
    if (s.vpcId === vpcId && rangeContains(s.cidr, ip)) return s;
  }
  return undefined;
}

export function vpcContains(model: NetworkModel, vpcId: string, ip: number): boolean {
  return model.vpcs.get(vpcId)?.cidrs.some((c) => rangeContains(c, ip)) ?? false;
}

export function eniByPrivateIp(model: NetworkModel, ip: number): Eni | undefined {
  const text = formatIpv4(ip);
  for (const e of model.enis.values()) if (e.privateIps.includes(text)) return e;
  return undefined;
}

export function primaryIp(eni: Eni): number | undefined {
  const first = eni.privateIps[0];
  return first ? parseIpv4(first) : undefined;
}

/** True for interfaces that belong to an Elastic Load Balancing node. */
export function isElbNode(eni: Eni): boolean {
  return eni.interfaceType === 'network_load_balancer' || eni.interfaceType === 'gateway_load_balancer' || eni.description.startsWith('ELB ');
}

export function attachedIgw(model: NetworkModel, vpcId: string): string | undefined {
  for (const g of model.internetGateways.values()) if (g.vpcId === vpcId) return g.id;
  return undefined;
}

export function displayName(model: NetworkModel, eni: Eni): string {
  if (eni.instanceId) {
    const inst = model.instances.get(eni.instanceId);
    return inst?.name ? `${inst.name} (${eni.instanceId}, ${eni.id})` : `${eni.instanceId} (${eni.id})`;
  }
  return eni.description ? `${eni.id} (${eni.description})` : eni.id;
}
