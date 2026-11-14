/**
 * Converts a raw snapshot into the NetworkModel the evaluator works on.
 *
 * Everything that needs interpreting AWS field conventions lives here, so the
 * evaluator can assume clean data: numeric protocol strings, parsed CIDRs,
 * route targets classified by type, NACL entries sorted.
 */
import { isIpv4Cidr, parseCidr } from './ipv4.js';
import { normalizeProtocol } from './packet.js';
import type { RawAction, RawIpPermission, RawRoute, Snapshot } from './snapshot.js';
import { assertSnapshot } from './snapshot.js';
import type {
  Cidr,
  Eni,
  NaclEntry,
  NetworkModel,
  Route,
  RouteTargetType,
  SgRule,
  TargetGroup,
  Warning,
} from './types.js';

/**
 * An Elastic IP is owned by an account (12 digits). Auto-assigned public IPs
 * report the owner "amazon", load balancer node addresses "amazon-elb".
 */
function isAccountOwner(owner: string | undefined): boolean {
  return owner !== undefined && /^\d{12}$/.test(owner);
}

function tagName(tags: { Key?: string; Value?: string }[] | undefined): string | undefined {
  return tags?.find((t) => t.Key === 'Name')?.Value;
}

function tryCidr(text: string | undefined, warnings: Warning[], resourceId: string): Cidr | undefined {
  if (!text || !isIpv4Cidr(text)) return undefined;
  try {
    return parseCidr(text);
  } catch {
    warnings.push({ code: 'bad-cidr', message: `Could not parse CIDR "${text}".`, resourceIds: [resourceId] });
    return undefined;
  }
}

function classifyTarget(r: RawRoute): { type: RouteTargetType; id: string } {
  const gw = r.GatewayId;
  if (gw === 'local') return { type: 'local', id: 'local' };
  if (r.NatGatewayId) return { type: 'nat', id: r.NatGatewayId };
  if (r.VpcPeeringConnectionId) return { type: 'pcx', id: r.VpcPeeringConnectionId };
  if (r.TransitGatewayId) return { type: 'tgw', id: r.TransitGatewayId };
  if (r.EgressOnlyInternetGatewayId) return { type: 'eigw', id: r.EgressOnlyInternetGatewayId };
  if (r.NetworkInterfaceId) return { type: 'eni', id: r.NetworkInterfaceId };
  if (r.InstanceId) return { type: 'instance', id: r.InstanceId };
  if (gw?.startsWith('igw-')) return { type: 'igw', id: gw };
  if (gw?.startsWith('vgw-')) return { type: 'vgw', id: gw };
  if (gw?.startsWith('vpce-')) return { type: 'vpce', id: gw };
  const other = gw ?? r.CarrierGatewayId ?? r.LocalGatewayId ?? r.CoreNetworkArn ?? 'unknown';
  return { type: 'other', id: other };
}

function routeOrigin(r: RawRoute): Route['origin'] {
  if (r.Origin === 'CreateRouteTable' || r.GatewayId === 'local') return 'local';
  if (r.Origin === 'EnableVgwRoutePropagation') return 'propagated';
  return 'static';
}

/** Expands the classic IpPermissions shape into one rule per source. */
function rulesFromPermissions(groupId: string, perms: RawIpPermission[] | undefined, egress: boolean): SgRule[] {
  const out: SgRule[] = [];
  (perms ?? []).forEach((p, i) => {
    const base = {
      groupId,
      egress,
      protocol: normalizeProtocol(p.IpProtocol),
      ...(p.FromPort !== undefined ? { fromPort: p.FromPort } : {}),
      ...(p.ToPort !== undefined ? { toPort: p.ToPort } : {}),
    };
    // Synthetic IDs: stable and readable, but clearly not real sgr- IDs.
    let j = 0;
    const id = () => `${groupId}:${egress ? 'egress' : 'ingress'}:${i}.${j++}`;
    for (const r of p.IpRanges ?? []) {
      if (r.CidrIp && isIpv4Cidr(r.CidrIp)) out.push({ ...base, id: id(), cidr: parseCidr(r.CidrIp), ...(r.Description ? { description: r.Description } : {}) });
    }
    for (const r of p.Ipv6Ranges ?? []) {
      if (r.CidrIpv6) out.push({ ...base, id: id(), ipv6CidrText: r.CidrIpv6 });
    }
    for (const r of p.PrefixListIds ?? []) {
      if (r.PrefixListId) out.push({ ...base, id: id(), prefixListId: r.PrefixListId });
    }
    for (const r of p.UserIdGroupPairs ?? []) {
      if (r.GroupId) {
        out.push({
          ...base,
          id: id(),
          referencedGroupId: r.GroupId,
          ...(r.VpcId ? { referencedVpcId: r.VpcId } : {}),
          ...(r.VpcPeeringConnectionId ? { referencedPeeringConnectionId: r.VpcPeeringConnectionId } : {}),
        });
      }
    }
  });
  return out;
}

function forwardTargets(actions: RawAction[] | undefined): string[] {
  const arns: string[] = [];
  for (const a of actions ?? []) {
    if (a.Type !== 'forward') continue;
    if (a.TargetGroupArn) arns.push(a.TargetGroupArn);
    for (const tg of a.ForwardConfig?.TargetGroups ?? []) if (tg.TargetGroupArn) arns.push(tg.TargetGroupArn);
  }
  return arns;
}

/**
 * ELB node interfaces carry the description "ELB <type>/<name>/<id>", where
 * the second part is the tail of the load balancer ARN.
 */
function elbEniDescription(lbArn: string): string | undefined {
  const m = /:loadbalancer\/((?:app|net|gwy)\/[^/]+\/[^/]+)$/.exec(lbArn);
  return m ? `ELB ${m[1]}` : undefined;
}

export function normalize(input: unknown): NetworkModel {
  assertSnapshot(input);
  const snap: Snapshot = input;
  const ec2 = snap.ec2 ?? {};
  const elb = snap.elbv2 ?? {};
  const warnings: Warning[] = [];

  const model: NetworkModel = {
    ...(snap.accountId ? { accountId: snap.accountId } : {}),
    ...(snap.region ? { region: snap.region } : {}),
    vpcs: new Map(),
    subnets: new Map(),
    routeTables: new Map(),
    nacls: new Map(),
    securityGroups: new Map(),
    prefixLists: new Map(),
    internetGateways: new Map(),
    natGateways: new Map(),
    peerings: new Map(),
    transitGateways: new Map(),
    tgwAttachments: new Map(),
    tgwRouteTables: new Map(),
    enis: new Map(),
    instances: new Map(),
    loadBalancers: new Map(),
    listeners: [],
    targetGroups: new Map(),
    vpcEndpoints: new Map(),
    warnings,
  };

  for (const e of snap.errors ?? []) {
    warnings.push({
      code: 'collection-error',
      message: `Collector could not read ${e.api}: ${e.message}. Results involving this data may be incomplete.`,
      resourceIds: [],
    });
  }

  // ---- VPCs and subnets
  for (const v of ec2.Vpcs ?? []) {
    const texts = new Set<string>();
    for (const a of v.CidrBlockAssociationSet ?? []) {
      const state = a.CidrBlockState?.State;
      if (a.CidrBlock && (!state || state === 'associated')) texts.add(a.CidrBlock);
    }
    if (texts.size === 0 && v.CidrBlock) texts.add(v.CidrBlock);
    model.vpcs.set(v.VpcId, {
      id: v.VpcId,
      cidrs: [...texts].map((t) => tryCidr(t, warnings, v.VpcId)).filter((c): c is Cidr => !!c),
      ipv6CidrTexts: (v.Ipv6CidrBlockAssociationSet ?? []).map((a) => a.Ipv6CidrBlock).filter((x): x is string => !!x),
      ...(v.OwnerId ? { ownerId: v.OwnerId } : {}),
    });
  }
  for (const s of ec2.Subnets ?? []) {
    const cidr = tryCidr(s.CidrBlock, warnings, s.SubnetId);
    if (!cidr) continue;
    model.subnets.set(s.SubnetId, {
      id: s.SubnetId,
      vpcId: s.VpcId,
      cidr,
      availabilityZone: s.AvailabilityZone ?? '',
      ...(s.AvailabilityZoneId ? { availabilityZoneId: s.AvailabilityZoneId } : {}),
    });
  }

  // ---- Prefix lists (needed by routes and SG rules)
  const entriesById = ec2.PrefixListEntries ?? {};
  const listIds = new Set<string>([...(ec2.ManagedPrefixLists ?? []).map((p) => p.PrefixListId), ...Object.keys(entriesById)]);
  for (const id of listIds) {
    const meta = (ec2.ManagedPrefixLists ?? []).find((p) => p.PrefixListId === id);
    const raw = entriesById[id];
    const entries: Cidr[] = [];
    let hasIpv6 = false;
    for (const e of raw ?? []) {
      if (e.Cidr && isIpv4Cidr(e.Cidr)) entries.push(parseCidr(e.Cidr));
      else if (e.Cidr) hasIpv6 = true;
    }
    model.prefixLists.set(id, { id, name: meta?.PrefixListName ?? id, entries, entriesKnown: raw !== undefined, hasIpv6Entries: hasIpv6 });
  }

  // ---- Route tables
  for (const rt of ec2.RouteTables ?? []) {
    const routes: Route[] = [];
    for (const r of rt.Routes ?? []) {
      if (!r.DestinationCidrBlock && !r.DestinationPrefixListId) continue; // IPv6-only route
      const destination = tryCidr(r.DestinationCidrBlock, warnings, rt.RouteTableId);
      if (r.DestinationCidrBlock && !destination) continue;
      routes.push({
        ...(destination ? { destination } : {}),
        ...(r.DestinationPrefixListId && !destination ? { destinationPrefixListId: r.DestinationPrefixListId } : {}),
        target: classifyTarget(r),
        state: r.State === 'blackhole' ? 'blackhole' : 'active',
        origin: routeOrigin(r),
      });
    }
    const assoc = (rt.Associations ?? []).filter((a) => !a.AssociationState?.State || a.AssociationState.State === 'associated');
    model.routeTables.set(rt.RouteTableId, {
      id: rt.RouteTableId,
      vpcId: rt.VpcId,
      isMain: assoc.some((a) => a.Main === true),
      subnetIds: assoc.map((a) => a.SubnetId).filter((x): x is string => !!x),
      gatewayIds: assoc.map((a) => a.GatewayId).filter((x): x is string => !!x),
      routes,
    });
  }

  // ---- Network ACLs
  for (const n of ec2.NetworkAcls ?? []) {
    const entries: NaclEntry[] = [];
    for (const e of n.Entries ?? []) {
      const cidr = tryCidr(e.CidrBlock, warnings, n.NetworkAclId);
      const protocol = normalizeProtocol(e.Protocol);
      entries.push({
        ruleNumber: e.RuleNumber,
        egress: e.Egress,
        action: e.RuleAction === 'allow' ? 'allow' : 'deny',
        protocol,
        ...(cidr ? { cidr } : {}),
        ...(e.Ipv6CidrBlock ? { ipv6CidrText: e.Ipv6CidrBlock } : {}),
        ...(e.PortRange && e.PortRange.From !== undefined ? { portRange: { from: e.PortRange.From, to: e.PortRange.To ?? e.PortRange.From } } : {}),
        ...(e.IcmpTypeCode ? { icmp: { type: e.IcmpTypeCode.Type ?? -1, code: e.IcmpTypeCode.Code ?? -1 } } : {}),
      });
    }
    entries.sort((a, b) => a.ruleNumber - b.ruleNumber);
    model.nacls.set(n.NetworkAclId, {
      id: n.NetworkAclId,
      vpcId: n.VpcId,
      isDefault: n.IsDefault === true,
      entries,
      subnetIds: (n.Associations ?? []).map((a) => a.SubnetId).filter((x): x is string => !!x),
    });
  }

  // ---- Security groups. Prefer DescribeSecurityGroupRules because it carries
  // the sgr- rule IDs we cite in findings.
  const rulesByGroup = new Map<string, SgRule[]>();
  for (const r of ec2.SecurityGroupRules ?? []) {
    const rule: SgRule = {
      id: r.SecurityGroupRuleId,
      groupId: r.GroupId,
      egress: r.IsEgress,
      protocol: normalizeProtocol(r.IpProtocol),
      ...(r.FromPort !== undefined ? { fromPort: r.FromPort } : {}),
      ...(r.ToPort !== undefined ? { toPort: r.ToPort } : {}),
      ...(r.CidrIpv4 ? { cidr: parseCidr(r.CidrIpv4) } : {}),
      ...(r.CidrIpv6 ? { ipv6CidrText: r.CidrIpv6 } : {}),
      ...(r.PrefixListId ? { prefixListId: r.PrefixListId } : {}),
      ...(r.ReferencedGroupInfo?.GroupId ? { referencedGroupId: r.ReferencedGroupInfo.GroupId } : {}),
      ...(r.ReferencedGroupInfo?.VpcId ? { referencedVpcId: r.ReferencedGroupInfo.VpcId } : {}),
      ...(r.ReferencedGroupInfo?.VpcPeeringConnectionId ? { referencedPeeringConnectionId: r.ReferencedGroupInfo.VpcPeeringConnectionId } : {}),
      ...(r.Description ? { description: r.Description } : {}),
    };
    const list = rulesByGroup.get(r.GroupId) ?? [];
    list.push(rule);
    rulesByGroup.set(r.GroupId, list);
  }
  for (const g of ec2.SecurityGroups ?? []) {
    const fromRulesApi = rulesByGroup.get(g.GroupId);
    const rules = fromRulesApi ?? [...rulesFromPermissions(g.GroupId, g.IpPermissions, false), ...rulesFromPermissions(g.GroupId, g.IpPermissionsEgress, true)];
    model.securityGroups.set(g.GroupId, {
      id: g.GroupId,
      name: g.GroupName ?? g.GroupId,
      vpcId: g.VpcId ?? '',
      ingress: rules.filter((r) => !r.egress),
      egress: rules.filter((r) => r.egress),
    });
  }

  // ---- Gateways
  for (const g of ec2.InternetGateways ?? []) {
    const att = (g.Attachments ?? []).find((a) => a.State === 'available' || a.State === 'attached');
    model.internetGateways.set(g.InternetGatewayId, { id: g.InternetGatewayId, ...(att?.VpcId ? { vpcId: att.VpcId } : {}) });
  }
  for (const n of ec2.NatGateways ?? []) {
    model.natGateways.set(n.NatGatewayId, {
      id: n.NatGatewayId,
      vpcId: n.VpcId,
      subnetId: n.SubnetId,
      state: n.State ?? 'available',
      connectivity: n.ConnectivityType === 'private' ? 'private' : 'public',
    });
  }
  for (const p of ec2.VpcPeeringConnections ?? []) {
    const cidrs = (info: typeof p.RequesterVpcInfo) => {
      const texts = new Set<string>((info?.CidrBlockSet ?? []).map((c) => c.CidrBlock).filter((x): x is string => !!x));
      if (texts.size === 0 && info?.CidrBlock) texts.add(info.CidrBlock);
      return [...texts].map((t) => tryCidr(t, warnings, p.VpcPeeringConnectionId)).filter((c): c is Cidr => !!c);
    };
    model.peerings.set(p.VpcPeeringConnectionId, {
      id: p.VpcPeeringConnectionId,
      status: p.Status?.Code ?? 'unknown',
      requesterVpcId: p.RequesterVpcInfo?.VpcId ?? '',
      requesterCidrs: cidrs(p.RequesterVpcInfo),
      ...(p.RequesterVpcInfo?.Region ? { requesterRegion: p.RequesterVpcInfo.Region } : {}),
      accepterVpcId: p.AccepterVpcInfo?.VpcId ?? '',
      accepterCidrs: cidrs(p.AccepterVpcInfo),
      ...(p.AccepterVpcInfo?.Region ? { accepterRegion: p.AccepterVpcInfo.Region } : {}),
    });
  }

  // ---- Transit gateways
  for (const t of ec2.TransitGateways ?? []) {
    model.transitGateways.set(t.TransitGatewayId, { id: t.TransitGatewayId, sgReferencing: t.Options?.SecurityGroupReferencingSupport === 'enable' });
  }
  const vpcAttach = new Map((ec2.TransitGatewayVpcAttachments ?? []).map((a) => [a.TransitGatewayAttachmentId, a]));
  for (const a of ec2.TransitGatewayAttachments ?? []) {
    const va = vpcAttach.get(a.TransitGatewayAttachmentId);
    const assocState = a.Association?.State;
    model.tgwAttachments.set(a.TransitGatewayAttachmentId, {
      id: a.TransitGatewayAttachmentId,
      tgwId: a.TransitGatewayId,
      resourceType: a.ResourceType ?? 'unknown',
      resourceId: a.ResourceId ?? '',
      state: a.State ?? 'available',
      ...(a.Association?.TransitGatewayRouteTableId && (!assocState || assocState === 'associated')
        ? { associatedRouteTableId: a.Association.TransitGatewayRouteTableId }
        : {}),
      subnetIds: va?.SubnetIds ?? [],
      // The attachment option defaults to enabled (TGW VPC attachments guide);
      // the TGW-level option must also be on, which the evaluator checks.
      sgReferencing: va?.Options?.SecurityGroupReferencingSupport !== 'disable',
    });
  }
  const tgwRoutes = ec2.TransitGatewayRoutes ?? {};
  for (const t of ec2.TransitGatewayRouteTables ?? []) {
    const raw = tgwRoutes[t.TransitGatewayRouteTableId];
    model.tgwRouteTables.set(t.TransitGatewayRouteTableId, {
      id: t.TransitGatewayRouteTableId,
      tgwId: t.TransitGatewayId,
      routesKnown: raw !== undefined,
      routes: (raw ?? [])
        .filter((r) => r.DestinationCidrBlock ? isIpv4Cidr(r.DestinationCidrBlock) : !!r.PrefixListId)
        .map((r) => ({
          ...(r.DestinationCidrBlock ? { destination: parseCidr(r.DestinationCidrBlock) } : {}),
          ...(r.PrefixListId && !r.DestinationCidrBlock ? { prefixListId: r.PrefixListId } : {}),
          attachmentIds: (r.TransitGatewayAttachments ?? []).map((x) => x.TransitGatewayAttachmentId).filter((x): x is string => !!x),
          type: r.Type === 'propagated' ? 'propagated' : 'static',
          state: r.State === 'blackhole' ? 'blackhole' : 'active',
        })),
    });
  }

  // ---- Interfaces and instances
  for (const n of ec2.NetworkInterfaces ?? []) {
    const privs = [...(n.PrivateIpAddresses ?? [])].sort((a, b) => Number(b.Primary === true) - Number(a.Primary === true));
    const privateIps = privs.map((p) => p.PrivateIpAddress).filter((x): x is string => !!x);
    if (privateIps.length === 0 && n.PrivateIpAddress) privateIps.push(n.PrivateIpAddress);
    const publicAddresses: Eni['publicAddresses'] = [];
    for (const p of privs) {
      if (p.Association?.PublicIp && p.PrivateIpAddress) {
        publicAddresses.push({ publicIp: p.Association.PublicIp, privateIp: p.PrivateIpAddress, elastic: isAccountOwner(p.Association.IpOwnerId) });
      }
    }
    if (publicAddresses.length === 0 && n.Association?.PublicIp && privateIps[0]) {
      publicAddresses.push({ publicIp: n.Association.PublicIp, privateIp: privateIps[0], elastic: isAccountOwner(n.Association.IpOwnerId) });
    }
    model.enis.set(n.NetworkInterfaceId, {
      id: n.NetworkInterfaceId,
      subnetId: n.SubnetId,
      vpcId: n.VpcId,
      interfaceType: n.InterfaceType ?? 'interface',
      description: n.Description ?? '',
      requesterManaged: n.RequesterManaged === true,
      privateIps,
      publicAddresses,
      groupIds: (n.Groups ?? []).map((g) => g.GroupId).filter((x): x is string => !!x),
      ...(n.Attachment?.InstanceId ? { instanceId: n.Attachment.InstanceId } : {}),
      hasIpv6: (n.Ipv6Addresses ?? []).length > 0,
    });
  }
  for (const i of ec2.Instances ?? []) {
    const nics = i.NetworkInterfaces ?? [];
    const primary = nics.find((x) => x.Attachment?.DeviceIndex === 0) ?? nics[0];
    const name = tagName(i.Tags);
    model.instances.set(i.InstanceId, {
      id: i.InstanceId,
      ...(name ? { name } : {}),
      state: i.State?.Name ?? 'unknown',
      ...(primary?.NetworkInterfaceId ? { primaryEniId: primary.NetworkInterfaceId } : {}),
      eniIds: nics.map((x) => x.NetworkInterfaceId).filter((x): x is string => !!x),
    });
  }
  // Instances that were not collected still get a record from their ENIs.
  for (const eni of model.enis.values()) {
    if (eni.instanceId && !model.instances.has(eni.instanceId)) {
      model.instances.set(eni.instanceId, { id: eni.instanceId, state: 'unknown', primaryEniId: eni.id, eniIds: [eni.id] });
    }
  }

  for (const e of ec2.VpcEndpoints ?? []) {
    model.vpcEndpoints.set(e.VpcEndpointId, { id: e.VpcEndpointId, type: e.VpcEndpointType ?? 'unknown', serviceName: e.ServiceName ?? '', vpcId: e.VpcId ?? '' });
  }

  // ---- Load balancers
  for (const lb of elb.LoadBalancers ?? []) {
    const desc = elbEniDescription(lb.LoadBalancerArn);
    const nodeEnis = [...model.enis.values()].filter((e) => desc !== undefined && e.description === desc);
    const type = lb.Type === 'network' ? 'network' : lb.Type === 'gateway' ? 'gateway' : 'application';
    model.loadBalancers.set(lb.LoadBalancerArn, {
      arn: lb.LoadBalancerArn,
      name: lb.LoadBalancerName ?? lb.LoadBalancerArn,
      type,
      scheme: lb.Scheme === 'internal' ? 'internal' : 'internet-facing',
      vpcId: lb.VpcId ?? '',
      subnetIds: (lb.AvailabilityZones ?? []).map((z) => z.SubnetId).filter((x): x is string => !!x),
      securityGroupIds: lb.SecurityGroups ?? [],
      nodeIps: nodeEnis.flatMap((e) => e.privateIps.slice(0, 1)),
      nodeEniIds: nodeEnis.map((e) => e.id),
    });
  }
  const rulesByListener = new Map<string, string[]>();
  for (const r of elb.Rules ?? []) {
    if (!r.ListenerArn) continue;
    rulesByListener.set(r.ListenerArn, [...(rulesByListener.get(r.ListenerArn) ?? []), ...forwardTargets(r.Actions)]);
  }
  for (const l of elb.Listeners ?? []) {
    const tgs = new Set([...forwardTargets(l.DefaultActions), ...(rulesByListener.get(l.ListenerArn) ?? [])]);
    model.listeners.push({ arn: l.ListenerArn, loadBalancerArn: l.LoadBalancerArn, port: l.Port ?? 0, protocol: l.Protocol ?? 'TCP', targetGroupArns: [...tgs] });
  }
  for (const tg of elb.TargetGroups ?? []) {
    const attrs = elb.TargetGroupAttributes?.[tg.TargetGroupArn];
    const pci = attrs?.find((a) => a.Key === 'preserve_client_ip.enabled')?.Value;
    const targetType = (['instance', 'ip', 'lambda', 'alb'].includes(tg.TargetType ?? '') ? tg.TargetType : 'instance') as TargetGroup['targetType'];
    model.targetGroups.set(tg.TargetGroupArn, {
      arn: tg.TargetGroupArn,
      name: tg.TargetGroupName ?? tg.TargetGroupArn,
      ...(tg.Protocol ? { protocol: tg.Protocol } : {}),
      ...(tg.Port !== undefined ? { port: tg.Port } : {}),
      targetType,
      ...(tg.VpcId ? { vpcId: tg.VpcId } : {}),
      ...(tg.HealthCheckPort ? { healthCheckPort: tg.HealthCheckPort } : {}),
      ...(pci !== undefined ? { preserveClientIp: pci === 'true' } : {}),
      targets: (elb.TargetHealth?.[tg.TargetGroupArn] ?? [])
        .filter((t) => t.Target?.Id)
        .map((t) => ({
          id: t.Target!.Id!,
          ...(t.Target?.Port !== undefined ? { port: t.Target.Port } : {}),
          ...(t.Target?.AvailabilityZone ? { availabilityZone: t.Target.AvailabilityZone } : {}),
          ...(t.TargetHealth?.State ? { state: t.TargetHealth.State } : {}),
        })),
    });
  }

  return model;
}
