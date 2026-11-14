#!/usr/bin/env node
// A fake AWS backend that answers read-only API calls from a fixture snapshot.
//
// Used two ways:
//  - imported by collector.test.ts as the collector's `Send` function;
//  - executed as an `aws` binary on PATH to test scripts/cloudshell-collect.sh.
//    The fixture path comes from FAKE_AWS_SNAPSHOT; FAKE_AWS_FAIL lists
//    operations to fail with AccessDenied; FAKE_AWS_LOG records each call.
import { readFileSync, appendFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export class AccessDenied extends Error {
  constructor(op) {
    super(`User is not authorized to perform: ${op}`);
    this.name = 'UnauthorizedOperation';
  }
}

/** Answers one call. Lists are split into pages of `pageSize` to exercise pagination. */
export function respond(snap, service, op, input, pageSize = 1) {
  const ec2 = snap.ec2 ?? {};
  const elb = snap.elbv2 ?? {};
  const page = (key, list) => {
    const start = Number(input.NextToken ?? input.Marker ?? 0);
    const items = (list ?? []).slice(start, start + pageSize);
    const next = start + pageSize < (list ?? []).length ? String(start + pageSize) : undefined;
    return { [key]: items, ...(next ? (service === 'elbv2' ? { NextMarker: next } : { NextToken: next }) : {}) };
  };
  switch (`${service}:${op}`) {
    case 'sts:GetCallerIdentity': return { Account: snap.accountId ?? '111122223333' };
    case 'ec2:DescribeVpcs': return page('Vpcs', ec2.Vpcs);
    case 'ec2:DescribeSubnets': return page('Subnets', ec2.Subnets);
    case 'ec2:DescribeRouteTables': return page('RouteTables', ec2.RouteTables);
    case 'ec2:DescribeInternetGateways': return page('InternetGateways', ec2.InternetGateways);
    case 'ec2:DescribeEgressOnlyInternetGateways': return page('EgressOnlyInternetGateways', ec2.EgressOnlyInternetGateways);
    case 'ec2:DescribeNatGateways': return page('NatGateways', ec2.NatGateways);
    case 'ec2:DescribeVpcPeeringConnections': return page('VpcPeeringConnections', ec2.VpcPeeringConnections);
    case 'ec2:DescribeTransitGateways': return page('TransitGateways', ec2.TransitGateways);
    case 'ec2:DescribeTransitGatewayAttachments': return page('TransitGatewayAttachments', ec2.TransitGatewayAttachments);
    case 'ec2:DescribeTransitGatewayVpcAttachments': return page('TransitGatewayVpcAttachments', ec2.TransitGatewayVpcAttachments);
    case 'ec2:DescribeTransitGatewayRouteTables': return page('TransitGatewayRouteTables', ec2.TransitGatewayRouteTables);
    case 'ec2:SearchTransitGatewayRoutes': {
      // Not paginated in the real API: up to MaxResults, plus a flag when more exist.
      const all = (ec2.TransitGatewayRoutes ?? {})[input.TransitGatewayRouteTableId] ?? [];
      const max = Number(input.MaxResults ?? 1000);
      return { Routes: all.slice(0, max), AdditionalRoutesAvailable: all.length > max };
    }
    case 'ec2:DescribeNetworkAcls': return page('NetworkAcls', ec2.NetworkAcls);
    case 'ec2:DescribeSecurityGroups': return page('SecurityGroups', ec2.SecurityGroups);
    case 'ec2:DescribeSecurityGroupRules': return page('SecurityGroupRules', ec2.SecurityGroupRules);
    case 'ec2:DescribeManagedPrefixLists': return page('PrefixLists', ec2.ManagedPrefixLists);
    case 'ec2:GetManagedPrefixListEntries': return page('Entries', (ec2.PrefixListEntries ?? {})[input.PrefixListId]);
    case 'ec2:DescribeNetworkInterfaces': return page('NetworkInterfaces', ec2.NetworkInterfaces);
    case 'ec2:DescribeInstances': return page('Reservations', (ec2.Instances ?? []).map((i) => ({ Instances: [i] })));
    case 'ec2:DescribeVpcEndpoints': return page('VpcEndpoints', ec2.VpcEndpoints);
    case 'elbv2:DescribeLoadBalancers': return page('LoadBalancers', elb.LoadBalancers);
    case 'elbv2:DescribeListeners': return page('Listeners', (elb.Listeners ?? []).filter((l) => l.LoadBalancerArn === input.LoadBalancerArn));
    case 'elbv2:DescribeRules':
      return page('Rules', (elb.Rules ?? []).filter((r) => r.ListenerArn === input.ListenerArn).map(({ ListenerArn, ...r }) => r));
    case 'elbv2:DescribeTargetGroups': return page('TargetGroups', elb.TargetGroups);
    case 'elbv2:DescribeTargetHealth': return { TargetHealthDescriptions: (elb.TargetHealth ?? {})[input.TargetGroupArn] ?? [] };
    case 'elbv2:DescribeTargetGroupAttributes': return { Attributes: (elb.TargetGroupAttributes ?? {})[input.TargetGroupArn] ?? [] };
    default: throw new Error(`fake-aws: unexpected call ${service}:${op}`);
  }
}

// ---------------------------------------------------------------- CLI mode

const pascal = (kebab) => kebab.split('-').map((w) => w[0].toUpperCase() + w.slice(1)).join('');

function main(argv) {
  const [service, command, ...rest] = argv;
  const op = pascal(command);
  const input = {};
  let query;
  let output = 'json';
  for (let i = 0; i < rest.length; i += 2) {
    const flag = rest[i];
    const value = rest[i + 1];
    if (flag === '--region') continue;
    if (flag === '--output') { output = value; continue; }
    if (flag === '--query') { query = value; continue; }
    if (flag === '--filters') continue;
    input[pascal(flag.replace(/^--/, ''))] = value;
  }
  if (process.env.FAKE_AWS_LOG) appendFileSync(process.env.FAKE_AWS_LOG, `${service}:${op}\n`);
  if ((process.env.FAKE_AWS_FAIL ?? '').split(',').includes(op)) {
    process.stderr.write(`An error occurred (UnauthorizedOperation) when calling the ${op} operation: not authorized\n`);
    process.exit(254);
  }
  const snap = JSON.parse(readFileSync(process.env.FAKE_AWS_SNAPSHOT, 'utf8'));
  const svc = service === 'elbv2' ? 'elbv2' : service;
  // The real CLI follows pagination itself; emulate by using one big page.
  const res = respond(snap, svc, op, input, Number.MAX_SAFE_INTEGER);
  if (query === 'Account' && output === 'text') {
    process.stdout.write(`${res.Account}\n`);
    return;
  }
  process.stdout.write(JSON.stringify(res));
}

// Compare real paths: the test runs this file through an `aws` symlink.
if (process.argv[1] && fileURLToPath(import.meta.url) === realpathSync(process.argv[1])) {
  main(process.argv.slice(2));
}
