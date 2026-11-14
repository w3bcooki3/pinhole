/**
 * AWS SDK v3 backend for the collector's `Send` function.
 *
 * Only read-only commands are imported. Credentials come from the standard
 * provider chain, or from a named profile in ~/.aws/config when given.
 */
import {
  EC2Client,
  DescribeVpcsCommand,
  DescribeSubnetsCommand,
  DescribeRouteTablesCommand,
  DescribeInternetGatewaysCommand,
  DescribeEgressOnlyInternetGatewaysCommand,
  DescribeNatGatewaysCommand,
  DescribeVpcPeeringConnectionsCommand,
  DescribeTransitGatewaysCommand,
  DescribeTransitGatewayAttachmentsCommand,
  DescribeTransitGatewayVpcAttachmentsCommand,
  DescribeTransitGatewayRouteTablesCommand,
  SearchTransitGatewayRoutesCommand,
  DescribeNetworkAclsCommand,
  DescribeSecurityGroupsCommand,
  DescribeSecurityGroupRulesCommand,
  DescribeManagedPrefixListsCommand,
  GetManagedPrefixListEntriesCommand,
  DescribeNetworkInterfacesCommand,
  DescribeInstancesCommand,
  DescribeVpcEndpointsCommand,
} from '@aws-sdk/client-ec2';
import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
  DescribeListenersCommand,
  DescribeRulesCommand,
  DescribeTargetGroupsCommand,
  DescribeTargetHealthCommand,
  DescribeTargetGroupAttributesCommand,
} from '@aws-sdk/client-elastic-load-balancing-v2';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { fromIni } from '@aws-sdk/credential-providers';
import type { Send, Service } from './collect.js';

/* eslint-disable @typescript-eslint/no-explicit-any */
type CommandCtor = new (input: any) => any;

const COMMANDS: Record<Service, Record<string, CommandCtor>> = {
  ec2: {
    DescribeVpcs: DescribeVpcsCommand,
    DescribeSubnets: DescribeSubnetsCommand,
    DescribeRouteTables: DescribeRouteTablesCommand,
    DescribeInternetGateways: DescribeInternetGatewaysCommand,
    DescribeEgressOnlyInternetGateways: DescribeEgressOnlyInternetGatewaysCommand,
    DescribeNatGateways: DescribeNatGatewaysCommand,
    DescribeVpcPeeringConnections: DescribeVpcPeeringConnectionsCommand,
    DescribeTransitGateways: DescribeTransitGatewaysCommand,
    DescribeTransitGatewayAttachments: DescribeTransitGatewayAttachmentsCommand,
    DescribeTransitGatewayVpcAttachments: DescribeTransitGatewayVpcAttachmentsCommand,
    DescribeTransitGatewayRouteTables: DescribeTransitGatewayRouteTablesCommand,
    SearchTransitGatewayRoutes: SearchTransitGatewayRoutesCommand,
    DescribeNetworkAcls: DescribeNetworkAclsCommand,
    DescribeSecurityGroups: DescribeSecurityGroupsCommand,
    DescribeSecurityGroupRules: DescribeSecurityGroupRulesCommand,
    DescribeManagedPrefixLists: DescribeManagedPrefixListsCommand,
    GetManagedPrefixListEntries: GetManagedPrefixListEntriesCommand,
    DescribeNetworkInterfaces: DescribeNetworkInterfacesCommand,
    DescribeInstances: DescribeInstancesCommand,
    DescribeVpcEndpoints: DescribeVpcEndpointsCommand,
  },
  elbv2: {
    DescribeLoadBalancers: DescribeLoadBalancersCommand,
    DescribeListeners: DescribeListenersCommand,
    DescribeRules: DescribeRulesCommand,
    DescribeTargetGroups: DescribeTargetGroupsCommand,
    DescribeTargetHealth: DescribeTargetHealthCommand,
    DescribeTargetGroupAttributes: DescribeTargetGroupAttributesCommand,
  },
  sts: {
    GetCallerIdentity: GetCallerIdentityCommand,
  },
};

/** The operations the collector can ever call; used for the IAM policy test. */
export const COLLECTOR_OPERATIONS: { service: Service; operation: string }[] = Object.entries(COMMANDS).flatMap(([service, ops]) =>
  Object.keys(ops).map((operation) => ({ service: service as Service, operation })),
);

export function sdkSender(opts: { region: string; profile?: string }): Send {
  const credentials = opts.profile ? fromIni({ profile: opts.profile }) : undefined;
  const config = { region: opts.region, maxAttempts: 8, retryMode: 'adaptive' as const, ...(credentials ? { credentials } : {}) };
  const clients: Record<Service, { send: (cmd: any) => Promise<any> }> = {
    ec2: new EC2Client(config),
    elbv2: new ElasticLoadBalancingV2Client(config),
    sts: new STSClient(config),
  };
  return async (service, operation, input) => {
    const Ctor = COMMANDS[service][operation];
    if (!Ctor) throw new Error(`Operation ${service}:${operation} is not in the collector's allow-list.`);
    return clients[service].send(new Ctor(input));
  };
}
