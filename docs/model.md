# What the v1 engine models

This file lists each AWS behaviour the engine implements, the documentation it is based on, and where the engine simplifies. Code comments in `packages/engine/src` cite the same pages.

## Security groups

Source: [Security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html), [Security groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html).

- Rules only allow. Anything no rule allows is denied.
- The rules of every group attached to an interface are aggregated into one set. All matching rules are reported, not just the first.
- A rule's source or destination is an IPv4/IPv6 CIDR, a prefix list ID, or a security group ID.
- A security group reference matches traffic by the private IP addresses of interfaces in the referenced group. Internet clients have no interface, so they never match.
- Inbound references work within a VPC, across peering, and across a transit gateway. Outbound references only work within a VPC or across peering.
- Across a transit gateway, a reference matches only when security group referencing is enabled on the transit gateway and on both VPC attachments. The attachment option defaults to enabled; the transit gateway option is read from the snapshot. ([TGW VPC attachments](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-vpc-attachments.html))
- References do not work across inter-Region peering. ([Peering and security groups](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-security-groups.html))
- Groups are stateful. For a connection, only the opening direction is checked: outbound on the source, inbound on the destination.
- Rule IDs (`sgr-...`) come from `DescribeSecurityGroupRules`. A snapshot that only has `IpPermissions` gets synthetic IDs of the form `sg-x:ingress:i.j`.
- An interface with no security groups is not filtered. Network Load Balancers without security groups are the documented case: all client traffic reaches the listeners.

## Network ACLs

Source: [Custom network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html), [Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html), [Default network ACL](https://docs.aws.amazon.com/vpc/latest/userguide/default-network-acl.html).

- Inbound and outbound rules are separate. Rules are evaluated from the lowest rule number; the first match decides. The `*` rule, reported by the API as 32767, denies the rest.
- Protocol `-1` matches everything. TCP and UDP rules match port ranges; ICMP rules match type and code, with -1 as a wildcard.
- IPv4 rules never match IPv6 traffic.
- A subnet without an explicit association uses the VPC's default NACL.
- NACLs filter traffic entering and leaving a subnet, so traffic between two interfaces in the same subnet is not evaluated.
- NACLs are stateless. The response is a separate packet to the client's ephemeral port. The engine computes, per client profile, how much of the ephemeral range every NACL on the return path allows:

  | Profile | Range | Used for |
  |---|---|---|
  | Linux kernels (incl. Amazon Linux) | 32768-61000 | internet clients and interfaces |
  | Windows Server 2008 and later | 49152-65535 | internet clients and interfaces |
  | Elastic Load Balancing | 1024-65535 | load balancer node to target |

  The return path is `all` when every profile is fully covered, `none` when no profile has any allowed port (the path is then blocked), and `partial` otherwise.

## Routing

Source: [Route priority](https://docs.aws.amazon.com/vpc/latest/userguide/route-tables-priority.html), [Route tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html).

- A subnet uses its associated route table, or else the VPC's main route table.
- The longest prefix wins, whatever the route type. On an exact tie: static, then prefix-list routes, then propagated routes. For a prefix-list route, the matching entry's prefix length is what counts.
- If the selected route is a blackhole, the packet is dropped. A less specific active route does not take over.
- Targets followed: `local`, peering connections, transit gateways, internet gateways. NAT gateways, VPN gateways, VPC endpoints and interface or instance targets end the walk: as "leaves the modelled network", or as `unknown` when the destination should have been inside the snapshot.

## VPC peering

Source: [How peering works](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html), [Peering routes](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html).

- The connection must be `active`.
- The destination must be inside the peer VPC's CIDRs. Peering is not transitive, and there is no edge-to-edge routing through the peer's gateways.
- Each side needs its own route. The engine checks the return route separately, so "the request arrives but the response has no route" is reported as blocked at `return-route`.

## Transit gateway

Source: [How transit gateways work](https://docs.aws.amazon.com/vpc/latest/tgw/how-transit-gateways-work.html), [TGW route tables](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-route-tables.html), [TGW and network ACLs](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-nacls.html).

- The source VPC needs an available attachment to the transit gateway named by the route.
- Only resources in Availability Zones where the attachment has a subnet can reach the transit gateway.
- The attachment's associated route table decides. Longest prefix first; for the same prefix: static, prefix list, then propagated. Blackhole routes drop.
- On the destination side, the transit gateway uses its interface in the destination's AZ, or in another AZ if there is none there. Traffic is then routed by that attachment subnet's route table. If that table sends the destination anywhere other than `local`, the path goes through an appliance and the result is `unknown`.
- NACLs are evaluated as in the AWS table:
  - instance to TGW: instance subnet outbound (destination IP), then TGW subnet inbound (source IP); if the two are the same subnet, both rule sets of that NACL;
  - TGW to instance: TGW subnet outbound (destination IP), then instance subnet inbound (source IP); if the two are the same subnet, none.
- Only VPC attachments are followed. VPN, Direct Connect, peering and Connect attachments give `unknown`.
- With ECMP (several attachments on one route), the first attachment is followed.

## Internet exposure

Source: [Add internet access to a subnet](https://docs.aws.amazon.com/vpc/latest/userguide/working-with-igw.html), [Internet gateways](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html), [NAT gateways](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html).

An interface is reachable from an internet address on a port when all of these hold, checked in this order:

1. The interface has a public IPv4 address or Elastic IP, mapped to one of its private IPs.
2. An internet gateway is attached to the VPC.
3. The internet gateway has no gateway route table. If it has one, the result is `unknown` (ingress routing through an appliance).
4. The subnet NACL allows the request inbound from the client.
5. A security group rule allows the request.
6. The subnet's route for the client's address points at that internet gateway. If it points at a NAT gateway instead, the response never reaches the client from the right address.
7. The subnet NACL allows the response outbound to the client's ephemeral port (see the profiles above).

Interfaces of NAT gateways, load balancers (reported per listener instead), VPC endpoints, Gateway Load Balancer endpoints and transit gateways are not reported directly.

"Internet address" means IPv4 minus the RFC 6890 special-purpose blocks that cannot arrive through an internet gateway: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`. The RFC 5737 documentation ranges are kept as internet addresses.

### How exposure is computed exactly

For one interface, cut the IPv4 space at every boundary of every CIDR in its security group inbound rules, the referenced prefix lists, its subnet's NACL and its subnet's routes. Then cut the port space at every boundary of every relevant security group and NACL port range. Within each resulting cell every rule either matches the whole cell or none of it, so one representative packet per cell gives the answer for the cell. Cells that no security group rule could admit are skipped. Adjacent cells with the same answer and the same deciding rules are merged into one finding.

## Load balancers

Source: [ALB security groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html), [ALB targets](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-register-targets.html), [NLB security groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html), [NLB targets](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/target-group-register-targets.html), [NLB target group attributes](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html).

- Load balancer nodes are the interfaces whose description is `ELB <app|net>/<name>/<id>`. The internet-to-listener leg is the interface exposure analysis restricted to the listener's port and protocol, across all nodes.
- ALB listeners are TCP. NLB TCP and TLS listeners are TCP, UDP and QUIC are UDP, and TCP_UDP and TCP_QUIC are both.
- Target groups come from the listener's default forward action and from forward actions in its rules.
- For each target, every node is checked as a source: node security group outbound, NACLs, target security group inbound (where a reference to the load balancer's group matches), and the return path with the Elastic Load Balancing ephemeral range. A target is `reachable` from all nodes, `partial` from some, or `blocked`.
- NLB client IP preservation: always on for UDP, TCP_UDP, QUIC and TCP_QUIC. For TCP and TLS it follows `preserve_client_ip.enabled`, which defaults to on for instance targets and off for IP targets. With preservation, the target's NACL and security groups see the client's internet address; a rule referencing the NLB's security group still matches.

## Lateral movement

`reachServices(model, a, b)` answers "what can interface A open on interface B" exactly. The port space is cut at every port boundary of B's inbound security group rules that could match A (a CIDR containing A's address, a reference to one of A's groups, or a prefix list containing A's address), A's outbound rules, and every network ACL entry for the protocol. One packet per cell is evaluated with the full path model: security groups on both sides, route tables, peering and transit gateway, and the network ACLs of the subnets crossed. Network ACLs are not evaluated between two interfaces in the same subnet, as AWS documents ([Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)). Cells with the same outcome and the same deciding rules are merged into ranges.

### Blast radius

Entry points are interfaces with an internet exposure finding, plus load balancer targets the internet reaches through a listener. From each entry, a breadth-first search (three hops by default) records every service reachable on every other interface. The attacker only moves on through services that normally give command execution:

- remote administration: SSH, RDP, WinRM, VNC, Telnet, SMB, MS RPC, NetBIOS;
- container and cluster control planes: Docker API, Kubernetes API, kubelet, etcd;
- port ranges of 1,000 ports or more, and all-traffic rules.

A database reached on its port is a target, not a new foothold. This models what the network allows, not what is exploitable: it assumes the attacker has credentials or a vulnerability for each pivot service.

Chains are reported once per target and impact (data store, control plane, remote administration); other entry points and routes to the same target are listed on that chain rather than as separate chains. A chain is not reported when the internet can already reach the target service directly, because that is an exposure finding; such targets are counted as hidden. Severity starts at critical for those impacts, drops one level when the entry point is only exposed on medium or lower-risk ports (a web server), and drops one more for chains of three or more hops. Chains are ranked by severity, the entry point's severity, data stores first, and shortest first.

Pairs are first checked with a cheap rule match: if no inbound rule on B could match A at all, the pair is skipped without evaluating packets. The search stops evaluating new pairs at 50,000 (configurable) and says so.

### What-if and fixes

`applyChanges` returns a new model with security group rules revoked, edited or added, network ACL entries added or removed, routes removed, public IPs removed or security groups detached. The original model is not modified. `diffExposure` compares two exposure reports per resource, protocol and port, and reports each range as closed, opened, narrowed (fewer internet sources), widened or changed; given two blast radius reports it also lists chains closed and opened. A chain that existed before but was hidden because the internet reached its target directly is listed separately as revealed, not opened: the change did not create it.

The fix finder builds candidates for each finding: cut the finding's ports out of a wider rule, remove the rule (or every rule) that allows it, add a network ACL deny numbered just ahead of the allowing entry, or remove the public IP. Each candidate is applied to a copy of the model and the exposure of every interface and load balancer it could affect is analysed again. A fix is verified only if no internet path to the finding's resource, protocol and ports remains. Other paths the change closes are reported as a bonus when they are critical or high, and as collateral otherwise, because web and low-risk paths are usually wanted.

Fixes that keep access from inside the network (restricting a rule to the VPC CIDR) get a small preference. For those, the attack chains are analysed again: if another internet-facing server could still reach the resource after the change, the chains are reported with the fix and the fix is ranked below one that removes the access.

The fix plan is greedy. Starting from the worst critical or high exposure or chain, it tries the verified fixes for it and the rules on the chain, applies the one that removes the most weighted risk (critical 10, high 6) with a penalty of 15 for each other path it closes, skips any change that opens an exposure or a chain, and repeats on the new model. Anything no single change closes is listed as unresolved.

AWS CLI commands are printed for each change. Pinhole never runs them.

### Rule hygiene

- **redundant-sg-rule:** another rule in the same group allows everything this one does.
- **shadowed-nacl-entry:** a lower-numbered entry in the same direction covers its protocol, ports and CIDR, so it is never evaluated ([NACL rule order](https://docs.aws.amazon.com/vpc/latest/userguide/nacl-basics.html)).
- **stale-group-reference:** a rule refers to a group that is not in the snapshot (deleted, or in another VPC or account).
- **unused-security-group:** attached to no interface or load balancer.
- **open-to-world:** an inbound rule from 0.0.0.0/0 on anything but web ports, on a group in use.
- **broad-internal-source:** a private range of /16 or wider allowed to remote administration, a data store or a control plane.
- **all-ports:** every port or protocol allowed from a CIDR.

## Out of scope, detected and warned about

| Detected | How |
|---|---|
| AWS Network Firewall | route targets `vpce-...` that are not in `DescribeVpcEndpoints` |
| Gateway Load Balancer | `GatewayLoadBalancer` endpoints, `gateway` load balancers, GWLB interface types |
| Appliances and NAT instances | routes to an interface or instance |
| Ingress routing | route tables associated with an internet or virtual private gateway |
| VPN / Direct Connect | routes to a virtual private gateway |
| IPv6 | VPC IPv6 CIDRs, egress-only internet gateways |
| Global Accelerator | `global_accelerator_managed` interfaces |
| CloudFront | security group rules using the CloudFront origin-facing prefix list |
| Data outside the snapshot | peer VPCs in other accounts or Regions, transit gateway route tables without routes, failed API calls |
