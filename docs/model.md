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
- On the destination side, the transit gateway uses its interface in the destination's AZ, or in another AZ if there is none there. Traffic is then routed by that attachment subnet's route table. If that table sends the destination to an inspection endpoint, the path goes through the appliance and on from the endpoint's subnet (centralised inspection: back to the transit gateway, whose route table for the inspection VPC's attachment then decides). Anything else is `unknown`.
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
3. If the internet gateway has a gateway route table (ingress routing), its route for the interface's private address decides: `local` goes straight on; a Network Firewall or Gateway Load Balancer endpoint sends the packet through the appliance (see below) and on by the endpoint subnet's route table; anything else is `unknown`.
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

The fix plan is built in three passes, and every number in it comes from applying changes to a copy of the model and re-running both analyses.

1. **Candidates.** The verified fixes for the three worst open critical or high exposures, and for the two worst open attack chains: the removal of each rule on every route of the chain, plus the fixes for the internet exposure of the chain's entry points. A change at the entry point often cuts every chain from that server at once. Candidates are generated once per goal and kept.
2. **Lazy greedy selection** (Minoux's accelerated greedy). The gain of a change is the weighted risk it removes (critical 10, high 6), minus 15 for each other, probably wanted, path it closes, minus one per change. A change that opens an exposure or a chain is never picked. Closing a goal only lowers what is left for the other changes, so each candidate's last measured gain is an upper bound: candidates are re-measured in bound order and the step stops as soon as no bound can beat the best fresh gain. The candidates for the single worst goal are always re-measured, because two rules that only matter together break the bound.
3. **Pruning.** Each step is taken out in turn and the rest re-applied. A step whose removal leaves every goal as closed as before is redundant (a later step covered it) and is dropped. The test suite checks the result: removing any step of a plan leaves something open.

Anything no single change closes is listed as unresolved. The plan reports how many candidates it tried, how many full re-analyses it ran and how many steps it dropped.

AWS CLI commands are printed for each change. Pinhole never runs them.

### Across accounts and Regions

A snapshot covers one account in one Region. Snapshots that share a VPC peering connection or a transit gateway are grouped (union-find over the shared IDs) and each group is merged into one model, so the same path analysis runs across the link: routes on both sides, NACLs on both sides, and security group references across the link where AWS allows them (same-Region peering; a transit gateway with security group referencing turned on, inbound only). A merged model is only built when the snapshots share nothing but the link: real accounts never share other IDs, so a clash means copies of one account or made-up data, and the group is analysed separately with the reason given.

Only attack chains that cross from one snapshot into another are reported for a joined group; chains inside one snapshot are already in that snapshot's own report. The fix plan for a joined group has the crossing chains as its only goals and names the account and Region each change runs in.

Sources: [VPC peering basics](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html), [security groups across peering](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-security-groups.html), [transit gateway security group referencing](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-vpc-attachments.html).

### Rule hygiene

- **redundant-sg-rule:** another rule in the same group allows everything this one does.
- **shadowed-nacl-entry:** a lower-numbered entry in the same direction covers its protocol, ports and CIDR, so it is never evaluated ([NACL rule order](https://docs.aws.amazon.com/vpc/latest/userguide/nacl-basics.html)).
- **stale-group-reference:** a rule refers to a group that is not in the snapshot (deleted, or in another VPC or account).
- **unused-security-group:** attached to no interface or load balancer.
- **open-to-world:** an inbound rule from 0.0.0.0/0 on anything but web ports, on a group in use.
- **broad-internal-source:** a private range of /16 or wider allowed to remote administration, a data store or a control plane.
- **all-ports:** every port or protocol allowed from a CIDR.

## Internal traffic a change breaks

`packages/engine/src/internal.ts`. For a list of changes, the interfaces they can affect are found (members of changed security groups, interfaces in subnets whose network ACL or route table changes, interfaces a group is attached to or detached from). Every pair into or out of those interfaces is evaluated with `reachServices` before and after, and every protocol and port range that no longer gets through is reported. Each lost range carries its evidence:

| Evidence | Meaning |
|---|---|
| `load-balancer` | a load balancer node reaching a registered target on its traffic port |
| `health-check` | the same, on a separate health check port (HTTP and HTTPS health checks are TCP) |
| `group-reference` | the rule that let it in names the source's security group |
| `network` | allowed only by an address range or prefix list: may or may not be used |

A fix is *safe* when it is verified, opens nothing, and loses nothing with the first three kinds of evidence. Public IP, internet gateway and listener changes do not carry traffic between private addresses and are not counted.

The least-privilege rewrite finds the interfaces whose only allowing rule, on some service, is the rule in question (`usersOf`), and replaces the rule's source with a greedy cover of their security groups (groups with no other members first; never a group containing the excluded foothold), plus `/32` addresses for interfaces without a usable group. It is offered when that takes at most eight rules.

## Fix plan proof

After the greedy plan and pruning, `planFixes` records, for every goal it closed, the connections the goal depends on (`needsOf`): an exposure needs the internet to reach its resource on its ports; a chain needs its entries' exposures and every hop of every route found. A candidate *can close* a need only if it revokes or narrows a rule that matches the need's traffic on the destination (or the source, for egress rules), adds a deny network ACL entry for its protocol and ports in either subnet, or removes the interface's public IP or a group; adding a rule or an allow entry can close nothing. This is sound for the candidates the planner generates, all of which only take access away.

- **Lower bound:** the minimum hitting set of the goals' candidate sets, by branch and bound with a disjoint-sets bound.
- **Search:** every set of the relevant candidates of each size from the bound up to the plan's size minus one, skipping sets with two changes to the same rule, network ACL entry number or public IP. A set is accepted if, re-analysed, it closes every goal the plan closed, opens nothing, breaks no more wanted traffic and no more protected (policy) traffic. Because candidates only take access away, a goal left open by some candidates is left open by any subset of them; those sets are skipped without re-analysis.
- **Result:** `optimal` with the plan's size as the bound when every smaller size was searched (or a smaller plan was found, which then replaces it), `bounded` with the bound when the budget (`proofBudget`, default 500 re-analyses) ran out. Optimality is relative to the candidates considered, not to every possible change.

## Policies

`packages/engine/src/policy.ts`. The file format is in the documentation site's Policies page and validated by `parsePolicy`. Selectors match interfaces (not load balancer nodes) and load balancers; tags are merged from the VPC, then the subnet, then the instance, the most specific winning.

- *deny from internet*: every exposure finding on a matching resource whose ports overlap, and every load balancer target that matches and is reachable on an overlapping target port. With `indirect`, every attack chain whose target matches and whose last service overlaps.
- *deny between groups*: every reachable service between every pair of matching interfaces (`reachServices`).
- *require from internet*: a finding on the resource covering the whole port range; otherwise the result of `evaluatePath` from a documentation address shows where it is blocked.
- *require between groups*: a reachable service covering the whole range for every pair; otherwise `evaluatePath` shows the blocking hop.

`diffPolicy` compares two reports by connection, for Terraform plans.

## Crown jewels and the minimum cut

`packages/engine/src/cut.ts` and `jewels.ts`. Crown jewels are interfaces tagged `pinhole:crown-jewel` (or `crown-jewel`; any value but false, no or 0) or with a `data-classification` / `classification` tag of confidential, restricted, secret, top-secret, sensitive, PII, PHI, PCI or critical, on the instance, subnet or VPC. Without any, the targets of data and control-plane chains are used. Chains to tagged jewels get 25 added to their score.

The attack graph has a source (the internet), `controls(eni)` nodes, `reaches(jewel)` nodes and a sink. Edges: internet to each entry (every rule that admits the internet to it, by `allowingRules`), controls to controls for pivot services, controls to reaches for a jewel's data, control-plane, admin or critical services, reaches to sink. An edge's capacity is the number of rules that must all go to cut it, times 10 for entries whose worst exposure is medium or lower (public websites) and at least 5 for rules that reference a security group. An edge with no security group rule to remove (a destination without groups) has infinite capacity. Edmonds-Karp gives the minimum cut; its rules are pruned one at a time while no chain to a jewel returns, and the result is verified by re-analysis.

## Rule cleanup

`packages/engine/src/cleanup.ts`. Comparisons are made on cells: addresses cut at every CIDR and prefix list boundary of the rules involved, ports at every port boundary, ICMP at every type and code mentioned, plus one peer per referenced group outside every CIDR. One packet per cell goes through `evaluateSg` or `evaluateNacl`. Within a cell every rule matches all or nothing, so agreement on every cell is agreement on every packet.

- *Covered together*: a rule whose every allowed cell another rule of its group allows (single-rule cover is left to hygiene).
- *Covered by an attached group*: every interface and load balancer that uses the rule's group has other groups that together allow every cell.
- *Network ACL entry decided by earlier entries*: every cell the entry matches is matched first by an earlier entry (not the default `*` rule); harmless when they give the same answer.
- *Compaction*: per protocol, all-protocol rules first; per referenced group and prefix list, port ranges merged; per port cell, the CIDR rules' address set (minus all-protocol addresses) merged with equal neighbours and written as the fewest CIDR blocks. ICMP, protocols without ports and IPv6 rules are kept. The result is offered only when it has fewer rules and `sameRules` confirms it cell by cell.
- *Quotas*: 80% of the defaults: 60 rules per direction per group, 20 per direction per network ACL, 5 groups per interface ([Amazon VPC quotas](https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html)).

## Differential testing

`packages/engine/test/fuzz.test.ts` and `reference.ts`. A seeded generator builds random networks: one VPC, two subnets, an internet gateway attached or not, main and subnet route tables with default and more-specific routes to the gateway, a NAT gateway or a blackhole, default and subnet network ACLs with random entries, three security groups with random rules, and public addresses on some interfaces. For every interface, client address, protocol and port in a fixed list, the reference evaluator answers from the snapshot JSON directly, and the engine answers twice: `evaluatePath` and the exposure report's exact `sourceRanges`. Any disagreement fails with the seed and the snapshot. Compaction is fuzzed against a direct rule matcher in the same way. Network Firewall is fuzzed against `referenceFirewall`: random stateless rules (protocols, sources, source and destination ports, any action) and default actions, random Suricata rules (any action, protocol, addresses including variables, ports and ranges, either direction) in either rule order with any strict default action, decided for three clients, two protocols, three ports and five client ports each.

## Firewalls and appliances

`packages/engine/src/firewall.ts`, and the appliance steps in `walk.ts` and `path.ts`.

**Following the route.** A route whose target is a Network Firewall endpoint (from `DescribeFirewall`'s sync states) or a Gateway Load Balancer endpoint hands the packet to the appliance. The walk adds an appliance checkpoint, crosses into the endpoint's subnet (its network ACL inbound, unless it is the same subnet), and routes on from the endpoint subnet's route table, crossing its network ACL outbound. This covers ingress routing on the internet gateway, subnet routes through the firewall (for replies, and between subnets), and a transit gateway attachment subnet that sends traffic to an endpoint (centralised inspection). More than four appliances in one direction is reported as a routing loop.

**Deciding the connection.** Network Firewall is evaluated on the connection: the request (client to server) and the reply (server to client), for each cell of the client's ephemeral port range cut at every port any rule mentions.

- Stateless: each packet goes through the policy's stateless groups in priority order and their rules in priority order; the first match passes, drops or forwards it; otherwise the stateless default action applies. A rule matching on TCP flags gives `unknown`. A dropped request or reply blocks the connection.
- Stateful: the forwarded packets, request first, go through the stateful rules. In default action order, all pass rules come first, then drop, reject and alert; in strict order, groups by priority and rules as written. The first pass, drop or reject decides (a `DROP_TO_ALERT` override makes a group's drops alerts). If nothing decides, strict order applies `aws:drop_strict` or `aws:drop_established` as a drop; otherwise the flow passes.
- Headers: protocol (`ip`, `tcp`, `udp`, `icmp`; application protocols such as `http` or `tls` match only TCP or UDP and are conditional), addresses and ports with lists, ranges, negation and variables, `->` or `<>`, and `flow:to_server` / `to_client`. `HOME_NET` defaults to the firewall VPC's CIDRs; policy variables override it; `EXTERNAL_NET` is everything else.
- Domain lists generate rules from `HOME_NET` to `EXTERNAL_NET` with `flow:to_server`: pass (allow list) or drop (deny list) for the listed hosts, and, for an allow list, drop for other TLS or HTTP.
- Anything else a rule matches on (content, host names, flowbits, application protocols) makes it conditional. The evaluator follows both outcomes; if they differ, the connection is `unknown` inside the firewall, and the path continues with a caveat on the hop and the finding.
- A rule group whose rules are not in the snapshot makes the stateful result `unknown` (with a caveat). AWS managed groups are skipped: they drop known-malicious traffic only.

The client ports the firewall allows are intersected with the network ACLs' return coverage, so a firewall that passes replies only to some ephemeral ports gives `returnPath: partial`.

**Symmetry.** The firewalls and appliances on the forward walk and the return walk are compared. A Network Firewall on one direction only is a block (its stateful engine drops flows it did not see start); a third-party appliance on one direction only is a caveat.

**Third-party appliances.** A Gateway Load Balancer endpoint that is not a Network Firewall endpoint is followed and assumed to pass, with a caveat naming the endpoint service.

**Cells.** Exposure and service reachability also cut addresses and ports at firewall rule boundaries and at the network ACL and route table entries of every endpoint subnet, so each cell is decided the same way throughout.

## Outbound

`packages/engine/src/egress.ts`, and `outboundToInternet` in `path.ts`.

An interface opening a connection to an internet address
([internet gateways](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html),
[NAT gateways](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html)):

1. Its security groups allow it out.
2. Its subnet's route for the address leads, possibly through firewalls, to the VPC's internet gateway; the interface then needs a public IPv4 address or Elastic IP, which it leaves as. Or the route leads to a NAT gateway that is `available` and public, whose own subnet's route leads, possibly through firewalls, to the internet gateway; the traffic leaves as the NAT gateway's Elastic IP. A private NAT gateway, an egress-only gateway (IPv6 only) or a route inside the network ends the path.
3. Network ACLs allow it out at every subnet boundary, the NAT gateway's subnet included, and the replies back: into the NAT gateway's subnet on the NAT gateway's ports (1024-65535), out of it and into the interface's subnet on the interface's ephemeral ports.
4. Replies come in through the internet gateway, through its route table (ingress routing) and any firewall on the way; a Network Firewall seen in one direction only drops them.

The report cuts destination addresses at every security group egress rule, network ACL entry and route of the interface's subnet and its NAT gateway's subnet, firewall rule and gateway route table entry, and ports likewise; one connection per cell is evaluated, and cells with the same answer and the same deciding rules are merged. Interfaces with the same subnet, groups and public address status are evaluated once. Severity: any port range of 1,000 or more to every internet address is medium, high when the interface holds data (a crown jewel tag, or a data service port its security groups let in); a data store otherwise is low; SMTP and remote administration out are low; the rest is info.

## On-premises

`packages/engine/src/onprem.ts`, `hybrid.ts`, and `fromOnPrem` / `toOnPrem` in `path.ts`.

**Links.** A virtual private gateway (`DescribeVpnGateways`, attached VPCs) and the transit gateway attachments of type `vpn` or `direct-connect-gateway`. VPN connections (`DescribeVpnConnections`; only state, gateway, static routes and tunnel status are kept, never the customer gateway configuration or tunnel options, which hold the pre-shared keys) say which links are VPN and whether every tunnel was down. A virtual private gateway without a VPN connection may be Direct Connect.

**On-premises networks.** The ranges AWS routes to a link: active VPC routes to a virtual private gateway (static or propagated), active transit gateway routes to a VPN or Direct Connect attachment, and the static routes of VPN connections. An address with no interface in the snapshot is treated as on-premises.

**From on-premises to an interface.**

1. The interface's subnet route for the client decides the link the replies take. With no such route, or one to an internet or NAT gateway, the connection is blocked (`return-route`): replies cannot get back.
2. The connection arrives over that same link ([routing is symmetric only if on-premises makes it so](https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNRoutingTypes.html)). Over a virtual private gateway attached to the VPC, its gateway route table, if any, may send the traffic through a firewall first. Over a transit gateway, the attachment's associated route table must send the destination to the VPC's attachment; then the attachment subnet's route table and network ACLs apply, as for any transit gateway path.
3. The destination subnet's network ACL and the interface's security groups allow the client's address. Security groups cannot reference on-premises groups.
4. Replies: the return route and network ACLs on the client's ephemeral ports, and firewall symmetry, as for any connection.

**From an interface to on-premises.** Security group, route (to a virtual private gateway attached to the VPC, or through a transit gateway to a VPN or Direct Connect attachment), network ACLs; then the replies arrive over the same link to the interface's subnet, and its network ACLs let them in on the interface's ephemeral ports.

Every path over a link carries a caveat: on-premises routers and firewalls are not visible to AWS. The report (`analyzeOnPrem`) uses the exposure method on the on-premises address space, cut at every security group rule, network ACL entry and route of the interface's VPC, transit gateway route, gateway route table entry and firewall rule. Severity is the internet rating of the service lowered one level, and one more when only 256 or fewer on-premises addresses reach it.

## PrivateLink

`packages/engine/src/privatelink.ts`.

**Services this account provides** (`DescribeVpcEndpointServiceConfigurations`, `DescribeVpcEndpointServicePermissions`, `DescribeVpcEndpointConnections`):

- *Who may connect.* The allowed principals. `*` (type `All`) is every AWS account. Without acceptance required, an allowed principal's endpoint connects at once ([configure an endpoint service](https://docs.aws.amazon.com/vpc/latest/privatelink/configure-endpoint-service.html)). Principals whose ARN is not in this account are listed as outside principals.
- *Who has.* Endpoint connections that are not deleted, rejected, failed or expired, with the owner account and Region.
- *What they reach.* For each listener of each Network Load Balancer behind the service: the consumer addresses its security groups let in on the listener port. With no security groups, or with "Enforce inbound rules on PrivateLink traffic" off, that is any address; otherwise the CIDR and prefix list rules (the source is the consumer's private address, and a rule that names a security group cannot match it) ([NLB security groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html)). Targets see the load balancer's own address whatever the client IP preservation setting ([target group attributes](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html)), so each target is evaluated from every load balancer node with the full path model.
- *Severity.* Every account without approval is high, with approval medium, outside principals low, otherwise info. An open service (medium or above) that reaches a target port rated high or critical (remote administration, databases, admin panels) is raised one level.

**This account's endpoints.** For interface and gateway endpoints: the security group's inbound rules, whether the service belongs to another account (a `vpce-svc-` service not in this snapshot), and whether the endpoint policy has an unconditional statement allowing every principal every action (`*` or `service:*`) on every resource. On S3 and DynamoDB endpoints that is low: data can be copied to buckets and tables in any account ([control access with endpoint policies](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html)).

## Repairing a blocked connection

`packages/engine/src/repair.ts` (`pinhole can --port N --fix`, and the console's query page).

The connection is evaluated; at the hop that stops it, or the network ACL that turns some replies away, one narrow change is proposed, applied to a copy of the model, and the connection evaluated again, until it works, a hop is reached that configuration Pinhole writes cannot change, or a change makes no progress (at most eight steps).

| Stops at | Change |
|---|---|
| Security group, inbound or outbound | A rule for this protocol and port on the interface's group attached to the fewest interfaces, naming the other end's group when both are in one VPC, otherwise its address (/32) |
| Network ACL, either direction | An allow entry for the peer's address (/32) and the port (the client ephemeral range, 32768-65535, for replies), numbered at the highest free number below the entry that decides it now |
| Route or return route | A route to what already connects the two ends: an active peering connection or a shared transit gateway (the peer VPC's CIDR), the VPN gateway or transit gateway of an on-premises link (the on-premises network), a NAT gateway that reaches the internet for a server without a public address, or the internet gateway (0.0.0.0/0, or only the client's address when the table already sends 0.0.0.0/0 elsewhere) |
| Public IP, internet gateway | Attach an Elastic IP, attach an internet gateway |
| Firewall, appliance, NAT gateway, transit gateway route table | No change; the advice names what to change |

Notes say when a group, route table or network ACL is shared by other interfaces or subnets. Afterwards the internet exposure of the whole model is compared before and after, and anything new or wider is listed.

## Network Firewall rule hygiene

`packages/engine/src/fwhygiene.ts`, reported with the rest of rule hygiene.

A rule never decides anything when every packet it matches is matched first by a rule that ends the evaluation. The order is the engine's: stateless groups by priority and rules by priority, where pass, drop and forward all end it ([rule engines](https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-rules-engines.html)); stateful rules in strict order (groups by priority, rules as written) or in default action order (every pass, then drop, reject and alert, [evaluation order](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html)), where pass, drop and reject end it and alert does not. A group with the `DROP_TO_ALERT` override counts as alerts.

Each rule is a union of boxes over protocol, source and destination addresses, source and destination ports, and, for stateful rules, direction (`flow:to_server`, `to_client`, or both; `<>` adds the reversed box). Variables and negations are resolved as for path evaluation. The earlier rules' boxes are cut into cells inside each of the rule's boxes, so cover by several rules together is found exactly. Rules that also match on the traffic itself (TCP flags, content, host names, application protocols) can be covered but never cover others. IPv6 rules are skipped.

- *Redundant* (info): the covering rules all take the same action. Removing the rule changes nothing.
- *Shadowed* (low; medium for a drop or reject hidden behind a pass): the covering rules decide differently, so the rule's action never happens.
- *Matches nothing* (info): a field is empty once resolved, for example `[10.0.0.0/8,!10.0.0.0/8]`.
- *Empty group*, and rules that could not be read (info).

`packages/engine/test/fwhygiene.test.ts` checks the stateless result against brute force over every packet class on random rule lists.

## Out of scope, detected and warned about

| Detected | How |
|---|---|
| Endpoints not in the snapshot | route targets `vpce-...` that are neither firewall endpoints nor in `DescribeVpcEndpoints` (usually a firewall collected without the Network Firewall permissions) |
| Third-party appliances | routes to `GatewayLoadBalancer` endpoints that are not Network Firewall endpoints (followed, assumed to pass) |
| Appliances and NAT instances | routes to an interface or instance |
| Ingress routing elsewhere | gateway route tables that send traffic to something other than `local` or an inspection endpoint |
| On-premises side of VPN / Direct Connect | routes to a virtual private gateway, VPN and Direct Connect gateway attachments (followed to the link, then assumed to pass) |
| IPv6 | VPC IPv6 CIDRs, egress-only internet gateways |
| Global Accelerator | `global_accelerator_managed` interfaces |
| CloudFront | security group rules using the CloudFront origin-facing prefix list |
| Data outside the snapshot | peer VPCs in other accounts or Regions, transit gateway route tables without routes, failed API calls |

## Comparing snapshots

`pinhole diff` and the console's Compare page analyse both snapshots in full and compare the results, not the raw files.

- **Exposure** is compared per resource, protocol and listener, over every port. Each port range is reported as new, wider (more internet sources than before), narrower, changed, or closed. Sources inside private address space were never internet exposure, so restricting a rule to `10.0.0.0/8` and then opening it to `0.0.0.0/0` shows as new, not wider.
- **Attack chains** are compared by target and impact. A chain is reported closed only if it is gone and its target is not now reachable from the internet directly; a target that became directly exposed is shown as new exposure, which is worse.
- **Configuration** is compared by AWS ID: security groups and their rules, network ACL entries and subnet associations, non-local routes, public IPs per interface, the security groups attached to each interface, internet gateway attachments, load balancers and listeners.
- Snapshots must be of the same account and region; IDs do not line up otherwise.

## Terraform plans

`pinhole plan` reads `terraform show -json PLANFILE` and turns the network changes in it into the same changes the simulator uses, against a snapshot. It then compares exposure and attack chains before and after.

Mapped exactly, when every value is known at plan time and the resources are in the snapshot:

| Terraform resource | Becomes |
|---|---|
| `aws_vpc_security_group_ingress_rule`, `aws_vpc_security_group_egress_rule` | rule added or removed (matched by rule ID, or by content) |
| `aws_security_group_rule` | one rule per CIDR, prefix list or source group, added or removed (matched by content) |
| `aws_security_group`, `aws_default_security_group` | inline `ingress` and `egress` blocks compared before and after; deleting the group removes its rules |
| `aws_network_acl_rule` | entry added or removed |
| `aws_network_acl`, `aws_default_network_acl` | inline entries compared by rule number |
| `aws_route` | route added or removed |
| `aws_route_table`, `aws_default_route_table` | inline routes compared by destination |
| `aws_network_interface_sg_attachment` | security group attached or detached |
| `aws_instance`, `aws_network_interface` (updates) | `vpc_security_group_ids` / `security_groups` changes |
| `aws_eip_association` | public IP added or removed |
| `aws_route_table_association`, `aws_main_route_table_association` | subnet moved to another route table, or back to the main one; main route table changed |
| `aws_network_acl_association` | subnet moved to another network ACL; removing it returns the subnet to the default ACL |
| `aws_internet_gateway`, `aws_internet_gateway_attachment` | gateway attached to or detached from a VPC |
| `aws_lb_listener`, `aws_alb_listener` | listener added to or removed from a load balancer |

IPv6 is handled throughout: `ipv6_cidr_blocks` on security group rules, `ipv6_cidr_block` on network ACL entries, and `destination_ipv6_cidr_block` on routes are placed exactly like their IPv4 forms.

Security groups and internet gateways the plan creates get a placeholder ID (`sg-plan1`, `igw-plan1`, ...). Where a rule, an attachment or a source group is unknown until apply, Pinhole follows the plan's `configuration` references, through module outputs, to the resource it comes from; if that is a security group or internet gateway the plan creates, the placeholder is used. A new group with its rules, attached to an existing instance in the same plan, is therefore checked end to end, and so is a new internet gateway with a route to it. A second internet gateway on a VPC that keeps its first is refused, as AWS refuses it. A reference that could mean several instances (`count` or `for_each` without an index) is not resolved.

Listed as not analysed, with the reason: values known only after apply that do not lead to a security group or internet gateway the plan creates; resources not in the snapshot (another account, region or VPC); listeners whose load balancer the plan does not name; new instances, interfaces, subnets and load balancers; and other network resource types (NAT gateways, peering, transit gateways, endpoints). Everything outside networking is counted and ignored.

Every mapped change passes the same validation as a hand-written `--changes` file before it is used.

## IPv6

IPv6 addresses in a VPC are global unicast addresses: they need no public IP or NAT to be reachable ([IP addressing](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html)). An interface is exposed over IPv6 when:

- its VPC has an internet gateway attached;
- the subnet's network ACL allows the request in by an IPv6 rule (rules are evaluated in number order; IPv4 rules never match IPv6 traffic; the IPv6 `*` rule is number 32768);
- a security group on the interface allows it by an IPv6 CIDR rule (security group references and IPv4 rules never match internet IPv6 traffic);
- the subnet's longest-prefix IPv6 route for the client's address targets that internet gateway. A route to an [egress-only internet gateway](https://docs.aws.amazon.com/vpc/latest/userguide/egress-only-internet-gateway.html) carries only connections the instance opens, so it exposes nothing;
- the network ACL lets the response out to the client's ephemeral ports, checked for the same client operating systems as IPv4.

The analysis is exact over ports and over 128-bit source address ranges. "Every internet address" means global unicast space (`2000::/3`, [IANA](https://www.iana.org/assignments/ipv6-unicast-address-assignments)) outside the VPC's own IPv6 blocks; unique local (`fc00::/7`), link-local and other special ranges are never internet sources. The documentation range `2001:db8::/32` counts as internet so fixtures can use it.

Dual-stack load balancers ([IP address types](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-ip-address-type.html)) take IPv6 clients on every listener. Each load balancer node interface is analysed as above, limited to the listener's port, and the nodes are merged as for IPv4. A network load balancer without security groups filters no client, so only its network ACL and routes decide. Behind the listener, targets are evaluated from the nodes' own addresses: an IPv6 client's address cannot be carried to an IPv4 target, so client IP preservation does not apply. A load balancer with `IpAddressType` `dualstack-without-public-ipv4` has no public IPv4 address and is reachable over IPv6 only. Snapshots collected before this field was read do not say whether a load balancer is dual-stack; those in IPv6 VPCs are listed in Coverage.

Not analysed for IPv6: ICMPv6, prefix lists with IPv6 entries, and lateral movement between IPv6 addresses. IPv6 findings are marked as such in every output.
