# 04: Blackhole routes

There are two blackholes:

1. `rtb-a` in `vpc-a` still has `10.1.0.0/16 -> pcx-deleted` in state `blackhole`. AWS marks a route this way when its target, here a peering connection, no longer exists.
2. `tgw-rtb-1` has a static blackhole route for `10.2.9.0/24`, next to the propagated `10.2.0.0/16 -> tgw-attach-c`.

| From | To | Expected |
|---|---|---|
| `eni-a` | `eni-c1` (10.2.1.10) | reachable: VPC route to `tgw-1`, then `tgw-rtb-1` 10.2.0.0/16 to `tgw-attach-c` |
| `eni-a` | `eni-c9` (10.2.9.10) | blocked in the TGW route table: the /24 blackhole is more specific than the /16 |
| `eni-a` | 10.1.0.5 | blocked in the VPC route table: the best match is a blackhole |

Why:
- Route selection is longest prefix first, and the selected route decides even when it is a blackhole. https://docs.aws.amazon.com/vpc/latest/userguide/route-tables-priority.html
- TGW route tables support blackhole routes, which drop matching traffic. https://docs.aws.amazon.com/vpc/latest/tgw/tgw-route-tables.html

Both VPCs use a dedicated /28 attachment subnet in the same AZ as the workloads. The engine evaluates the attachment subnets' NACLs in the directions given in https://docs.aws.amazon.com/vpc/latest/tgw/tgw-nacls.html. All NACLs here allow everything, so the NACLs don't change the outcome.
