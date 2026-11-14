# 05: Peering without a return route

The peering connection `pcx-ab` is active. `vpc-a` has `10.1.0.0/16 -> pcx-ab`. `vpc-b` has only its local route. All security groups and NACLs allow the traffic.

| From | To | Expected |
|---|---|---|
| `eni-a` | `eni-b:22` | blocked on the return route: the request arrives, but `vpc-b` has no route back to 10.0.1.10 |
| `eni-b` | `eni-a:22` | blocked on the forward route: no route from `vpc-b` to 10.0.0.0/16 |

Why: an active peering connection carries no traffic until both sides have routes. AWS says to add a route to the peer VPC's CIDR to the route tables in each VPC. Security groups being stateful does not help here: they only remove the need for a return *rule*. The response packet still needs a *route*.

- https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html
- https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html

This is the case where "the SYN gets there but the connection times out", which a forward-only analysis gets wrong.
