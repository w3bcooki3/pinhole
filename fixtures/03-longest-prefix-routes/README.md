# 03: Longest-prefix routing

`vpc-a` (10.0.0.0/16) peers with `vpc-b` (10.1.0.0/16) and `vpc-c` (10.2.0.0/16). Its route table has:

| Destination | Target |
|---|---|
| 10.0.0.0/16 | local |
| 10.1.0.0/16 | pcx-ab |
| 10.1.1.0/24 | pcx-ac (misconfigured) |

| From | To | Expected |
|---|---|---|
| `eni-a` | `eni-b2` (10.1.2.10) | reachable: only the /16 matches, so via `pcx-ab` |
| `eni-a` | `eni-b1` (10.1.1.10) | blocked: the /24 is more specific and points at `pcx-ac`, and `vpc-c` does not contain 10.1.1.10 |

Why:
- "We direct traffic using the most specific route that matches the traffic. This is known as the longest prefix match." https://docs.aws.amazon.com/vpc/latest/userguide/route-tables-priority.html
- Peering is not transitive, and traffic can't be routed through a peer VPC to somewhere else. https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html

Every SG and NACL allows this traffic, so routing is the only thing being tested.
