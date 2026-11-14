# 08: NLB client IP preservation

An internet-facing Network Load Balancer (`api`) with no security groups. It listens on TCP 5000 and forwards to two target groups.

| Target | Target group | Client IP preserved | Target SG | Expected |
|---|---|---|---|---|
| `i-open` | `instances` (instance) | yes | 5000 from 0.0.0.0/0 | reachable |
| `i-vpc` | `instances` (instance) | yes | 5000 from 10.0.0.0/16 | blocked: the target sees the internet client's address |
| `10.0.10.23` | `ips` (ip) | no | 5000 from 10.0.0.0/16 | reachable: the target sees the NLB's private address |

Why:
- If you don't assign a security group to a Network Load Balancer, all client traffic can reach its listeners. https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html
- With client IP preservation, targets must allow the client addresses (or reference the NLB's security group, if it has one). Without it, they must allow the NLB's private IP addresses. https://docs.aws.amazon.com/elasticloadbalancing/latest/network/target-group-register-targets.html
- Preservation is controlled by `preserve_client_ip.enabled` on the target group. https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html

The exposure report lists the NLB on TCP 5000 (no security group filters it), and not its node interface separately.
