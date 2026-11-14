# 01: NACL ephemeral return traffic

Three web servers, each in its own public subnet. Same security group (`sg-web`, TCP 443 from `0.0.0.0/0`), same inbound NACL rule (TCP 443 allowed). Only the outbound NACL rule differs:

| Subnet | Outbound rule 100 | Expected |
|---|---|---|
| `subnet-full` | TCP 1024-65535 | reachable, return path covers all clients |
| `subnet-linux` | TCP 32768-61000 | reachable, but only partially: Windows/macOS clients use 49152-65535 |
| `subnet-none` | TCP 443 | blocked: the response goes to the client's ephemeral port and hits the `*` deny |

Why: network ACLs are stateless, so "for every rule that you add, there must be an inbound or outbound rule that allows response traffic". The client picks the ephemeral port; Linux kernels use 32768-61000 and Windows Server 2008+ uses 49152-65535.

- https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html (Ephemeral ports)
- Security groups are stateful, so `sg-web` needs no outbound rule for the response: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html

The SSH query is blocked at the inbound NACL (only 443 is allowed in), before the security group is even reached.
