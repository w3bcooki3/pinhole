# 06: Public IP without an internet gateway route

The same security group (`sg-ssh`: TCP 22 from `0.0.0.0/0`) and an allow-all NACL are used everywhere.

| Interface | Subnet route for internet traffic | Public IP | Expected |
|---|---|---|---|
| `eni-public` | `0.0.0.0/0 -> igw-1` | yes | exposed on 22 |
| `eni-private-eip` | `0.0.0.0/0 -> nat-1` | Elastic IP | not exposed |
| `eni-no-public-ip` | `0.0.0.0/0 -> igw-1` | no | not exposed |
| `eni-nat` (NAT gateway) | `0.0.0.0/0 -> igw-1` | yes | not reported: external services cannot initiate connections through a NAT gateway ([NAT gateways](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html)) |

Why: AWS lists the requirements for internet access as an attached internet gateway, a subnet route to it, a public IPv4 address on the resource, and security groups (and NACLs) that allow the traffic.

- https://docs.aws.amazon.com/vpc/latest/userguide/working-with-igw.html
- https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html

For `eni-private-eip`, the response to the client is routed to `nat-1` instead of `igw-1`. The NAT gateway rewrites the source address, so the client never gets a reply from 52.0.0.2. The engine reports this at the return route.

`exactResources` in `expected.json` asserts that `eni-public` is the only interface in the exposure report.
