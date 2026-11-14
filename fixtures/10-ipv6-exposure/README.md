# 10: IPv6 without a public IP

A dual-stack VPC. IPv6 addresses are global unicast addresses, so an interface with one is reachable from the internet without any public IP, as long as its subnet routes the client's address to an internet gateway and the network ACL and security groups allow it ([IP addressing for your VPCs and subnets](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html)).

- **eni-dual** (`subnet-dual`, route `::/0 -> igw-1`, IPv6 `2600:1f18:aaaa:ff01::10`, no public IPv4):
  - tcp/22 is exposed, but only to `2001:db8:abcd::/48`: the security group rule allows that range and network ACL rule 100 allows `::/0`.
  - tcp/443 is exposed to every internet address.
  - tcp/5432 is exposed to every internet address except `2001:db8:dead::/48`, which network ACL rule 120 denies before rule 130 allows the rest ([network ACL rules](https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html)).
  - tcp/8080 is allowed by the security group but has no network ACL rule, so the IPv6 `*` rule (32768) denies it.
  - tcp/3306 is allowed only from `fd00::/8`, unique local space, which is never an internet source.
  - Responses are allowed only to ports 49152-65535: all of the Windows ephemeral range, part of the Linux one, so every finding's return path is `partial`.
  - The IPv4 rule `tcp/22 from 0.0.0.0/0` exposes nothing over IPv4: the interface has no public IPv4 address.
- **eni-egress-only** (`subnet-egress-only`, route `::/0 -> eigw-1`): not exposed. An [egress-only internet gateway](https://docs.aws.amazon.com/vpc/latest/userguide/egress-only-internet-gateway.html) carries only connections the instance starts.
- **eni-ipv4-only**: no IPv6 address and no public IPv4, so not exposed.
