# 09: Lateral movement

A three-tier VPC: a bastion and a web server in the public subnet, an app server in a private subnet, and a database and a cache in a data subnet. The data subnet's network ACL only admits Postgres and Redis from the app subnet, and SSH from the VPC.

| Resource | Security group rules (inbound) | Reachable from the internet |
|---|---|---|
| bastion `eni-bastion` | 22 from `0.0.0.0/0` | yes, SSH |
| web `eni-web` | 443 from `0.0.0.0/0`, 443 from `203.0.113.0/24` (redundant), 22 from `sg-bastion` | yes, HTTPS |
| app `eni-app` | 8080 from `sg-web`, 22 from `sg-bastion`, 9000 from `sg-deleted` (stale) | no |
| orders-db `eni-db` | 5432 from `sg-app`, 22 from `10.0.0.0/16` | no |
| session-cache `eni-cache` | 6379 from `10.0.0.0/8` | no |

## What an attacker reaches

From the bastion: SSH to the app server (by group reference), then Postgres on the database and Redis on the cache. That is the top chain.

From the web server: only 8080 on the app server, which is not a remote administration service, so the attacker does not get a foothold there. But `sgr-db-ssh-vpc` allows SSH to the database from the whole VPC, so the web server can SSH straight to the database, and from the database reach Redis. The data subnet's ACL admits Redis only from the app subnet, but the database and the cache share a subnet, and network ACLs only filter traffic entering and leaving a subnet.

- Security group references: https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
- Network ACLs filter traffic at the subnet boundary: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html

Removing `sgr-db-ssh-vpc` changes nothing about internet exposure, but closes every chain that goes through SSH to the database. `whatIf` in `expected.json` asserts this.

## Hygiene

- `acl-data` inbound rule 120 repeats rule 100 and can never match (rules are evaluated in order, lowest first: https://docs.aws.amazon.com/vpc/latest/userguide/nacl-basics.html).
- `sgr-web-https-partner` is covered by `sgr-web-https`.
- `sgr-app-old` refers to `sg-deleted`, which is not in the snapshot.
- `sg-unused` is attached to nothing but allows all traffic from anywhere.
- `sgr-db-ssh-vpc` and `sgr-cache-redis` admit whole private ranges to SSH and Redis.
