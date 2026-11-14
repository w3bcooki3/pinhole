# 02: Security group to security group references

`sg-db` has one inbound rule: TCP 5432 from `sg-web`. Two interfaces sit in the same subnet. `eni-web` is in `sg-web` and `eni-other` is not. The database interface also has an Elastic IP in a subnet with an internet gateway route, and the default NACL allows everything.

| From | To | Expected |
|---|---|---|
| `eni-web` (member of `sg-web`) | `eni-db:5432` | reachable via `sgr-db-from-web` |
| `eni-other` (same subnet, not a member) | `eni-db:5432` | blocked at the destination security group |
| internet `198.51.100.7` | `eni-db:5432` | blocked at the destination security group |

Why: a rule that references a security group "applies to all instances associated with that group". The traffic is matched on the private IP addresses of those instances' network interfaces. Internet clients have no interface in the account, so they can never match a reference, whatever the destination's public IP or routes.

- https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html (Security group references)

Exposure must therefore not report `eni-db:5432`, even though the database has a public IP and an internet gateway route.
