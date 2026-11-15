# 11: Attack chains across accounts

Two snapshots, two accounts, one VPC peering connection (`pcx-0c11`) that appears in both.

- **Account 111122223333** (`account-a/snapshot.json`): `bastion` (`i-0a-bastion`, 10.0.1.10) has a public IP and allows SSH from `0.0.0.0/0`. Its route table sends 10.20.0.0/16 to `pcx-0c11`.
- **Account 444455556666** (`account-b/snapshot.json`): the data subnet routes 10.0.0.0/16 back to `pcx-0c11`; the cache subnet has only its local route.

| From | To | Expected | Why |
|---|---|---|---|
| internet → `bastion` | `orders-db` tcp/5432 | attack chain, critical | `sgr-0b-db-from-a` allows 10.0.0.0/16, and both sides route to each other |
| internet → `bastion` | `ops-admin` tcp/22 | attack chain, critical | `sgr-0b-admin-ssh` references `sg-0a-bastion`; AWS allows that across same-Region peering |
| internet → `bastion` | `cache` tcp/6379 | blocked | the request arrives, but the cache subnet has no route back to 10.0.0.0/16 |

Analysed one at a time, neither snapshot shows any chain: account A stops at the peering connection, and account B has nothing on the internet. Only by joining them do the two chains appear.

Variations covered by `packages/engine/test/join.test.ts`:

- With the peering connection across Regions, the reference no longer applies, so `ops-admin` drops out and `orders-db` stays.
- Without B's route back, no chain is left.
- The fix plan is one change on the bastion's SSH rule, which cuts both chains at their entry point, rather than one change per chain.

Sources:

- https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html
- https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-security-groups.html
- https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html
