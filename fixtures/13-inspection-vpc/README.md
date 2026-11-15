# 13: inspection VPC behind a transit gateway

Two spoke VPCs reach each other only through an inspection VPC: the transit gateway sends spoke traffic to the inspection VPC's attachment, whose subnet routes it to a Network Firewall endpoint, which hands it back to the transit gateway. See `expected.json`.
