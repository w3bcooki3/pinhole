# 12: Network Firewall at the internet edge

An internet gateway route table sends traffic for the public subnet to an AWS Network Firewall endpoint, and the subnet sends replies back through it. The security groups allow everything they list; the firewall narrows it. See `expected.json`.
