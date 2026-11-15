# 12: Network Firewall at the internet edge

An internet gateway route table sends traffic for the public subnet to an AWS Network Firewall endpoint, and the subnet sends replies back through it. The security groups allow everything they list; the firewall narrows it. One stateful rule (sid 104, a drop of SSH from the office) never applies, because an earlier pass rule decides that traffic: rule hygiene reports it. See `expected.json`.
