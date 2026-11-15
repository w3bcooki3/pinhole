# 15: hybrid

On-premises networks over Site-to-Site VPN (a virtual private gateway, and a transit gateway VPN attachment) and Direct Connect (a transit gateway Direct Connect gateway attachment). A connection from on-premises needs the server's subnet to route the replies back over the link it arrived on; the database's subnet has no such route. A network ACL denies RDP from the Direct Connect range. See `expected.json`.

- [How AWS Site-to-Site VPN works](https://docs.aws.amazon.com/vpn/latest/s2svpn/how_it_works.html)
- [Site-to-Site VPN routing options](https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNRoutingTypes.html)
- [Transit gateway VPN attachments](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-vpn-attachments.html)
- [Transit gateway attachments to a Direct Connect gateway](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-dcg-attachments.html)
