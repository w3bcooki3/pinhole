# 17: Savings

Network resources that cost money and serve nothing, next to look-alikes that do serve something:

- **Unused, so removing them changes nothing but the bill.** An Elastic IP attached to nothing; a NAT gateway that only an unassociated route table points to; an internet-facing load balancer whose only target group is empty; two servers whose public IPs no internet address can reach and which cannot send out through them either (one auto-assigned, one an Elastic IP).
- **Not flagged.** A web server the internet reaches on 443; a server that uses its public IP only to send out; the NAT gateway both private subnets use.
- **Per gigabyte, reported for checking.** A private subnet that reaches S3 through the NAT gateway with no gateway endpoint; a subnet in us-east-1b whose NAT gateway is in us-east-1a. Its route table already has the S3 gateway endpoint, so it is not reported for S3.

Prices are us-east-1 list prices. See `expected.json`.

- [Amazon VPC pricing](https://aws.amazon.com/vpc/pricing/)
- [Elastic Load Balancing pricing](https://aws.amazon.com/elasticloadbalancing/pricing/)
- [Gateway endpoints for Amazon S3](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html)
- [Removing auto-assigned public IPv4 addresses](https://aws.amazon.com/about-aws/whats-new/2024/04/removing-adding-auto-assigned-public-ipv4-address/)
