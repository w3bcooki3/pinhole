# 16: PrivateLink

Two endpoint services this account provides (one open to every AWS account without approval, one shared with a partner whose load balancer does not apply its security group to PrivateLink traffic), and three VPC endpoints (an S3 gateway endpoint with the default policy, a restricted Secrets Manager endpoint, and an endpoint to another account's service). See `expected.json`.

- [Share your services through AWS PrivateLink](https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-share-your-services.html)
- [Configure an endpoint service](https://docs.aws.amazon.com/vpc/latest/privatelink/configure-endpoint-service.html)
- [Security groups for your Network Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html)
- [Control access to VPC endpoints using endpoint policies](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html)
