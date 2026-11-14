# Terraform plan fixtures

Hand-written `terraform show -json PLANFILE` output, used by the `pinhole plan` tests. The format is described in [Terraform's JSON output format](https://developer.hashicorp.com/terraform/internals/json-format).

`09-plan.json` is a plan against [fixture 09](../09-lateral-movement). It:

- opens tcp/8443 on the web server to everyone (`aws_vpc_security_group_ingress_rule`): new exposure;
- narrows SSH on the bastion from `0.0.0.0/0` to `203.0.113.0/24` (inline rules of `aws_security_group`): narrower exposure;
- adds network ACL rule 50 denying tcp/443 from anywhere (`aws_network_acl_rule`): closes HTTPS to the web server;
- adds a rule to a security group created in the same plan, whose ID is unknown: skipped, with the reason;
- adds a load balancer listener: a network type Pinhole does not analyse from plans, skipped;
- creates an S3 bucket and reads a data source: ignored, not network changes.

`09-plan-new-group.json` creates a security group in a module (SSH from anywhere inline, plus an RDP rule as a separate resource that refers to the group) and attaches it to the existing web server through a module output. Pinhole follows the references and reports SSH and RDP newly open on the web server.
