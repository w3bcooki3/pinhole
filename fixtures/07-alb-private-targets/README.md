# 07: Load balancer in front of private instances

An internet-facing ALB (`web`) has nodes in `subnet-pub-a` and `subnet-pub-b`. Its listener on 443 forwards to target group `app` (port 8080) with two instances in `subnet-app`, which has no internet gateway route and no public IPs.

Security groups:
- `sg-alb`: inbound 443 from `0.0.0.0/0`, outbound 8080 to 10.0.10.0/24.
- `sg-app` (on `i-app1`): inbound 8080 from `sg-alb`. This is the setup AWS recommends.
- `sg-app-wrong` (on `i-app2`): inbound 8080 from 10.0.10.0/24, the targets' own subnet. That does not include the ALB nodes (10.0.1.50 and 10.0.2.50).

NACLs are custom and tight, so they are tested too:
- `acl-public` allows 443 in from anywhere, return traffic from the app subnet on 1024-65535, and 1024-65535 out.
- `acl-app` allows 8080 in from the VPC and 1024-65535 out to the VPC. Elastic Load Balancing uses ephemeral ports 1024-65535.

Expected:
- The exposure report lists the ALB on TCP 443, not its node interfaces separately and not the instances.
- Behind the listener, `i-app1:8080` is reachable from both ALB nodes and `i-app2:8080` is blocked at its security group.

Docs:
- ALB security groups and recommended rules: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html
- Target security groups must allow the load balancer: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-register-targets.html
- ELB ephemeral range 1024-65535: https://docs.aws.amazon.com/vpc/latest/userguide/custom-network-acl.html

M1 does not model health checks: `HealthCheckPort` is `traffic-port`, so it is the same port as the traffic anyway.
