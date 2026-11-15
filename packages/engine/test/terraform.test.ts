import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeBlastRadius, analyzeExposure, applyChanges, assertSnapshot, diffExposure, mapTerraformPlan, normalize, PlanError } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '../../..');
const model = () => {
  const s = JSON.parse(readFileSync(join(root, 'fixtures/09-lateral-movement/snapshot.json'), 'utf8'));
  assertSnapshot(s);
  return normalize(s);
};
const plan = () => JSON.parse(readFileSync(join(root, 'fixtures/plans/09-plan.json'), 'utf8'));

describe('Terraform plan mapping', () => {
  it('maps security group, inline rule and network ACL changes onto the snapshot', () => {
    const m = mapTerraformPlan(model(), plan());
    expect(m.changes).toEqual([
      { kind: 'add-sg-rule', groupId: 'sg-web', egress: false, protocol: '6', fromPort: 8443, toPort: 8443, cidr: '0.0.0.0/0' },
      { kind: 'revoke-sg-rule', ruleId: 'sgr-bastion-ssh-world' },
      { kind: 'add-sg-rule', groupId: 'sg-bastion', egress: false, protocol: '6', fromPort: 22, toPort: 22, cidr: '203.0.113.0/24' },
      { kind: 'add-nacl-entry', naclId: 'acl-default', egress: false, ruleNumber: 50, action: 'deny', protocol: '6', cidr: '0.0.0.0/0', fromPort: 443, toPort: 443 },
    ]);
    expect(m.skipped).toEqual([
      { address: 'aws_security_group_rule.new_group_ssh', type: 'aws_security_group_rule', reason: 'the security group is known only after apply and is not one this plan creates' },
      { address: 'aws_lb_listener.public', type: 'aws_lb_listener', reason: 'the plan does not say which load balancer the listener is on' },
    ]);
    expect(m.ignored).toBe(1);
  });

  it('gives the exposure the plan would create', () => {
    const before = model();
    const after = applyChanges(before, mapTerraformPlan(before, plan()).changes);
    const e0 = analyzeExposure(before);
    const e1 = analyzeExposure(after);
    const d = diffExposure(e0, e1, { before: analyzeBlastRadius(before, e0), after: analyzeBlastRadius(after, e1) });
    const by = (s: string) => d.deltas.filter((x) => x.status === s).map((x) => `${x.resourceId} ${x.protocol}/${x.ports?.from}`);
    expect(by('opened')).toEqual(['eni-web tcp/8443']);
    expect(by('narrowed')).toEqual(['eni-bastion tcp/22']);
    expect(by('closed')).toEqual(['eni-web tcp/443']);
  });

  it('skips what is not in the snapshot instead of guessing', () => {
    const m = mapTerraformPlan(model(), {
      resource_changes: [
        { address: 'aws_vpc_security_group_ingress_rule.x', mode: 'managed', type: 'aws_vpc_security_group_ingress_rule', change: { actions: ['create'], after: { security_group_id: 'sg-elsewhere', ip_protocol: 'tcp', from_port: 22, to_port: 22, cidr_ipv4: '0.0.0.0/0' }, after_unknown: {} } },
        { address: 'aws_route.default', mode: 'managed', type: 'aws_route', change: { actions: ['create'], after: { route_table_id: 'rtb-other', destination_cidr_block: '0.0.0.0/0', gateway_id: 'igw-1' }, after_unknown: {} } },
      ],
    });
    expect(m.changes).toEqual([]);
    expect(m.skipped.map((x) => x.reason)).toEqual(['security group sg-elsewhere is not in the snapshot', 'route table rtb-other is not in the snapshot']);
  });

  it('refuses values that would end up in commands, and wrong input shapes', () => {
    const m = mapTerraformPlan(model(), {
      resource_changes: [{ address: 'aws_vpc_security_group_ingress_rule.bad', mode: 'managed', type: 'aws_vpc_security_group_ingress_rule', change: { actions: ['create'], after: { security_group_id: 'sg-web', ip_protocol: 'tcp', from_port: 22, to_port: 22, prefix_list_id: 'pl-1; rm -rf ~' }, after_unknown: {} } }],
    });
    expect(m.changes).toEqual([]);
    expect(m.skipped[0]!.reason).toMatch(/not analysed: Change 1: "prefixListId"/);
    expect(() => mapTerraformPlan(model(), { planned_values: {} })).toThrow(PlanError);
    expect(() => mapTerraformPlan(model(), [])).toThrow(/terraform show -json/);
  });
});

describe('Terraform plans that create what they attach', () => {
  it('follows references to a security group created in the same plan, through a module output', () => {
    const before = model();
    const p = JSON.parse(readFileSync(join(root, 'fixtures/plans/09-plan-new-group.json'), 'utf8'));
    const m = mapTerraformPlan(before, p);
    expect(m.skipped).toEqual([]);
    expect(m.changes).toEqual([
      { kind: 'create-sg', groupId: 'sg-plan1', name: 'admin-access', vpcId: 'vpc-1' },
      { kind: 'add-sg-rule', groupId: 'sg-plan1', egress: false, protocol: '6', fromPort: 22, toPort: 22, cidr: '0.0.0.0/0' },
      { kind: 'add-sg-rule', groupId: 'sg-plan1', egress: false, protocol: '6', fromPort: 3389, toPort: 3389, cidr: '0.0.0.0/0' },
      { kind: 'attach-sg', eniId: 'eni-web', groupId: 'sg-plan1' },
    ]);
    const after = applyChanges(before, m.changes);
    const d = diffExposure(analyzeExposure(before), analyzeExposure(after));
    expect(d.deltas.filter((x) => x.status === 'opened').map((x) => `${x.resourceId} ${x.protocol}/${x.ports?.from}`).sort()).toEqual(['eni-web tcp/22', 'eni-web tcp/3389']);
  });

  it('skips an attachment whose groups cannot be told apart', () => {
    const p = JSON.parse(readFileSync(join(root, 'fixtures/plans/09-plan-new-group.json'), 'utf8'));
    // Two instances of the new group (count = 2): a reference without an index is ambiguous.
    const second = JSON.parse(JSON.stringify(p.resource_changes[0]));
    p.resource_changes[0].address = 'module.access.aws_security_group.admin[0]';
    second.address = 'module.access.aws_security_group.admin[1]';
    p.resource_changes.splice(1, 0, second);
    const m = mapTerraformPlan(model(), p);
    expect(m.changes.filter((c) => c.kind === 'attach-sg')).toEqual([]);
    expect(m.skipped.map((x) => `${x.address}: ${x.reason}`)).toEqual([
      'module.access.aws_vpc_security_group_ingress_rule.rdp: the security group is known only after apply and is not one this plan creates',
      'aws_instance.web: security groups depend on values known only after apply',
    ]);
  });

  describe('IPv6', () => {
    // Fixture 10: eni-dual in subnet-dual. sg-dual already allows 8080 from ::/0, but acl-dual has no IPv6 rule for it.
    const m10 = () => normalize(JSON.parse(readFileSync(join(root, 'fixtures/10-ipv6-exposure/snapshot.json'), 'utf8')));
    const rc = (address: string, type: string, actions: string[], before: unknown, after: unknown) => ({ address, mode: 'managed', type, change: { actions, before, after, after_unknown: {} } });
    const run = (changes: unknown[]) => {
      const model = m10();
      const mapped = mapTerraformPlan(model, { resource_changes: changes });
      const after = applyChanges(model, mapped.changes);
      return { mapped, diff: diffExposure(analyzeExposure(model), analyzeExposure(after)) };
    };
    const v6 = (d: { family?: string; resourceId: string; protocol: string; ports?: { from: number } }) => `${d.family ?? 'ipv4'} ${d.resourceId} ${d.protocol}/${d.ports?.from}`;

    it('opens a port over IPv6 when the plan adds the missing network ACL rule', () => {
      const { mapped, diff } = run([rc('aws_network_acl_rule.alt', 'aws_network_acl_rule', ['create'], null, { network_acl_id: 'acl-dual', rule_number: 140, egress: false, protocol: 'tcp', rule_action: 'allow', ipv6_cidr_block: '::/0', from_port: 8080, to_port: 8080 })]);
      expect(mapped.skipped).toEqual([]);
      expect(mapped.changes).toEqual([{ kind: 'add-nacl-entry', naclId: 'acl-dual', egress: false, ruleNumber: 140, action: 'allow', protocol: '6', cidr: '::/0', fromPort: 8080, toPort: 8080 }]);
      expect(diff.deltas.filter((d) => d.status === 'opened').map(v6)).toEqual(['ipv6 eni-dual tcp/8080']);
    });

    it('opens a port with an IPv6 security group rule, in either rule shape', () => {
      for (const r of [
        rc('aws_vpc_security_group_ingress_rule.https', 'aws_vpc_security_group_ingress_rule', ['create'], null, { security_group_id: 'sg-dual', ip_protocol: 'tcp', from_port: 22, to_port: 22, cidr_ipv6: '2001:db8::/32' }),
        rc('aws_security_group_rule.https', 'aws_security_group_rule', ['create'], null, { type: 'ingress', security_group_id: 'sg-dual', protocol: 'tcp', from_port: 22, to_port: 22, ipv6_cidr_blocks: ['2001:db8::/32'] }),
      ]) {
        const { mapped, diff } = run([r]);
        expect(mapped.skipped).toEqual([]);
        expect(diff.deltas.filter((d) => d.status === 'widened').map(v6)).toEqual(['ipv6 eni-dual tcp/22']);
      }
    });

    it('closes all IPv6 exposure when the plan removes the ::/0 route to the internet gateway', () => {
      const { mapped, diff } = run([rc('aws_route.v6', 'aws_route', ['delete'], { route_table_id: 'rtb-dual', destination_ipv6_cidr_block: '::/0', gateway_id: 'igw-1' }, null)]);
      expect(mapped.changes).toEqual([{ kind: 'remove-route', routeTableId: 'rtb-dual', destination: '::/0' }]);
      expect(diff.deltas.filter((d) => d.status === 'closed' && d.family === 'ipv6').map(v6).sort()).toEqual(['ipv6 eni-dual tcp/22', 'ipv6 eni-dual tcp/443', 'ipv6 eni-dual tcp/5432']);
    });

    it('matches an IPv6 rule being removed however its address is written', () => {
      const { mapped } = run([rc('aws_vpc_security_group_ingress_rule.ssh', 'aws_vpc_security_group_ingress_rule', ['delete'], { security_group_id: 'sg-dual', ip_protocol: 'tcp', from_port: 22, to_port: 22, cidr_ipv6: '2001:0db8:abcd:0000::/48' }, null)]);
      expect(mapped.changes).toEqual([{ kind: 'revoke-sg-rule', ruleId: 'sgr-ssh-v6-office' }]);
    });
  });

  describe('subnets, gateways and listeners', () => {
    const load = (f: string) => normalize(JSON.parse(readFileSync(join(root, `fixtures/${f}/snapshot.json`), 'utf8')));
    const rc = (address: string, type: string, actions: string[], before: unknown, after: unknown, after_unknown: Record<string, unknown> = {}) => ({ address, mode: 'managed', type, change: { actions, before, after, after_unknown } });
    const run = (fixture: string, changes: unknown[]) => {
      const model = load(fixture);
      const mapped = mapTerraformPlan(model, { resource_changes: changes });
      const diff = diffExposure(analyzeExposure(model), analyzeExposure(applyChanges(model, mapped.changes)));
      const by = (status: string) => diff.deltas.filter((d) => d.status === status).map((d) => `${d.family ?? 'ipv4'} ${d.resourceId} ${d.protocol}/${d.ports?.from}`).sort();
      return { mapped, by };
    };

    it('moving a subnet to a route table with an internet gateway route exposes it', () => {
      // Fixture 06: eni-private-eip has an Elastic IP, but its subnet routes the internet to a NAT gateway.
      const { mapped, by } = run('06-public-ip-without-igw-route', [rc('aws_route_table_association.private', 'aws_route_table_association', ['update'], { subnet_id: 'subnet-private', route_table_id: 'rtb-private' }, { subnet_id: 'subnet-private', route_table_id: 'rtb-public' })]);
      expect(mapped.changes).toEqual([{ kind: 'associate-route-table', subnetId: 'subnet-private', routeTableId: 'rtb-public' }]);
      expect(by('opened')).toEqual(['ipv4 eni-private-eip tcp/22']);
    });

    it('removing the association returns the subnet to the main route table', () => {
      const { mapped, by } = run('06-public-ip-without-igw-route', [rc('aws_route_table_association.public', 'aws_route_table_association', ['delete'], { subnet_id: 'subnet-public', route_table_id: 'rtb-public' }, null)]);
      expect(mapped.changes).toEqual([{ kind: 'associate-route-table', subnetId: 'subnet-public' }]);
      expect(by('closed')).toEqual(['ipv4 eni-public tcp/22']);
    });

    it('detaching the internet gateway closes everything behind it, and a second gateway is refused', () => {
      const { by } = run('06-public-ip-without-igw-route', [rc('aws_internet_gateway_attachment.main', 'aws_internet_gateway_attachment', ['delete'], { internet_gateway_id: 'igw-1', vpc_id: 'vpc-1' }, null)]);
      expect(by('closed')).toEqual(['ipv4 eni-public tcp/22']);
      const second = run('06-public-ip-without-igw-route', [rc('aws_internet_gateway.extra', 'aws_internet_gateway', ['create'], null, { vpc_id: 'vpc-1' }, { id: true })]);
      expect(second.mapped.changes).toEqual([]);
      expect(second.mapped.skipped[0]!.reason).toMatch(/vpc-1 already has internet gateway igw-1/);
    });

    it('a new internet gateway and a route to it, in one plan, are checked together', () => {
      const plan = [
        rc('aws_internet_gateway_attachment.main', 'aws_internet_gateway_attachment', ['delete'], { internet_gateway_id: 'igw-1', vpc_id: 'vpc-1' }, null),
        rc('aws_internet_gateway.new', 'aws_internet_gateway', ['create'], null, { vpc_id: 'vpc-1' }, { id: true }),
        rc('aws_route.private_out', 'aws_route', ['create'], null, { route_table_id: 'rtb-private', destination_cidr_block: '198.51.100.0/24' }, { gateway_id: true }),
      ];
      const model = load('06-public-ip-without-igw-route');
      const config = { configuration: { root_module: { resources: [{ address: 'aws_route.private_out', expressions: { gateway_id: { references: ['aws_internet_gateway.new.id', 'aws_internet_gateway.new'] } } }] } } };
      const mapped = mapTerraformPlan(model, { resource_changes: plan, ...config });
      expect(mapped.changes).toContainEqual({ kind: 'attach-igw', igwId: 'igw-plan1', vpcId: 'vpc-1' });
      expect(mapped.changes).toContainEqual({ kind: 'add-route', routeTableId: 'rtb-private', destination: '198.51.100.0/24', targetId: 'igw-plan1' });
      const after = analyzeExposure(applyChanges(model, mapped.changes));
      // eni-private-eip answers 198.51.100.0/24 through the new gateway now; everything else still goes to the NAT gateway.
      expect(after.findings.filter((f) => f.resourceId === 'eni-private-eip').map((f) => f.sourceRanges)).toEqual([['198.51.100.0/24']]);
    });

    it('a new listener on an NLB without security groups is exposed at once', () => {
      const lb = 'arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/api/fedcba9876543210';
      const { mapped, by } = run('08-nlb-client-ip-preservation', [rc('aws_lb_listener.ssh', 'aws_lb_listener', ['create'], null, { load_balancer_arn: lb, port: 2222, protocol: 'TCP', default_action: [{ type: 'forward' }] }, { arn: true })]);
      expect(mapped.changes[0]).toMatchObject({ kind: 'add-listener', loadBalancerArn: lb, port: 2222, protocol: 'TCP', targetGroupArns: [] });
      expect(by('opened')).toEqual([`ipv4 ${lb} tcp/2222`]);
    });

    it('moving a subnet to another network ACL changes what it lets in', () => {
      // Fixture 10: acl-dual allows only 22, 443 and 5432 over IPv6; acl-default allows everything.
      const { mapped, by } = run('10-ipv6-exposure', [rc('aws_network_acl_association.dual', 'aws_network_acl_association', ['update'], { subnet_id: 'subnet-dual', network_acl_id: 'acl-dual' }, { subnet_id: 'subnet-dual', network_acl_id: 'acl-default' })]);
      expect(mapped.changes).toEqual([{ kind: 'associate-nacl', subnetId: 'subnet-dual', naclId: 'acl-default' }]);
      expect(by('opened')).toContain('ipv6 eni-dual tcp/8080');
    });
  });
});
