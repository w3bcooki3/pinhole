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
      { address: 'aws_lb_listener.public', type: 'aws_lb_listener', reason: 'aws_lb_listener changes are not analysed' },
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
        { address: 'aws_vpc_security_group_ingress_rule.v6', mode: 'managed', type: 'aws_vpc_security_group_ingress_rule', change: { actions: ['create'], after: { security_group_id: 'sg-web', ip_protocol: 'tcp', from_port: 22, to_port: 22, cidr_ipv6: '::/0' }, after_unknown: {} } },
      ],
    });
    expect(m.changes).toEqual([]);
    expect(m.skipped.map((x) => x.reason)).toEqual(['security group sg-elsewhere is not in the snapshot', 'route table rtb-other is not in the snapshot', 'IPv6 source ::/0 is not analysed']);
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
});
