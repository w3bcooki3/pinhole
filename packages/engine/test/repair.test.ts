import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { evaluatePath, applyChanges, normalize, repairPath } from '../src/index.js';
import type { PathQuery } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const load = (f: string) => normalize(JSON.parse(readFileSync(join(here, '../../../fixtures', f, 'snapshot.json'), 'utf8')));
const tcp = (from: PathQuery['from'], to: PathQuery['to'], port: number): PathQuery => ({ from, to, protocol: 'tcp', port });

/** Every repair is checked independently: apply all its changes at once and evaluate again. */
function verified(f: string, q: PathQuery) {
  const m = load(f);
  const r = repairPath(m, q);
  if (r.verdict === 'repaired') {
    const after = evaluatePath(applyChanges(m, r.steps.map((s) => s.change)), q);
    expect(after.verdict).toBe('reachable');
    expect(after.returnPath).toBe('all');
  }
  return r;
}

describe('repairPath', () => {
  it('leaves a working path alone', () => {
    const r = verified('01-nacl-ephemeral-return', tcp({ internet: '198.51.100.7' }, { eni: 'eni-full' }, 443));
    expect(r.verdict).toBe('already');
    expect(r.steps).toEqual([]);
  });

  it('network ACL replies: an allow entry for the ephemeral range, numbered before the entry that decides', () => {
    const none = verified('01-nacl-ephemeral-return', tcp({ internet: '198.51.100.7' }, { eni: 'eni-none' }, 443));
    expect(none.verdict).toBe('repaired');
    expect(none.steps[0]!.change).toMatchObject({ kind: 'add-nacl-entry', naclId: 'acl-no-return', egress: true, ruleNumber: 32766, cidr: '198.51.100.7/32', fromPort: 32768, toPort: 65535 });
    // It opens the server to that client, and says so.
    expect(none.opens.map((o) => `${o.resourceId} ${o.status}`)).toEqual(['eni-none opened']);
    const partial = verified('01-nacl-ephemeral-return', tcp({ internet: '198.51.100.7' }, { eni: 'eni-linux' }, 443));
    expect(partial.verdict).toBe('repaired');
    expect(partial.steps[0]!.change).toMatchObject({ kind: 'add-nacl-entry', ruleNumber: 99 });
  });

  it('network ACL deny: an allow just below it', () => {
    const r = verified('15-hybrid', tcp({ ip: '172.16.5.5' }, { eni: 'eni-web' }, 3389));
    expect(r.steps.map((s) => s.change)).toEqual([{ kind: 'add-nacl-entry', naclId: 'acl-web', egress: false, ruleNumber: 49, action: 'allow', protocol: 'tcp', cidr: '172.16.5.5/32', fromPort: 3389, toPort: 3389 }]);
  });

  it('routes back: on-premises over the VPN gateway, the peer VPC over peering', () => {
    const onprem = verified('15-hybrid', tcp({ ip: '192.168.10.5' }, { eni: 'eni-db' }, 5432));
    expect(onprem.steps.map((s) => s.change)).toEqual([{ kind: 'add-route', routeTableId: 'rtb-db', destination: '192.168.0.0/16', targetId: 'vgw-1' }]);
    const peer = verified('05-peering-no-return-route', tcp({ eni: 'eni-a' }, { eni: 'eni-b' }, 22));
    expect(peer.steps.map((s) => s.change)).toEqual([{ kind: 'add-route', routeTableId: 'rtb-b', destination: '10.0.0.0/16', targetId: 'pcx-ab' }]);
  });

  it('several blockers in a row, and a security group rule from the source group in one VPC', () => {
    const r = verified('09-lateral-movement', tcp({ instance: 'i-web' }, { instance: 'i-db' }, 5432));
    expect(r.verdict).toBe('repaired');
    expect(r.steps.map((s) => s.change.kind)).toEqual(['add-nacl-entry', 'add-sg-rule']);
    expect(r.steps[1]!.change).toMatchObject({ groupId: 'sg-db', referencedGroupId: 'sg-web', fromPort: 5432 });
  });

  it('outbound from a private server goes through the NAT gateway, and says the table is shared', () => {
    const r = verified('14-outbound', tcp({ eni: 'eni-batch' }, { internet: '8.8.8.8' }, 443));
    expect(r.steps.map((s) => s.change)).toEqual([{ kind: 'add-route', routeTableId: 'rtb-isolated', destination: '0.0.0.0/0', targetId: 'nat-1' }]);
    expect(r.steps[0]!.notes.join(' ')).toMatch(/main route table/);
  });

  it('a private subnet with a public IP: a narrow route, with a warning and the exposure it opens', () => {
    const r = verified('06-public-ip-without-igw-route', tcp({ internet: '198.51.100.7' }, { eni: 'eni-private-eip' }, 22));
    expect(r.steps[0]!.change).toEqual({ kind: 'add-route', routeTableId: 'rtb-private', destination: '198.51.100.7/32', targetId: 'igw-1' });
    expect(r.steps[0]!.notes.join(' ')).toMatch(/public subnet/);
    expect(r.opens.length).toBeGreaterThan(0);
  });

  it('stops at a firewall rule, with advice', () => {
    const r = repairPath(load('12-network-firewall'), tcp({ internet: '198.51.100.7' }, { eni: 'eni-web' }, 23));
    expect(r.verdict).toBe('stuck');
    expect(r.stuck?.advice).toMatch(/firewall edge/);
  });
});
