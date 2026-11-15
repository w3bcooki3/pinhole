import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { firewallHygiene, normalize } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const base = () => JSON.parse(readFileSync(join(here, '../../../fixtures/12-network-firewall/snapshot.json'), 'utf8'));
const STATELESS = 'arn:aws:network-firewall:us-east-1:111122223333:stateless-rulegroup/no-telnet';
const STATEFUL = 'arn:aws:network-firewall:us-east-1:111122223333:stateful-rulegroup/web-in';
const POLICY = 'arn:aws:network-firewall:us-east-1:111122223333:firewall-policy/edge-policy';

type Raw = { Priority: number; RuleDefinition: { Actions: string[]; MatchAttributes: Record<string, unknown> } };
const statelessRules = (snap: { networkFirewall: { RuleGroups: Record<string, { RuleGroup: { RulesSource: { StatelessRulesAndCustomActions: { StatelessRules: Raw[] } } } }> } }) =>
  snap.networkFirewall.RuleGroups[STATELESS]!.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules;
const findings = (snap: unknown) => firewallHygiene(normalize(snap));
const by = (fs: ReturnType<typeof findings>, rule: string) => fs.find((f) => f.ruleId === rule);

describe('firewall rule hygiene', () => {
  it('finds only the planted rule in the example policies', () => {
    expect(findings(base()).map((f) => `${f.code} ${f.ruleId}`)).toEqual(['firewall-shadowed-rule web-in sid 104']);
    expect(findings(JSON.parse(readFileSync(join(here, '../../../fixtures/13-inspection-vpc/snapshot.json'), 'utf8')))).toEqual([]);
  });

  it('stateless: redundant and shadowed rules, by priority', () => {
    const snap = base();
    statelessRules(snap).push(
      { Priority: 2, RuleDefinition: { Actions: ['aws:drop'], MatchAttributes: { Protocols: [6], Sources: [{ AddressDefinition: '10.0.0.0/8' }], DestinationPorts: [{ FromPort: 23, ToPort: 23 }] } } },
      { Priority: 3, RuleDefinition: { Actions: ['aws:pass'], MatchAttributes: { Protocols: [6], DestinationPorts: [{ FromPort: 23, ToPort: 23 }] } } },
      { Priority: 4, RuleDefinition: { Actions: ['aws:pass'], MatchAttributes: { Protocols: [6], DestinationPorts: [{ FromPort: 20, ToPort: 25 }] } } },
    );
    const fs = findings(snap);
    expect(by(fs, 'no-telnet#2')).toMatchObject({ code: 'firewall-redundant-rule', severity: 'info' });
    expect(by(fs, 'no-telnet#3')).toMatchObject({ code: 'firewall-shadowed-rule', severity: 'low' });
    expect(by(fs, 'no-telnet#3')!.detail).toMatch(/no-telnet#1 \(drop\)/);
    expect(by(fs, 'no-telnet#4')).toBeUndefined();
  });

  it('stateful, strict order: a drop behind a pass (sid 104, in the fixture), an empty rule, conditions and directions', () => {
    const snap = base();
    const g = snap.networkFirewall.RuleGroups[STATEFUL].RuleGroup.RulesSource;
    g.RulesString += [
      '',
      'pass tcp 203.0.113.9 any -> $HOME_NET 443 (flow:to_server; sid:106;)',
      'drop tcp any any -> $HOME_NET 8080 (sid:107;)',
      'pass tcp [10.0.0.0/8,!10.0.0.0/8] any -> any any (sid:108;)',
      'pass tcp $OFFICE any <> $HOME_NET 22 (sid:109;)',
      'pass tcp any any -> $HOME_NET 443 (sid:110;)',
    ].join('\n');
    const fs = findings(snap);
    expect(by(fs, 'web-in sid 104')).toMatchObject({ code: 'firewall-shadowed-rule', severity: 'medium' });
    expect(by(fs, 'web-in sid 106')).toMatchObject({ code: 'firewall-redundant-rule', severity: 'info' });
    // sid 102 matches on the application protocol, so it cannot hide 107.
    expect(by(fs, 'web-in sid 107')).toBeUndefined();
    expect(by(fs, 'web-in sid 108')).toMatchObject({ code: 'firewall-rule-matches-nothing' });
    // The reverse direction of 109 and the replies of 110 are not covered.
    expect(by(fs, 'web-in sid 109')).toBeUndefined();
    expect(by(fs, 'web-in sid 110')).toBeUndefined();
  });

  it('stateful, default action order: every pass rule comes first', () => {
    const snap = base();
    snap.networkFirewall.FirewallPolicies[POLICY].FirewallPolicy.StatefulEngineOptions.RuleOrder = 'DEFAULT_ACTION_ORDER';
    snap.networkFirewall.FirewallPolicies[POLICY].FirewallPolicy.StatefulDefaultActions = [];
    snap.networkFirewall.FirewallPolicies[POLICY].FirewallPolicy.StatefulRuleGroupReferences = [{ ResourceArn: STATEFUL }];
    const g = snap.networkFirewall.RuleGroups[STATEFUL];
    g.RuleGroup.StatefulRuleOptions.RuleOrder = 'DEFAULT_ACTION_ORDER';
    g.RuleGroup.RulesSource.RulesString = `drop tcp any any -> $HOME_NET 443 (flow:to_server; sid:1;)\n${g.RuleGroup.RulesSource.RulesString}`;
    const fs = findings(snap);
    expect(by(fs, 'web-in sid 1')).toMatchObject({ code: 'firewall-shadowed-rule', severity: 'medium' });
    expect(by(fs, 'web-in sid 1')!.detail).toMatch(/web-in sid 100 \(pass\)/);
  });

  it('reports an empty group', () => {
    const snap = base();
    snap.networkFirewall.RuleGroups[STATEFUL].RuleGroup.RulesSource.RulesString = '# nothing yet';
    expect(findings(snap).map((f) => f.code)).toContain('firewall-empty-group');
  });

  it('agrees with brute force on random stateless rule lists', () => {
    let seed = 7;
    const rnd = (n: number) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed % n);
    const range = (n: number) => {
      const a = rnd(n);
      const b = a + rnd(n - a);
      return [a, b] as const;
    };
    for (let run = 0; run < 150; run++) {
      const snap = base();
      const rules: Raw[] = [];
      const count = 2 + rnd(6);
      for (let i = 0; i < count; i++) {
        const m: Record<string, unknown> = {};
        if (rnd(3)) m.Protocols = rnd(2) ? [6] : [6, 17];
        if (rnd(2)) {
          const [a, b] = range(8);
          m.Sources = Array.from({ length: b - a + 1 }, (_, k) => ({ AddressDefinition: `10.0.0.${a + k}/32` }));
        }
        if (rnd(2)) {
          const [a, b] = range(8);
          m.DestinationPorts = [{ FromPort: a, ToPort: b }];
        }
        if (rnd(2)) {
          const [a, b] = range(8);
          m.SourcePorts = [{ FromPort: a, ToPort: b }];
        }
        rules.push({ Priority: i + 1, RuleDefinition: { Actions: [['aws:pass', 'aws:drop', 'aws:forward_to_sfe'][rnd(3)]!], MatchAttributes: m } });
      }
      statelessRules(snap).splice(0, 1, ...rules);
      const flagged = new Set(findings(snap).filter((f) => f.code === 'firewall-redundant-rule' || f.code === 'firewall-shadowed-rule').map((f) => f.ruleId));
      // Brute force over a domain that includes values outside every rule.
      const first = new Set<number>();
      const inR = (v: number, rs: { FromPort: number; ToPort: number }[] | undefined) => !rs || rs.some((r) => v >= r.FromPort && v <= r.ToPort);
      for (const proto of [6, 17, 1]) for (let src = 0; src < 10; src++) for (let sp = 0; sp < 10; sp++) for (let dp = 0; dp < 10; dp++) {
        const hit = rules.find((r) => {
          const m = r.RuleDefinition.MatchAttributes as { Protocols?: number[]; Sources?: { AddressDefinition: string }[]; DestinationPorts?: { FromPort: number; ToPort: number }[]; SourcePorts?: { FromPort: number; ToPort: number }[] };
          return (!m.Protocols || m.Protocols.includes(proto)) && (!m.Sources || m.Sources.some((s) => s.AddressDefinition === `10.0.0.${src}/32`)) && inR(dp, m.DestinationPorts) && inR(sp, m.SourcePorts);
        });
        if (hit) first.add(hit.Priority);
      }
      for (const r of rules) expect(flagged.has(`no-telnet#${r.Priority}`), `run ${run} rule ${r.Priority}: ${JSON.stringify(rules)}`).toBe(!first.has(r.Priority));
    }
  });
});
