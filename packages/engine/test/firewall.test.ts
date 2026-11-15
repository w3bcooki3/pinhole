import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeExposure, evaluatePath, normalize } from '../src/index.js';
import { parseSuricata } from '../src/firewall.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');
/* eslint-disable @typescript-eslint/no-explicit-any */
const fixture = (): any => JSON.parse(readFileSync(join(root, '12-network-firewall', 'snapshot.json'), 'utf8'));
const POLICY = 'arn:aws:network-firewall:us-east-1:111122223333:firewall-policy/edge-policy';
const WEB = 'arn:aws:network-firewall:us-east-1:111122223333:stateful-rulegroup/web-in';
const STATELESS = 'arn:aws:network-firewall:us-east-1:111122223333:stateless-rulegroup/no-telnet';
const policyOf = (s: any) => s.networkFirewall.FirewallPolicies[POLICY].FirewallPolicy;
const path = (s: any, port: number, from = '8.8.8.8', to = 'eni-web') => evaluatePath(normalize(s), { from: { internet: from }, to: { eni: to }, protocol: 'tcp', port });
const withRules = (rules: string, order: 'STRICT_ORDER' | 'DEFAULT_ACTION_ORDER' = 'STRICT_ORDER') => {
  const s = fixture();
  s.networkFirewall.RuleGroups[WEB].RuleGroup.RulesSource.RulesString = rules;
  policyOf(s).StatefulRuleGroupReferences = [{ ResourceArn: WEB, Priority: 10 }];
  if (order === 'DEFAULT_ACTION_ORDER') {
    delete policyOf(s).StatefulEngineOptions;
    delete policyOf(s).StatefulDefaultActions;
    policyOf(s).StatefulRuleGroupReferences = [{ ResourceArn: WEB }];
  }
  return s;
};

describe('Suricata rules', () => {
  it('reads headers, options, lists, negation and continued lines, and says what it cannot read', () => {
    const { rules, unparsed } = parseSuricata(
      [
        '# a comment',
        'pass tcp [10.0.0.0/8,!10.9.0.0/16] any -> $HOME_NET [80,443,8000:8080] (msg:"web; with a semicolon"; sid:1; rev:2;)',
        'drop udp any any <> any 53 \\',
        '  (msg:"dns"; sid:2;)',
        'alert http any any -> any any (http.host; content:"example.com"; sid:3;)',
        'not a rule at all',
        'pass sctp any any -> any any (sid:4;)',
      ].join('\n'),
    );
    expect(rules.map((r) => [r.action, r.protocol, r.sid, r.bidirectional])).toEqual([
      ['pass', 'tcp', '1', false],
      ['drop', 'udp', '2', true],
      ['alert', 'http', '3', false],
    ]);
    expect(rules[0]!.conditional).toBeUndefined();
    expect(rules[2]!.conditional).toMatch(/the traffic is HTTP and it matches http\.host, content/);
    expect(unparsed.map((u) => u.reason)).toEqual(['not a rule Pinhole can read', 'protocol "sctp" is not one Pinhole knows']);
  });
});

describe('Network Firewall decisions', () => {
  it('default action order: pass rules win over drop rules wherever they are written', () => {
    const s = withRules('drop tcp any any -> $HOME_NET 9000 (sid:1;)\npass tcp any any -> $HOME_NET 9000 (sid:2;)', 'DEFAULT_ACTION_ORDER');
    s.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: 'sgr-9000', GroupId: 'sg-web', IsEgress: false, IpProtocol: 'tcp', FromPort: 9000, ToPort: 9000, CidrIpv4: '0.0.0.0/0' });
    expect(path(s, 9000).verdict).toBe('reachable');
    // Traffic no rule matches passes with the default order (no default actions).
    expect(path(s, 3389).verdict).toBe('reachable');
  });

  it('strict order: the first decisive rule wins; drop_established leaves nothing usable', () => {
    const s = withRules('drop tcp any any -> $HOME_NET 443 (sid:1;)\npass tcp any any -> $HOME_NET 443 (sid:2;)');
    const r = path(s, 443);
    expect(r.verdict).toBe('blocked');
    expect(r.blockedAt?.detail).toMatch(/web-in sid 1 drops it/);
    const t = withRules('pass tcp any any -> $HOME_NET 443 (sid:2;)');
    policyOf(t).StatefulDefaultActions = ['aws:drop_established'];
    expect(path(t, 443).verdict).toBe('reachable');
    expect(path(t, 3389).verdict).toBe('blocked');
  });

  it('a rule on the reply direction can drop the connection', () => {
    const s = withRules('pass tcp any any -> $HOME_NET 443 (flow:to_server; sid:1;)\ndrop tcp $HOME_NET 443 -> any any (sid:2;)', 'DEFAULT_ACTION_ORDER');
    expect(path(s, 443).verdict).toBe('reachable'); // the pass on the request decides the flow first
    const t = withRules('drop tcp $HOME_NET 443 -> any any (sid:2;)', 'DEFAULT_ACTION_ORDER');
    expect(path(t, 443).verdict).toBe('blocked');
  });

  it('stateless rules must pass the reply too, and are cut by the client port', () => {
    const s = fixture();
    policyOf(s).StatelessDefaultActions = ['aws:drop'];
    s.networkFirewall.RuleGroups[STATELESS].RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules = [
      { Priority: 1, RuleDefinition: { Actions: ['aws:pass'], MatchAttributes: { Protocols: [6], DestinationPorts: [{ FromPort: 443, ToPort: 443 }] } } },
    ];
    // The request passes, the reply has no rule: dropped by the default.
    const r = path(s, 443);
    expect(r.verdict).toBe('blocked');
    expect(r.blockedAt?.detail).toMatch(/reply: no stateless rule matches; the default action drops it/);
    // A reply rule for Linux ephemeral ports only: Windows clients cannot complete.
    s.networkFirewall.RuleGroups[STATELESS].RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules.push({ Priority: 2, RuleDefinition: { Actions: ['aws:pass'], MatchAttributes: { Protocols: [6], SourcePorts: [{ FromPort: 443, ToPort: 443 }], DestinationPorts: [{ FromPort: 32768, ToPort: 61000 }] } } });
    const p = path(s, 443);
    expect(p.verdict).toBe('reachable');
    expect(p.returnPath).toBe('partial');
    expect(p.returnProfiles?.find((x) => x.profile.startsWith('Linux'))?.coverage).toBe('all');
    expect(p.returnProfiles?.find((x) => x.profile.startsWith('Windows'))?.coverage).toBe('partial');
  });

  it('DROP_TO_ALERT turns a group\'s drops into alerts', () => {
    const s = withRules('drop tcp any any -> $HOME_NET 443 (sid:1;)', 'DEFAULT_ACTION_ORDER');
    expect(path(s, 443).verdict).toBe('blocked');
    policyOf(s).StatefulRuleGroupReferences = [{ ResourceArn: WEB, Override: { Action: 'DROP_TO_ALERT' } }];
    expect(path(s, 443).verdict).toBe('reachable');
  });

  it('policy variables override HOME_NET for every group', () => {
    const s = withRules('pass tcp any any -> $HOME_NET 443 (sid:1;)');
    expect(path(s, 443).verdict).toBe('reachable');
    policyOf(s).PolicyVariables = { RuleVariables: { HOME_NET: { Definition: ['10.0.0.0/24'] } } };
    expect(path(s, 443).verdict).toBe('blocked');
  });

  it('a domain allow list only applies from HOME_NET outwards, and depends on the host name', () => {
    const s = fixture();
    s.networkFirewall.RuleGroups[WEB].RuleGroup.RulesSource = { RulesSourceList: { Targets: ['.example.com'], TargetTypes: ['TLS_SNI'], GeneratedRulesType: 'ALLOWLIST' } };
    policyOf(s).StatefulRuleGroupReferences = [{ ResourceArn: WEB }];
    delete policyOf(s).StatefulEngineOptions;
    delete policyOf(s).StatefulDefaultActions;
    const inbound = path(s, 443);
    expect(inbound.verdict).toBe('reachable');
    expect(inbound.hops.some((h) => h.caveat)).toBe(false);
  });

  it('a rule group that is not in the snapshot makes traffic it could decide a caveat, never a silent pass', () => {
    const s = fixture();
    delete s.networkFirewall.RuleGroups[WEB];
    const m = normalize(s);
    expect(m.warnings.map((w) => w.code)).toContain('firewall-rule-group-missing');
    const f = analyzeExposure(m).findings.find((x) => x.ports.from === 3389);
    expect(f?.caveats?.[0]).toMatch(/decides this by the traffic itself|cannot show/);
  });

  it('a third-party appliance is followed and assumed to pass, and every finding says so', () => {
    const s = fixture();
    delete s.networkFirewall;
    const m = normalize(s);
    const report = analyzeExposure(m);
    expect(report.warnings.map((w) => w.code)).toContain('third-party-appliance');
    const ssh = report.findings.find((f) => f.resourceId === 'eni-web' && f.ports.from <= 22 && f.ports.to >= 22)!;
    expect(ssh.inspectedBy).toEqual(['vpce-fw1']);
    expect(ssh.caveats?.[0]).toMatch(/rules are not visible to AWS APIs/);
    expect(report.findings.some((f) => f.resourceId === 'eni-db')).toBe(true);
  });

  it('refuses rule text with control characters', () => {
    const s = fixture();
    s.networkFirewall.RuleGroups[WEB].RuleGroup.RulesSource.RulesString = 'pass tcp any any -> any 443 (sid:1;)\u0007';
    expect(() => normalize(s)).toThrow(/contains control characters/);
  });
});
