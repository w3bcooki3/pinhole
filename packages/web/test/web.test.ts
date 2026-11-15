import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import { beforeAll, describe, expect, it } from 'vitest';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
let html = '';

beforeAll(() => {
  execFileSync('node', [join(root, 'scripts/build-web.mjs')], { stdio: 'ignore' });
  html = readFileSync(join(root, 'site/index.html'), 'utf8');
}, 60_000);

type Api = { loadText: (t: string, n: string) => boolean; go: (r: string, patch?: Record<string, unknown>) => void };
function page() {
  const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'https://pinhole.test/' });
  const w = dom.window as unknown as Window & { pinhole: Api };
  return { w, doc: w.document, api: w.pinhole };
}
const fixture = (name: string) => readFileSync(join(root, 'fixtures', name, 'snapshot.json'), 'utf8');
const text = (doc: Document, sel: string) => doc.querySelector(sel)?.textContent ?? '';

describe('web console', () => {
  it('follows attack chains across linked accounts in the demo', () => {
    const { doc, api } = page();
    api.go('blast', { blastKey: 'joined/111122223333/eu-central-1/2026-11-12T09:41:00Z+444455556666/eu-central-1/2026-11-12T09:42:00Z', chain: '' });
    const head = text(doc, '.ph');
    expect(head).toContain('Across accounts: 111122223333 / eu-central-1 + 444455556666 / eu-central-1');
    expect(head).toContain('peering connection pcx-0c11');
    const rows = [...doc.querySelectorAll('#chains tbody tr')].map((r) => r.textContent ?? '');
    expect(rows).toHaveLength(2);
    expect(rows.join('\n')).toMatch(/111122223333 \/ eu-central-1 → 444455556666 \/ eu-central-1/);
    // The dashboard plan includes the one change that cuts both, in the account that owns the rule.
    api.go('dashboard');
    expect(text(doc, '#plan')).toMatch(/sgr-0a-ssh-world/);
  });
  it('shows the firewall on the path, and what it could not decide', () => {
    const { doc, api } = page();
    api.go('issues');
    const rows = [...doc.querySelectorAll('table.t tbody tr')] as HTMLElement[];
    const row = rows.find((r) => /777788889999/.test(r.textContent ?? '') && /8080/.test(r.textContent ?? ''))!;
    row.click();
    expect(text(doc, '.caveat-box')).toMatch(/decides this by the traffic itself/);
    expect(text(doc, '.kv')).toMatch(/Inspected by\s*edge/);
    expect(text(doc, '.ap')).toMatch(/Network Firewall/);
  });

  it('compares two snapshots of one account and region, and uses only the latest elsewhere', () => {
    const { doc, api } = page();
    // The demo has an older copy of prod us-east-1: it is kept for Compare and left out of the dashboard.
    // 21 exposures across the estates, plus 3 behind the Network Firewall in 'inspected us-east-1'.
    expect(text(doc, '#total')).toBe('24');
    expect(text(doc, '.chip-older')).toBe('+1 older');
    api.go('compare');
    expect(text(doc, '#cmp-verdict')).toMatch(/^2 new or wider internet exposures, no new attack chains, 1 closed or narrower, 3 configuration changes\./);
    const exp = text(doc, '#cmp-exposure');
    expect(exp).toMatch(/New.*win-jump-01.*tcp\/3389.*0\.0\.0\.0\/0/);
    // 10.0.0.0/8 is not the internet, so analytics-db is newly exposed, not wider.
    expect(exp).toMatch(/New.*analytics-db.*tcp\/5432.*0\.0\.0\.0\/0/);
    // The chain to analytics-db is not "closed": the database is now directly exposed, which is worse.
    expect(doc.getElementById('cmp-chains')).toBeNull();
    expect(text(doc, '#cmp-config')).toMatch(/Changed.*sgr-000003427.*tcp\/5432 from 10\.0\.0\.0\/8.*tcp\/5432 from 0\.0\.0\.0\/0/);
    expect(exp).toMatch(/Closed.*grafana-ops.*tcp\/9090/);
    expect(text(doc, '#cmp-config')).toMatch(/Removed.*security group rule.*sgr-0prometheus01/);

    // Two snapshots of different scopes only: nothing to compare.
    api.loadText(fixture('06-public-ip-without-igw-route'), 'a.json');
    api.go('compare');
    expect(text(doc, '#main, main')).toMatch(/Load two snapshots of one account and region/);

    // Load the same scope again, later and with a new open port: Compare picks it up.
    const later = JSON.parse(fixture('06-public-ip-without-igw-route'));
    later.collectedAt = '2030-01-01T00:00:00Z';
    later.ec2.SecurityGroupRules.push({ SecurityGroupRuleId: 'sgr-new-22', GroupId: later.ec2.SecurityGroupRules[0].GroupId, IsEgress: false, IpProtocol: 'tcp', FromPort: 22, ToPort: 22, CidrIpv4: '0.0.0.0/0' });
    api.loadText(JSON.stringify(later), 'b.json');
    api.go('compare');
    expect(text(doc, '#cmp-config')).toMatch(/Added.*sgr-new-22/);
  });

  it('is one file with no external resources and a no-network content security policy', () => {
    expect(html).toMatch(/http-equiv="Content-Security-Policy" content="default-src 'none'/);
    // Scripts are allowed only by the hash of the one inline script.
    const csp = /content="(default-src[^"]+)"/.exec(html)![1]!;
    const script = /<script>([\s\S]*)<\/script>/.exec(html)![1]!;
    expect(csp).toContain(`script-src 'sha256-${createHash('sha256').update(script).digest('base64')}'`);
    expect(csp).not.toMatch(/script-src[^;]*unsafe/);
    expect(html).not.toMatch(/<script[^>]+src=/);
    expect(html).not.toMatch(/<link[^>]+href="(?!data:)/);
    // url() only for embedded data and in-document SVG references (markers).
    expect(html).not.toMatch(/url\((?!["']?(data:|#))/);
    expect(html).not.toMatch(/\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon/);
  });

  it('opens on the dashboard with the demo environment, clearly labelled', () => {
    const { doc } = page();
    expect(text(doc, 'h1')).toBe('Dashboard');
    expect(text(doc, '#demo')).toMatch(/Demo environment/);
    expect(Number(text(doc, '#total'))).toBeGreaterThan(5);
    expect(doc.querySelector('#surface svg.graph')).not.toBeNull();
    expect(doc.querySelectorAll('#categories [data-cat]')).toHaveLength(6);
    expect(doc.querySelectorAll('#top-paths tbody tr').length).toBeGreaterThan(3);
  });

  it('is light by default and remembers the dark theme', () => {
    const { doc } = page();
    expect(doc.documentElement.dataset.theme ?? 'light').toBe('light');
    (doc.getElementById('theme') as HTMLButtonElement).click();
    expect(doc.documentElement.dataset.theme).toBe('dark');
  });

  it('replaces the demo with loaded snapshots and keeps several side by side', () => {
    const { doc, api } = page();
    const a = JSON.parse(fixture('06-public-ip-without-igw-route'));
    const b = { ...JSON.parse(fixture('07-alb-private-targets')), region: 'eu-west-1' };
    expect(api.loadText(JSON.stringify(a), 'a.json')).toBe(true);
    expect(doc.getElementById('demo')).toBeNull();
    expect(doc.querySelectorAll('.chip-snap')).toHaveLength(1);
    expect(text(doc, '#total')).toBe('1');
    expect(text(doc, '#summary .slegend')).toMatch(/Critical\s*1/);
    api.loadText(JSON.stringify(b), 'b.json');
    expect(doc.querySelectorAll('.chip-snap')).toHaveLength(2);
    api.go('issues');
    expect(doc.querySelectorAll('table.t tbody tr')).toHaveLength(2);
  });

  it('shows a fix plan whose numbers come from re-analysis', () => {
    const { doc, api } = page();
    api.loadText(fixture('06-public-ip-without-igw-route'), 'a.json');
    expect(text(doc, '#plan .plan-sum')).toBe('1 change closes 1 of 1 critical and high exposures and 2 of 2 attack chains.');
    expect(text(doc, '#plan ol.plan li')).toMatch(/Allow tcp\/22 on sgr-ssh-world only from inside vpc-1/);
    expect(text(doc, '#plan')).toMatch(/Nothing else that is reachable today changes/);
    ([...doc.querySelectorAll('#plan .btn')] as HTMLElement[]).find((x) => /simulator/.test(x.textContent ?? ''))!.click();
    expect(text(doc, '#sim-result .tiles')).toMatch(/1Exposures closed/);
    expect(text(doc, '#sim-result .tiles')).toMatch(/2Chains cut/);
  });

  it('shows the full path, targets and remediation for a load balancer issue', () => {
    const { doc, api } = page();
    api.loadText(fixture('07-alb-private-targets'), 'test.json');
    api.go('issues');
    const rows = doc.querySelectorAll('table.t tbody tr');
    expect(rows).toHaveLength(1);
    (rows[0] as HTMLElement).click();
    const panel = doc.getElementById('detail')!;
    expect(panel.textContent).toMatch(/sgr-alb-https/);
    expect(panel.textContent).toMatch(/acl-public #100/);
    const steps = [...panel.querySelectorAll('ol.ap .k')].map((n) => n.textContent);
    expect(steps[0]).toBe('Internet');
    expect(steps).toContain('Security group');
    expect(steps.at(-1)).toBe('Listener');
    expect([...panel.querySelectorAll('.targets .tg')].find((t) => /blocked/.test(t.textContent ?? ''))!.textContent).toMatch(/i-app2.*sg-app-wrong/);
    expect(panel.textContent).toMatch(/Verified fixes/);
    expect(panel.textContent).toMatch(/Guidance/);
  });

  it('filters issues by severity, text, category and account', () => {
    const { w, doc, api } = page();
    api.go('issues');
    const all = doc.querySelectorAll('table.t tbody tr').length;
    expect(all).toBeGreaterThan(5);
    (doc.querySelector('[data-sev="low"]') as HTMLButtonElement).click();
    const noLow = doc.querySelectorAll('table.t tbody tr').length;
    expect(noLow).toBeLessThan(all);
    const search = doc.getElementById('search') as HTMLInputElement;
    search.value = 'bastion-prod';
    search.dispatchEvent(new w.Event('input'));
    expect(doc.querySelectorAll('table.t tbody tr')).toHaveLength(1);
    api.go('issues', { q: 'nothing-matches-this' });
    expect(text(doc, '.empty h3')).toBe('No exposures match these filters');
    api.go('issues', { q: '', cat: 'admin', sevOn: new w.Set(['critical', 'high', 'medium', 'low', 'info']) });
    expect([...doc.querySelectorAll('table.t tbody tr')].every((r) => /tcp\/(22|3389)(?!\d)/.test(r.textContent ?? ''))).toBe(true);
  });

  it('draws the attack graph and traces a selected path', () => {
    const { doc, api } = page();
    api.loadText(fixture('07-alb-private-targets'), 'test.json');
    api.go('graph');
    expect(doc.querySelectorAll('#canvas .g-node').length).toBe(4); // internet, ALB, two targets
    (doc.querySelectorAll('#canvas .g-node')[1] as HTMLElement).dispatchEvent(new doc.defaultView!.MouseEvent('click', { bubbles: true }));
    expect(text(doc, '#gsel')).toMatch(/Anyone on the internet can open/);
    (([...doc.querySelectorAll('#gsel button')] as HTMLElement[]).find((b) => /Open details/.test(b.textContent ?? ''))!).click();
    expect(doc.getElementById('detail')).not.toBeNull();
    api.go('graph');
    expect(doc.querySelectorAll('#canvas .g-node.sel').length).toBeGreaterThan(0);
  });

  it('walks through what to do with the script, with commands that follow the chosen regions', () => {
    const { w, doc, api } = page();
    api.go('connect');
    expect(text(doc, 'h1')).toBe('Connect an AWS account');
    const steps = [...doc.querySelectorAll('#wizard > li h3')].map((x) => x.textContent);
    expect(steps).toEqual([
      'Open AWS CloudShell in the account to check',
      'Put the collector script into CloudShell',
      'Run it',
      'Download the snapshot to your computer',
      'Load the snapshots here',
      'Optional: clean up CloudShell',
    ]);
    const wiz = () => doc.getElementById('wizard')!.textContent;
    expect(wiz()).toMatch(/bash cloudshell-collect\.sh us-east-1/);
    const region = doc.getElementById('region') as HTMLInputElement;
    region.value = 'us-east-1, eu-west-1';
    region.dispatchEvent(new w.Event('input'));
    expect(wiz()).toMatch(/for r in us-east-1 eu-west-1; do bash cloudshell-collect\.sh "\$r"; done/);
    expect(wiz()).toMatch(/pinhole-snapshot-111122223333-eu-west-1\.json/);
    expect(doc.querySelector('a[href^="https://us-east-1.console.aws.amazon.com/cloudshell/home"]')).not.toBeNull();
  });

  it('shows the full CloudShell script and the IAM policy in the viewer', () => {
    const { doc, api } = page();
    api.go('connect');
    const view = [...doc.querySelectorAll('#wizard button')].find((b) => b.textContent === 'View script') as HTMLButtonElement;
    view.click();
    const script = readFileSync(join(root, 'scripts/cloudshell-collect.sh'), 'utf8');
    const lines = [...doc.querySelectorAll('#code .l')].map((l) => (l.textContent === ' ' ? '' : l.textContent));
    expect(lines.join('\n')).toBe(script.replace(/\n$/, ''));
    (doc.querySelector('[data-tab="policy"]') as HTMLButtonElement).click();
    expect(text(doc, '#code')).toMatch(/elasticloadbalancing:DescribeTargetGroupAttributes/);
  });

  it('shows a readable error for a file that is not a snapshot', () => {
    const { doc, api } = page();
    expect(api.loadText('{"hello": 1}', 'wrong.json')).toBe(false);
    expect(text(doc, '#error')).toMatch(/wrong\.json: Unsupported snapshot schemaVersion/);
    expect(api.loadText('not json', 'x.txt')).toBe(false);
    expect(text(doc, '#error')).toMatch(/not JSON/);
  });

  it('never interprets snapshot text as HTML', () => {
    const { doc, api } = page();
    const snap = JSON.parse(fixture('06-public-ip-without-igw-route'));
    snap.ec2.Instances = [{ InstanceId: 'i-public', Tags: [{ Key: 'Name', Value: '<img src=x onerror=alert(1)>' }], NetworkInterfaces: [{ NetworkInterfaceId: 'eni-public', Attachment: { DeviceIndex: 0 } }] }];
    api.loadText(JSON.stringify(snap), 'x.json');
    for (const r of ['dashboard', 'graph', 'issues', 'resources']) {
      api.go(r);
      if (r === 'issues') (doc.querySelector('table.t tbody tr') as HTMLElement).click();
      expect(doc.querySelector('#root img')).toBeNull();
    }
    api.go('issues');
    expect(text(doc, '#detail h1')).toMatch(/<img src=x/);
    api.go('issues', { sel: '' });
    expect(text(doc, 'table.t')).toMatch(/<img src=x/);
  });

  it('reports coverage gaps on the coverage page', () => {
    const { doc, api } = page();
    const snap = JSON.parse(fixture('06-public-ip-without-igw-route'));
    snap.ec2.RouteTables[0].Routes.push({ DestinationCidrBlock: '10.99.0.0/16', NetworkInterfaceId: 'eni-appliance', State: 'active', Origin: 'CreateRoute' });
    api.loadText(JSON.stringify(snap), 'x.json');
    api.go('coverage');
    expect(text(doc, '#notes')).toMatch(/appliance or NAT instance/);
  });

  it('lists every page in the navigation, and the search finds pages by other words', () => {
    const { doc } = page();
    const routes = [...doc.querySelectorAll('#main-nav a[data-route]')].map((a) => a.getAttribute('data-route'));
    for (const r of ['dashboard', 'issues', 'graph', 'blast', 'resources', 'egress', 'onprem', 'privatelink', 'hygiene', 'policy', 'coverage', 'simulator', 'compare', 'ask', 'report', 'connect']) expect(routes, r).toContain(r);
    expect(doc.querySelector('.menu-btn')?.getAttribute('aria-controls')).toBe('main-nav');
  });

  describe('0.2 pages', () => {
    const load9 = () => {
      const p = page();
      p.api.loadText(fixture('09-lateral-movement'), 'orders.json');
      return p;
    };

    it('blast radius shows the crown jewels and the smallest verified cut', () => {
      const { doc, api } = load9();
      api.go('blast');
      const box = doc.querySelector('#jewels')!;
      expect(box.textContent).toMatch(/orders-db/);
      expect(box.textContent).toMatch(/Remove 2 rules and no attack path reaches any of them\./);
      expect(box.textContent).toMatch(/sgr-bastion-ssh-world/);
      expect(box.textContent).toMatch(/sgr-db-ssh-vpc/);
    });

    it('the fix plan says it is proved, and fixes are marked safe', () => {
      const { doc, api } = load9();
      api.go('dashboard');
      expect(text(doc, '#plan')).toMatch(/Proved: no plan with fewer changes/);
      api.go('issues');
      (doc.querySelector('table.t tbody tr') as HTMLElement).click();
      expect(text(doc, '#fixes .cut.best .safe-tag')).toBe('Safe');
      expect(text(doc, '#fixes')).toMatch(/cuts 2 internal connections allowed only by address range/);
    });

    it('policies: checks the example, shows violations, and names the field in a bad policy', () => {
      const { doc, api } = load9();
      api.go('policy');
      expect(text(doc, '.pol-sum')).toMatch(/1 of 3 rules fails across 1 snapshot/);
      // One card per rule, the failing one first, in words as well as by ID.
      const cards = [...doc.querySelectorAll('.pol-rule')];
      expect(cards).toHaveLength(3);
      expect(cards[0]!.textContent).toMatch(/no-db-from-internet/);
      expect(cards[0]!.textContent).toMatch(/the internet must never reach databases, not even through a compromised server/);
      expect(text(doc, '.pol-res')).toMatch(/attack chain from the internet: bastion/);
      // The editor stays folded until it is needed.
      expect((doc.querySelector('.pol-ed') as HTMLDetailsElement).open).toBe(false);
      const area = doc.querySelector('.pol-src') as HTMLTextAreaElement;
      area.value = JSON.stringify({ rules: [{ id: 'x', deny: { from: 'internet', to: 'nope' } }] });
      [...doc.querySelectorAll('.pol-ed button')].find((b) => b.textContent?.includes('Check'))!.dispatchEvent(new (doc.defaultView as unknown as typeof globalThis).MouseEvent('click', { bubbles: true }));
      expect(text(doc, '.pol-err')).toMatch(/rules\[0\]\.deny\.to: "nope"/);
      [...doc.querySelectorAll('.pol-ed button')].find((b) => b.textContent?.includes('Use the example'))!.dispatchEvent(new (doc.defaultView as unknown as typeof globalThis).MouseEvent('click', { bubbles: true }));
      expect(doc.querySelector('.pol-err')).toBeNull();
    });

    it('outbound lists what servers can send to the internet and traces one', () => {
      const { doc, api } = page();
      api.loadText(fixture('14-outbound'), 'out.json');
      api.go('egress');
      expect(text(doc, '.eg-sum')).toMatch(/can reach the internet/);
      const rows = [...doc.querySelectorAll('.eg-t tbody tr')] as HTMLElement[];
      expect(rows.length).toBeGreaterThan(0);
      const db = rows.find((r) => /db/.test(r.textContent ?? '') && /nat-1/.test(r.textContent ?? ''))!;
      expect(db).toBeTruthy();
      expect(db.textContent).toMatch(/any port/);
      db.click();
      expect(text(doc, '.eg-detail')).toMatch(/nat-1/);
      expect(doc.querySelector('.eg-detail .trace, .eg-detail ol, .eg-detail .steps')).not.toBeNull();
      expect(rows.some((r) => /nopub|batch/.test(r.textContent ?? ''))).toBe(false);
    });

    it('on-premises lists the links and what clients there reach, and the query page takes their addresses', () => {
      const { doc, api } = page();
      api.loadText(fixture('15-hybrid'), 'hybrid.json');
      api.go('onprem');
      expect(text(doc, '.op-links')).toMatch(/vgw-1/);
      expect(text(doc, '.op-links')).toMatch(/192\.168\.0\.0\/16/);
      expect(text(doc, '.op-links')).toMatch(/Direct Connect/);
      const rows = [...doc.querySelectorAll('.op-t tbody tr')] as HTMLElement[];
      expect(rows.length).toBe(3);
      expect(rows.some((r) => /db/.test(r.textContent ?? ''))).toBe(false);
      rows[0]!.click();
      expect(text(doc, '.op-detail')).toMatch(/not visible to AWS/);
      expect(text(doc, '.op-chains')).toMatch(/1 attack chain into AWS/);
      expect(text(doc, '.op-chains')).toMatch(/On-premises → app → db/);
      api.go('ask', { askMode: 'pair', askFrom: '192.168.10.5', askTo: 'db', askProto: 'tcp', askPort: '5432' });
      expect(text(doc, '.ask-results')).toMatch(/no way back on-premises/);
      api.go('ask', { askMode: 'pair', askFrom: 'web', askTo: '10.50.1.1', askProto: 'tcp', askPort: '443' });
      expect(text(doc, '.ask-results')).toMatch(/reachable/i);
    });

    it('PrivateLink lists who may connect to each service and what the endpoints allow', () => {
      const { doc, api } = page();
      api.loadText(fixture('16-privatelink'), 'pl.json');
      api.go('privatelink');
      const rows = [...doc.querySelectorAll('.pl-services tbody tr')] as HTMLElement[];
      expect(rows.length).toBe(2);
      expect(rows[0]!.textContent).toMatch(/vpce-svc-open.*Every AWS account.*Not required/);
      rows[1]!.click();
      expect(text(doc, '.pl-listeners')).toMatch(/security groups not applied to PrivateLink/);
      expect(text(doc, '.pl-listeners')).toMatch(/i-db:5432/);
      expect(text(doc, '.pl-endpoints')).toMatch(/vpce-s3.*Allows everything/);
    });

    it('the query page shows how to make a blocked connection work', () => {
      const { doc, api } = load9();
      api.go('ask', { askMode: 'pair', askFrom: 'web', askTo: 'orders-db', askProto: 'tcp', askPort: '5432' });
      expect(text(doc, '#ask-repair')).toMatch(/2 changes, verified/);
      expect(text(doc, '#ask-repair')).toMatch(/acl-data/);
      expect(text(doc, '#ask-repair')).toMatch(/from sg-web/);
      expect(text(doc, '#ask-repair')).toMatch(/Nothing else becomes reachable from the internet/);
      api.go('ask', { askMode: 'pair', askFrom: 'internet', askTo: 'bastion', askProto: 'tcp', askPort: '22' });
      expect(doc.querySelector('#ask-repair')).toBeNull();
    });

    it('on-premises says so when there are no links', () => {
      const { doc, api } = page();
      api.loadText(fixture('06-public-ip-without-igw-route'), 'x.json');
      api.go('onprem');
      expect(text(doc, '.page')).toMatch(/No VPN or Direct Connect links/);
    });

    it('blast radius lists chains, traces one and offers the rule that cuts the most', () => {
      const { doc, api } = load9();
      api.go('blast');
      expect(doc.querySelectorAll('.chain-item').length).toBe(5);
      expect(doc.querySelector('#lateral svg.lateral')).not.toBeNull();
      expect(text(doc, '.chain-item .tt')).toMatch(/^bastion → app → (orders-db|session-cache)$/);
      const pick = (re: RegExp) => ([...doc.querySelectorAll('.chain-item')] as HTMLElement[]).find((x) => re.test(x.textContent ?? ''))!.click();
      // Redis on the cache is reached from the web server too, so only the Redis rule cuts that chain on its own.
      pick(/session-cache/);
      expect(text(doc, '#chain-detail h1')).toMatch(/bastion → app → session-cache/);
      expect(text(doc, '#chain-detail')).toMatch(/Also reachable from web/);
      // That rule carries app's own Redis traffic, so it is offered with a caution, not recommended.
      expect(doc.querySelector('#cuts .cut.best')).toBeNull();
      expect(text(doc, '#cuts')).toMatch(/sgr-cache-redis.*cuts 1 of 5 chains/);
      expect(text(doc, '#cuts')).toMatch(/may be traffic it needs/);
      expect(text(doc, '#cuts')).toMatch(/close the way in/);
      api.go('blast', { chain: '' });
      pick(/bastion → web/);
      expect(text(doc, '#cuts .cut.best')).toMatch(/sgr-bastion-ssh-world.*cuts 3 of 5 chains/);
    });

    it('the simulator re-analyses a change and prints the AWS CLI command', () => {
      const { doc, api } = load9();
      api.go('simulator', { changes: [{ kind: 'revoke-sg-rule', ruleId: 'sgr-db-ssh-vpc' }] });
      expect(text(doc, '#sim-result .tiles')).toMatch(/0Exposures closed/);
      expect(text(doc, '#sim-result .tiles')).toMatch(/1Chains cut/);
      expect(text(doc, '#sim-result .cmd pre')).toContain('aws ec2 revoke-security-group-ingress --region us-east-1 --group-id sg-db --security-group-rule-ids sgr-db-ssh-vpc');
      // Toggling the rule back clears the change.
      const sw = doc.querySelector('[aria-label="Restore sgr-db-ssh-vpc"]') as HTMLElement;
      sw.click();
      expect(text(doc, '#sim-result')).toMatch(/No changes yet/);
    });

    it('the reachability query answers by name, and lists who can reach a target', () => {
      const { doc, api } = load9();
      api.go('ask', { askMode: 'pair', askFrom: 'app', askTo: 'orders-db', askPort: '' });
      const rows = [...doc.querySelectorAll('#ask-services tbody tr')].map((r) => r.querySelector('td')!.textContent);
      expect(rows).toEqual(['tcp/22', 'tcp/5432']);
      api.go('ask', { askFrom: 'bastion', askTo: 'session-cache', askPort: '6379' });
      expect(text(doc, '#ask-verdict .verdict')).toBe('Blocked');
      api.go('ask', { askMode: 'who', askTo: 'session-cache' });
      expect(text(doc, '#ask-who')).toMatch(/app \(eni-app\)/);
      expect(text(doc, '#ask-who')).not.toMatch(/bastion/);
    });

    it('rule hygiene lists every finding with a simulate button where a fix exists', () => {
      const { doc, api } = load9();
      api.go('hygiene');
      // The bastion's SSH rule is already an exposure, so it is listed there instead.
      // Six hygiene findings, and sg-web can be compacted from 3 rules to 2.
      expect(doc.querySelectorAll('table.hyg tbody tr').length).toBe(7);
      expect(text(doc, 'table.hyg')).toMatch(/sg-web \(web\): 3 inbound rules can be 2/);
      expect(text(doc, '.hyg-note')).toMatch(/1 more rule open to the world already lets the internet in|1 more rule open to the world already let the internet in/);
      api.go('hygiene', { hygAll: true });
      expect(doc.querySelectorAll('table.hyg tbody tr').length).toBe(8);
      expect(text(doc, 'table.hyg')).toMatch(/acl-data inbound rule 120 can never match/);
    });

    it('the issue detail shows verified fixes, best first', () => {
      const { doc, api } = load9();
      api.go('issues');
      (doc.querySelector('table.t tbody tr') as HTMLElement).click();
      expect(text(doc, '#fixes .cut.best')).toMatch(/Remove inbound rule sgr-bastion-ssh-world/);
      expect(text(doc, '#fixes')).toMatch(/Allow tcp\/22 on sgr-bastion-ssh-world only from inside vpc-1/);
      expect(text(doc, '#fixes')).toMatch(/could still reach it if compromised/);
    });

    it('the exposure detail is a full page: a plain verdict, what was checked, and previous and next', () => {
      const { doc, api } = load9();
      api.go('issues', { sel: '' });
      (doc.querySelector('table.t tbody tr') as HTMLElement).click();
      expect(text(doc, '#detail .lede')).toMatch(/^Anyone on the internet can open SSH \(tcp\/22\) on bastion at 52\.0\.0\.10\.$/);
      expect(text(doc, '#detail')).toMatch(/How sure is this/);
      expect(text(doc, '#detail')).toMatch(/does not see host firewalls/);
      expect(text(doc, '#detail .meta')).toMatch(/Collection time not recorded/);
      const first = text(doc, '#detail h1');
      (([...doc.querySelectorAll('.stepnav button')] as HTMLElement[]).find((b) => b.textContent === 'Next')!).click();
      expect(text(doc, '#detail h1')).not.toBe(first);
      (doc.querySelector('#detail .back') as HTMLElement).click();
      expect(doc.getElementById('detail')).toBeNull();
      expect(doc.querySelectorAll('table.t tbody tr').length).toBeGreaterThan(1);
    });

    it('builds a report that prints and downloads as one HTML file with no script', () => {
      const { doc, api } = load9();
      api.go('report');
      const rep = doc.querySelector('.report')!;
      expect(rep.querySelector('h1')!.textContent).toBe('1 account, 1 region');
      expect(rep.textContent).toMatch(/Fix plan/);
      expect(rep.textContent).toMatch(/aws ec2 revoke-security-group-ingress --region us-east-1 --group-id sg-bastion --security-group-rule-ids sgr-bastion-ssh-world/);
      expect(rep.textContent).toMatch(/Attack chains/);
      expect(rep.textContent).toMatch(/does not see host firewalls/);
      const out = (api as unknown as { reportHtml: () => string }).reportHtml();
      expect(out).toMatch(/default-src 'none'/);
      expect(out).toMatch(/sgr-bastion-ssh-world/);
      expect(out).not.toMatch(/<script/i);
    });

    it('flags snapshots older than a week', () => {
      const { doc, api } = page();
      const snap = JSON.parse(fixture('06-public-ip-without-igw-route'));
      snap.collectedAt = '2020-01-01T00:00:00Z';
      api.loadText(JSON.stringify(snap), 'old.json');
      expect(text(doc, '.stale-t')).toMatch(/Collected 1 Jan 2020.*collect fresh snapshots/);
    });

    it('the command palette opens with Ctrl+K and jumps to a chain', () => {
      const { w, doc, api } = load9();
      api.go('dashboard');
      doc.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }));
      const input = doc.querySelector('dialog.palette input') as HTMLInputElement;
      expect(input).not.toBeNull();
      input.value = 'app orders';
      input.dispatchEvent(new w.Event('input'));
      input.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Enter' }));
      expect(text(doc, '#chain-detail h1')).toMatch(/bastion → app → orders-db/);
    });
  });
});

describe('documentation', () => {
  it('builds, with every example produced by the real CLI', () => {
    const out = execFileSync(process.execPath, [join(root, 'scripts/build-docs.mjs')], { cwd: root, encoding: 'utf8' });
    expect(out).toMatch(/21 sections, 16 live examples/);
    const html = readFileSync(join(root, 'site/docs/index.html'), 'utf8');
    expect(html).not.toMatch(/<!--(run|trace|policy)/);
    expect(html).toContain('pinhole blast account-a/snapshot.json account-b/snapshot.json');
    expect(html).toMatch(/script-src 'sha256-[A-Za-z0-9+/=]+'; .*connect-src 'none'/);
  }, 60_000);
});
