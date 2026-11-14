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
    snap.ec2.Vpcs[0].Ipv6CidrBlockAssociationSet = [{ Ipv6CidrBlock: '2600:1f18::/56' }];
    api.loadText(JSON.stringify(snap), 'x.json');
    api.go('coverage');
    expect(text(doc, '#notes')).toMatch(/IPv6/);
  });

  describe('0.2 pages', () => {
    const load9 = () => {
      const p = page();
      p.api.loadText(fixture('09-lateral-movement'), 'orders.json');
      return p;
    };

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
      expect(doc.querySelectorAll('table.hyg tbody tr').length).toBe(6);
      expect(text(doc, '.hyg-note')).toMatch(/1 more rule open to the world already lets the internet in|1 more rule open to the world already let the internet in/);
      api.go('hygiene', { hygAll: true });
      expect(doc.querySelectorAll('table.hyg tbody tr').length).toBe(7);
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
