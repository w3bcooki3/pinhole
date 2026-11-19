/**
 * Policies page: write what must never be reachable and what must always be,
 * and check it against every loaded snapshot. The policy text stays in this
 * browser only.
 */
import { checkPolicy, parsePolicy, PolicyError } from '@pinhole/engine';
import { compareSeverity } from '@pinhole/engine';
import type { PolicyFile, PolicyReport, PolicyResult, PolicyRule, Severity, Target, Violation } from '@pinhole/engine';
import { h, on, toast } from './dom.js';
import * as D from './data.js';
import type { Snap } from './data.js';
import { iconSvg } from './graph.js';
import { btn, empty, sevPill } from './ui.js';

/** The example in fixtures/policies/09-policy.json, which matches the demo's "orders" estate. */
export const EXAMPLE_POLICY = `{
  "groups": {
    "databases": { "names": ["orders-db"] },
    "bastions": { "names": ["bastion"] }
  },
  "rules": [
    {
      "id": "no-db-from-internet",
      "description": "Databases are never reachable from the internet, even through a compromised server",
      "severity": "critical",
      "deny": { "from": "internet", "to": "databases", "indirect": true }
    },
    {
      "id": "ssh-only-to-bastions",
      "description": "Only bastions take SSH from the internet",
      "severity": "high",
      "deny": { "from": "internet", "to": { "not": "bastions" }, "ports": "tcp/22" }
    },
    {
      "id": "bastion-reaches-db",
      "description": "Operators keep SSH to the database through the bastion",
      "require": { "from": "bastions", "to": "databases", "ports": "tcp/22" }
    }
  ]
}
`;

const KEY = 'pinhole-policy';
let text: string | undefined;
const load = () => {
  if (text !== undefined) return text;
  try {
    text = localStorage.getItem(KEY) ?? EXAMPLE_POLICY;
  } catch {
    text = EXAMPLE_POLICY;
  }
  return text;
};
const save = (t: string) => {
  text = t;
  try {
    localStorage.setItem(KEY, t);
  } catch {
    /* storage can be unavailable; the policy still works for this visit */
  }
};

const cache = new WeakMap<Snap, { src: string; report: PolicyReport }>();
function reportFor(snap: Snap, src: string, policy: PolicyFile): PolicyReport {
  const hit = cache.get(snap);
  if (hit && hit.src === src) return hit.report;
  const report = checkPolicy(snap.model, D.reportOf(snap), D.blastOf(snap), policy);
  cache.set(snap, { src, report });
  return report;
}

/** Parsed policy, or the error that says which field is wrong. */
export function currentPolicy(): { policy?: PolicyFile; error?: string; src: string } {
  const src = load();
  try {
    return { policy: parsePolicy(JSON.parse(src)), src };
  } catch (e) {
    return { error: e instanceof PolicyError ? e.message : `Not JSON: ${(e as Error).message}`, src };
  }
}

/** A target in words: "the internet", a group name, or what a selector picks. */
function targetText(t: Target): string {
  if (t === 'internet') return 'the internet';
  if (t === 'onprem') return 'on-premises networks';
  if (t === '*') return 'anything';
  if (typeof t === 'string') return t;
  const parts: string[] = [];
  if (t.names) parts.push(t.names.join(', '));
  if (t.ids) parts.push(t.ids.join(', '));
  if (t.tags) parts.push(Object.entries(t.tags).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('|') : v}`).join(', '));
  if (t.securityGroups) parts.push(`members of ${t.securityGroups.join(', ')}`);
  if (t.subnets) parts.push(`in ${t.subnets.join(', ')}`);
  if (t.vpcs) parts.push(`in ${t.vpcs.join(', ')}`);
  if (t.any) parts.push(t.any.map(targetText).join(' or '));
  if (t.not) parts.push(`anything except ${targetText(t.not)}`);
  return parts.join('; ') || 'anything';
}

function ruleText(r: PolicyRule): string {
  const b = (r.deny ?? r.require)!;
  const ports = b.ports ? ` on ${Array.isArray(b.ports) ? b.ports.join(', ') : b.ports}` : '';
  if (r.deny) return `${targetText(b.from)} must never reach ${targetText(b.to)}${ports}${r.deny.indirect ? ', not even through a compromised server' : ''}`;
  return `${targetText(b.from)} must always reach ${targetText(b.to)}${ports}`;
}

type Row = { snap: Snap; x: PolicyResult };

export function policyPage(ctx: { st: { snaps: Snap[] }; render: () => void }): HTMLElement {
  const { policy, error, src } = currentPolicy();
  const area = h('textarea', { class: 'pol-src mono', spellcheck: 'false', 'aria-label': 'Policy (JSON)', rows: 22 }) as HTMLTextAreaElement;
  area.value = src;
  const check = () => {
    save(area.value);
    editorOpen = true;
    ctx.render();
  };
  on(area, 'keydown', (e) => {
    const k = e as KeyboardEvent;
    if ((k.metaKey || k.ctrlKey) && k.key === 'Enter') check();
  });
  const file = h('input', { type: 'file', accept: '.json,application/json', class: 'sr-only', 'aria-label': 'Load a policy file' }) as HTMLInputElement;
  on(file, 'change', async () => {
    const f = file.files?.[0];
    if (!f) return;
    if (f.size > 5_000_000) return toast('That file is larger than 5 MB');
    area.value = await f.text();
    check();
  });

  const editor = h(
    'details',
    { class: 'box pol-ed', ...(editorOpen || error ? { open: '' } : {}) },
    h('summary', {}, h('span', { class: 'pol-ed-t' }, iconSvg('policy', 15), 'Edit the policy'), h('span', { class: 'faint' }, 'JSON, kept in this browser only. Ctrl+Enter checks it.')),
    h(
      'div',
      { class: 'pad' },
      area,
      error ? h('p', { class: 'pol-err', role: 'alert' }, error) : null,
      h('div', { class: 'cut-a' }, btn([iconSvg('policy', 13), 'Check'], 'sm primary', check), btn('Load file', 'sm', () => file.click()), btn('Use the example', 'sm ghost', () => { area.value = EXAMPLE_POLICY; check(); }), file),
      h('p', { class: 'faint', style: 'margin:0.5rem 0 0' }, 'Each rule is a deny (must never be reachable) or a require (must always be). Pick resources by tags, names, security groups, subnets, VPCs or IDs. ', h('a', { href: 'docs/#policies', target: '_blank', rel: 'noopener' }, 'Policy reference')),
    ),
  );
  on(editor, 'toggle', () => (editorOpen = (editor as HTMLDetailsElement).open));

  const head = h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Policies'), h('p', {}, 'Write down what must never be reachable and what must always be. Every rule is checked exactly against each loaded snapshot.')));
  if (!policy) return h('div', { class: 'page pol-page' }, head, editor, h('div', { class: 'box pol-res' }, empty('The policy has an error', 'Fix it above to see results.')));
  if (!ctx.st.snaps.length) return h('div', { class: 'page pol-page' }, head, editor, h('div', { class: 'box pol-res' }, empty('No snapshots', 'Load a snapshot to check the policy.')));

  // One card per rule, across every snapshot: where it fails, where it holds, where it does not apply.
  const reports = ctx.st.snaps.map((snap) => ({ snap, r: reportFor(snap, src, policy) }));
  const rules = policy.rules.map((rule) => {
    const rows: Row[] = reports.map(({ snap, r }) => ({ snap, x: r.results.find((x) => x.id === rule.id)! })).filter((y) => y.x);
    const fail = rows.filter((y) => y.x.status === 'fail');
    const pass = rows.filter((y) => y.x.status === 'pass' && y.x.matched);
    const none = rows.filter((y) => y.x.status === 'pass' && !y.x.matched);
    return { rule, fail, pass, none, severity: rows[0]?.x.severity ?? 'medium' };
  });
  rules.sort((a, b) => (b.fail.length ? 1 : 0) - (a.fail.length ? 1 : 0) || compareSeverity(a.severity, b.severity));
  const failing = rules.filter((r) => r.fail.length).length;
  const holding = rules.filter((r) => !r.fail.length && r.pass.length).length;
  const idle = rules.length - failing - holding;

  const rest = [holding ? `${holding} ${holding === 1 ? 'holds' : 'hold'}` : '', idle ? `${idle} ${idle === 1 ? 'matches' : 'match'} nothing loaded` : ''].filter(Boolean).join(', ');
  const summary = h(
    'p',
    { class: 'pol-sum' },
    h('strong', {}, failing ? `${failing} of ${D.plural(rules.length, 'rule')} ${failing === 1 ? 'fails' : 'fail'}` : `All ${D.plural(rules.length, 'rule')} hold`),
    ` across ${D.plural(reports.length, 'snapshot')}${failing && rest ? `; ${rest}` : ''}.`,
  );

  return h('div', { class: 'page pol-page' }, head, summary, h('div', { class: 'pol-res' }, ...rules.map(ruleCard)), editor);
}

let editorOpen = false;

function ruleCard(c: { rule: PolicyRule; fail: Row[]; pass: Row[]; none: Row[]; severity: Severity }): HTMLElement {
  const where = (rows: Row[]) => rows.map((y) => `${y.snap.account} / ${y.snap.region}`).join(', ');
  const status = c.fail.length ? sevPill(c.severity) : c.pass.length ? h('span', { class: 'tag safe-tag' }, 'Holds') : h('span', { class: 'tag idle-tag' }, 'Matches nothing');
  const count = c.fail.reduce((n, y) => n + y.x.violations.length, 0);
  return h(
    'section',
    { class: `box pol-rule ${c.fail.length ? 'fail' : c.pass.length ? 'pass' : 'idle'}` },
    h(
      'div',
      { class: 'pol-rh' },
      h('div', { class: 'pol-rt' }, status, h('strong', {}, c.rule.description ?? ruleText(c.rule))),
      h('div', { class: 'pol-rs' }, h('span', { class: 'mono' }, c.rule.id), ' · ', c.rule.deny ? 'deny' : 'require', ': ', ruleText(c.rule)),
      c.fail.length ? h('div', { class: 'pol-rc' }, `${D.plural(count, c.rule.deny ? 'connection breaks it' : 'connection is missing', c.rule.deny ? 'connections break it' : 'connections are missing')} in ${D.plural(c.fail.length, 'snapshot')}`) : null,
    ),
    ...c.fail.map((y) =>
      h(
        'div',
        { class: 'pol-snap' },
        h('div', { class: 'pol-sh' }, h('span', { class: 'mono' }, `${y.snap.account} / ${y.snap.region}`), h('span', { class: 'faint' }, `${D.plural(y.x.violations.length, 'violation')}, ${D.plural(y.x.matched, 'resource')}, ${D.plural(y.x.checked, y.x.kind === 'require' ? 'pair' : 'path')} checked`)),
        h('div', { class: 'pol-v' }, ...y.x.violations.slice(0, 20).map(violation), y.x.violations.length > 20 ? h('p', { class: 'faint' }, `and ${y.x.violations.length - 20} more`) : null),
      ),
    ),
    c.pass.length || c.none.length
      ? h('div', { class: 'pol-foot faint' }, c.pass.length ? h('span', { title: where(c.pass) }, c.pass.length > 2 ? `Holds in ${D.plural(c.pass.length, 'snapshot')}.` : `Holds in ${where(c.pass)}.`) : null, c.none.length ? h('span', { title: where(c.none) }, ` Matches nothing in ${D.plural(c.none.length, 'other snapshot')}.`) : null)
      : null,
  );
}

function violation(v: Violation): HTMLElement {
  const d = h('details', { class: 'pol-d' }, h('summary', {}, v.detail));
  if (v.ruleIds.length) d.append(h('div', { class: 'dim' }, 'Let through by ', h('span', { class: 'mono' }, v.ruleIds.join(', '))));
  if (v.path.length) d.append(h('pre', { class: 'pol-path mono' }, v.path.join('\n')));
  return d;
}
