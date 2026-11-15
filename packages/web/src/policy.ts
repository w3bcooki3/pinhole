/**
 * Policies page: write what must never be reachable and what must always be,
 * and check it against every loaded snapshot. The policy text stays in this
 * browser only.
 */
import { checkPolicy, parsePolicy, PolicyError } from '@pinhole/engine';
import type { PolicyFile, PolicyReport, Violation } from '@pinhole/engine';
import { h, on, toast } from './dom.js';
import * as D from './data.js';
import type { Snap } from './data.js';
import { iconSvg } from './graph.js';
import { boxHead, btn, empty, sevPill } from './ui.js';

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

export function policyPage(ctx: { st: { snaps: Snap[] }; render: () => void }): HTMLElement {
  const { policy, error, src } = currentPolicy();
  const area = h('textarea', { class: 'pol-src mono', spellcheck: 'false', wrap: 'off', 'aria-label': 'Policy (JSON)', rows: 18 }) as HTMLTextAreaElement;
  area.value = src;
  const check = () => {
    save(area.value);
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
    'section',
    { class: 'box pol-ed' },
    boxHead('Policy', 'JSON. Kept in this browser only.'),
    h(
      'div',
      { class: 'pad' },
      area,
      error ? h('p', { class: 'pol-err', role: 'alert' }, error) : null,
      h('div', { class: 'cut-a' }, btn([iconSvg('policy', 13), 'Check'], 'sm primary', check), btn('Load file', 'sm', () => file.click()), btn('Use the example', 'sm ghost', () => { area.value = EXAMPLE_POLICY; check(); }), file),
      h('p', { class: 'faint', style: 'margin:0.5rem 0 0' }, 'Each rule is a deny (must never be reachable) or a require (must always be). Pick resources by tags, names, security groups, subnets, VPCs or IDs. ', h('a', { href: 'docs/#policies', target: '_blank', rel: 'noopener' }, 'Policy reference')),
    ),
  );

  const results: HTMLElement[] = [];
  if (policy) {
    const all = ctx.st.snaps.map((snap) => ({ snap, r: reportFor(snap, src, policy) }));
    all.sort((a, b) => b.r.failed - a.r.failed);
    for (const { snap, r } of all) results.push(resultBox(snap, r));
  }
  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Policies'), h('p', {}, 'Write down what must never be reachable and what must always be. Every rule is checked exactly against each loaded snapshot.'))),
    h('div', { class: 'pol-grid' }, editor, h('div', { class: 'pol-res' }, ...(results.length ? results : [error ? empty('The policy has an error', 'Fix it to see results.') : empty('No snapshots', 'Load a snapshot to check the policy.')]))),
  );
}

function resultBox(snap: Snap, r: PolicyReport): HTMLElement {
  return h(
    'section',
    { class: 'box', style: 'margin-bottom:1rem' },
    boxHead(`${snap.account} / ${snap.region}`, r.failed ? `${r.failed} of ${D.plural(r.results.length, 'rule')} fail` : `All ${D.plural(r.results.length, 'rule')} pass`),
    h(
      'ul',
      { class: 'pol-list' },
      ...r.results.map((x) =>
        h(
          'li',
          { class: `pol-r ${x.status}` },
          h(
            'div',
            { class: 'pol-h' },
            x.status === 'fail' ? sevPill(x.severity) : x.matched ? h('span', { class: 'tag safe-tag' }, 'Pass') : h('span', { class: 'tag idle-tag', title: 'Nothing in this snapshot matches the rule' }, 'No match'),
            h('strong', { class: 'mono' }, x.id),
            h('span', { class: 'faint' }, x.matched ? `${x.kind}, ${D.plural(x.matched, 'resource')}${x.checked ? `, ${D.plural(x.checked, x.kind === 'require' ? 'pair' : 'path')} checked` : ''}` : x.kind),
          ),
          x.description ? h('div', { class: 'dim' }, x.description) : null,
          x.violations.length ? h('div', { class: 'pol-v' }, ...x.violations.slice(0, 20).map(violation), x.violations.length > 20 ? h('p', { class: 'faint' }, `and ${x.violations.length - 20} more`) : null) : null,
        ),
      ),
    ),
  );
}

function violation(v: Violation): HTMLElement {
  const d = h('details', { class: 'pol-d' }, h('summary', {}, v.detail));
  if (v.ruleIds.length) d.append(h('div', { class: 'dim' }, 'Let through by ', h('span', { class: 'mono' }, v.ruleIds.join(', '))));
  if (v.path.length) d.append(h('pre', { class: 'pol-path mono' }, v.path.join('\n')));
  return d;
}
