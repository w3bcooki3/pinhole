/**
 * The pages added in 0.2: blast radius, simulator, reachability query and
 * rule hygiene, plus the command palette. They get the app's state and
 * navigation through a small context object, so they do not depend on app.ts.
 */
import { analyzeBlastRadius, analyzeExposure, applyChanges, ChangeError, cliFor, describeChange, diffExposure, evaluatePath, isLateralTarget, reachServices, ruleText, serviceLabel } from '@pinhole/engine';
import type { AttackChain, Change, ExposureDiff, NetworkModel, PathResult, ServiceReach } from '@pinhole/engine';
import { h, on, toast } from './dom.js';
import type { Child } from './dom.js';
import * as D from './data.js';
import type { Row, Severity, Snap } from './data.js';
import { iconSvg } from './graph.js';
import { renderLateral } from './lateral.js';
import { boxHead, btn, cmdBlock, empty, linkBtn, sevPill, sevVar, short } from './ui.js';

export interface PageState {
  snaps: Snap[];
  sel: string;
  blastKey: string;
  chain: string;
  simKey: string;
  changes: Change[];
  simQuery: string;
  askKey: string;
  askMode: 'pair' | 'who';
  askFrom: string;
  askTo: string;
  askProto: string;
  askPort: string;
  hygCode: string;
  hygAll: boolean;
}

export interface Ctx {
  st: PageState;
  go: (route: string, patch?: Partial<PageState> & Record<string, unknown>) => void;
  render: () => void;
  rows: () => Row[];
}

const snapByKey = (ctx: Ctx, key: string) => ctx.st.snaps.find((x) => x.key === key);
const snapSelect = (ctx: Ctx, value: string, set: (key: string) => void, filter: (s: Snap) => boolean = () => true): HTMLElement | null => {
  const list = ctx.st.snaps.filter(filter);
  if (list.length < 2) return null;
  const sel = h('select', { class: 'snap-select', 'aria-label': 'Snapshot' }, ...list.map((x) => h('option', { value: x.key }, `${x.account} / ${x.region}`))) as HTMLSelectElement;
  sel.value = value;
  sel.addEventListener('change', () => set(sel.value));
  return sel;
};

function stepper(items: { k: string; v: Child[]; state: 'pass' | 'block' | 'unknown' | 'info' | 'end' }[]): HTMLElement {
  return h(
    'ol',
    { class: 'ap' },
    ...items.map((x) => h('li', { class: x.state }, h('span', { class: 'dot' }, x.state === 'pass' ? iconSvg('check', 10) : x.state === 'block' ? iconSvg('x', 10) : null), h('div', { class: 'k' }, x.k), h('div', { class: 'v' }, ...x.v))),
  );
}

function traceStepper(r: PathResult | { hops: PathResult['hops'] }, end?: string): HTMLElement {
  const hops = r.hops.filter((x) => x.stage !== 'scope' || x.decision !== 'info');
  return stepper([
    ...hops.map((x) => ({ k: D.STAGE[x.stage] ?? x.stage, v: [h('code', {}, D.hopId(x)), ' ', D.hopDetail(x)], state: (x.decision === 'pass' ? 'pass' : x.decision === 'block' ? 'block' : x.decision === 'info' ? 'info' : 'unknown') as 'pass' | 'block' | 'unknown' | 'info' })),
    ...(end ? [{ k: end, v: [], state: 'end' as const }] : []),
  ]);
}

const chainText = (c: AttackChain) => c.steps.map((x) => short(x.name)).join(' → ');
const IMPACT: Record<string, string> = { data: 'Data store', control: 'Control plane', admin: 'Remote administration', wide: 'Wide port range', other: 'Service', web: 'Web' };

// ================================================================== blast radius

export function blastPage(ctx: Ctx): HTMLElement {
  const st = ctx.st;
  const withChains = st.snaps.filter((x) => D.blastOf(x).entries.length);
  if (!withChains.length) {
    return h('div', { class: 'page' }, h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Blast radius'), h('p', {}, 'If a server that the internet can reach is compromised, what can the attacker reach next?'))), h('div', { class: 'box' }, empty('No entry points', 'Nothing in the loaded snapshots is reachable from the internet, so there is nothing to move on from.')));
  }
  // Open on the snapshot with the deepest chains: the clearest picture of lateral movement.
  const depthOf = (x: Snap) => Math.max(0, ...D.blastOf(x).chains.map((c) => c.steps.length));
  const snap = snapByKey(ctx, st.blastKey) ?? withChains.slice().sort((a, b) => depthOf(b) - depthOf(a) || (D.blastOf(b).chains[0]?.score ?? 0) - (D.blastOf(a).chains[0]?.score ?? 0))[0]!;
  const blast = D.blastOf(snap);
  const chain = blast.chains.find((c) => `${snap.key}#${c.id}` === st.chain);

  const canvas = h('div', { class: 'canvas boxed', id: 'lateral' });
  const host = h('div', { style: 'position:absolute;inset:0' });
  canvas.append(
    host,
    h('div', { class: 'glegend hide-sm' }, h('span', {}, h('i', { style: 'background:var(--critical);height:3px' }), 'Remote access (attacker can move on)'), h('span', {}, h('i', { style: 'background:var(--ink3);height:1px' }), 'Reaches a service'), chain ? h('span', {}, h('i', { class: 'pk' }), 'This chain') : null),
  );
  const draw = () =>
    renderLateral(host, snap.model, blast, {
      selected: chain,
      onSelectNode: (id) => {
        const c = blast.chains.find((x) => x.targetId === id) ?? blast.chains.find((x) => x.entry.eniId === id);
        if (c) ctx.go('blast', { chain: `${snap.key}#${c.id}` });
      },
    });
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(draw);
  else draw();
  const sel = snapSelect(ctx, snap.key, (k) => ctx.go('blast', { blastKey: k, chain: '' }), (x) => D.blastOf(x).entries.length > 0);
  const graphBox = h('section', { class: 'box' }, boxHead('Lateral movement', chain ? 'The selected chain is outlined. Select a resource to open its chain.' : 'Every route that makes up a chain. Select a resource to open its chain.'), canvas);
  const out = chain ? chainDetail(ctx, snap, chain, graphBox) : chainOverview(ctx, snap, graphBox, sel);
  draw();
  return out;
}

const chainSentence = (c: AttackChain) => {
  const end = c.steps.at(-1)!;
  const what = end.serviceName ? `${end.serviceName} (${end.service})` : end.service ?? '';
  return `If ${short(c.entry.name)} is compromised (the internet reaches it on ${c.entry.how.replace(/ from .*$/, '')}), an attacker can open ${what} on ${short(end.name)} in ${D.plural(c.steps.length - 1, 'hop')}.`;
};

function chainOverview(ctx: Ctx, snap: Snap, graphBox: HTMLElement, sel: HTMLElement | null): HTMLElement {
  const blast = D.blastOf(snap);
  const cuts = D.chokepointsOf(snap);
  const age = D.collected(snap);
  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Blast radius'), h('p', {}, 'If a server that the internet can reach is compromised, what can the attacker reach next?'), h('p', { class: 'faint', style: 'margin-top:0.25rem' }, `${snap.account} / ${snap.region}. ${age.text}.`)), sel ? h('div', { class: 'acts' }, sel) : null),
    h(
      'section',
      { class: 'box', style: 'margin-bottom:1rem' },
      boxHead('Servers the internet can reach', 'Treated as the attacker’s starting points'),
      h(
        'div',
        { class: 'foot pad' },
        ...blast.footprints.map((f) =>
          h('div', { class: 'fp' }, h('div', { class: 'fp-h' }, sevPill(f.entry.severity), h('strong', {}, short(f.entry.name))), h('div', { class: 'fp-big' }, h('b', {}, String(f.reachable.length)), ` resource${f.reachable.length === 1 ? '' : 's'} reachable if compromised`), h('div', { class: 'fp-s' }, `${D.plural(f.dataStores, 'data store')}, remote access to ${f.takeovers}`), h('div', { class: 'fp-s faint mono' }, f.entry.how)),
        ),
      ),
    ),
    h(
      'section',
      { class: 'box', style: 'margin-bottom:1rem', id: 'chains' },
      boxHead('Attack chains', `${D.plural(blast.chains.length, 'internal resource')} an attacker can reach, worst first`),
      blast.chains.length
        ? h(
            'div',
            { class: 'tscroll' },
            h(
              'table',
              { class: 't' },
              h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Chain'), h('th', {}, 'Reaches'), h('th', { class: 'hide-sm' }, 'Hops'), h('th', { class: 'last hide-sm' }, 'Rule that cuts it'))),
              h(
                'tbody',
                {},
                ...blast.chains.map((c) => {
                  const end = c.steps.at(-1)!;
                  const cut = cuts.find((x) => x.chainsClosed.includes(c.id));
                  return on(
                    h(
                      'tr',
                      { class: 'click chain-item', tabindex: 0 },
                      h('td', { class: 'first' }, sevPill(c.severity)),
                      h('td', { class: 'tt' }, chainText(c)),
                      h('td', {}, h('div', {}, IMPACT[c.impact]), h('div', { class: 'faint' }, h('span', { class: 'mono' }, end.service ?? ''), end.serviceName ? ` ${end.serviceName}` : '')),
                      h('td', { class: 'hide-sm num' }, String(c.steps.length - 1)),
                      h('td', { class: 'last hide-sm mono' }, cut ? cut.ruleId : h('span', { class: 'faint' }, 'no single rule')),
                    ),
                    'click',
                    () => ctx.go('blast', { chain: `${snap.key}#${c.id}` }),
                  );
                }),
              ),
            ),
          )
        : empty('No attack chains', 'From the servers the internet can reach, no database, cache, control plane or remote administration port is reachable that the internet cannot already reach directly.'),
    ),
    graphBox,
  );
}

function chainDetail(ctx: Ctx, snap: Snap, c: AttackChain, graphBox: HTMLElement): HTMLElement {
  const hopOf = (groupId: string) => c.steps.findIndex((st, n) => n > 0 && (snap.model.enis.get(st.eniId)?.groupIds ?? []).includes(groupId));
  // Rules on the first hop (into the first internal server) are the safe cuts; deeper ones may carry traffic servers need.
  const cuts = D.chokepointsOf(snap).filter((x) => x.chainsClosed.includes(c.id)).map((x) => ({ x, hop: hopOf(x.groupId) })).sort((a, b) => Number(a.hop > 1) - Number(b.hop > 1)).map((a) => a.x);
  const best = cuts.findIndex((x) => hopOf(x.groupId) <= 1);
  const chains = D.blastOf(snap).chains;
  const total = chains.length;
  const i = chains.indexOf(c);
  const pick = (x: AttackChain | undefined) => (x ? () => ctx.go('blast', { chain: `${snap.key}#${x.id}` }) : undefined);
  const prev = pick(chains[i - 1]);
  const next = pick(chains[i + 1]);
  const sec = (title: string, attrs: Record<string, string>, ...body: Child[]) => h('section', { class: 'box dbox', ...attrs }, h('header', {}, h('h2', {}, title)), h('div', { class: 'pad' }, ...body));
  return h(
    'div',
    { class: 'page detail-page', id: 'chain-detail', 'aria-label': 'Attack chain' },
    h(
      'nav',
      { class: 'crumbs' },
      on(h('button', { type: 'button', class: 'back' }, iconSvg('chevl', 14), 'All attack chains'), 'click', () => ctx.go('blast', { chain: '' })),
      h('div', { class: 'stepnav' }, h('span', { class: 'faint' }, `${i + 1} of ${total}`), btn('Previous', 'sm', () => prev?.(), prev ? {} : { disabled: '' }), btn('Next', 'sm', () => next?.(), next ? {} : { disabled: '' })),
    ),
    h(
      'header',
      { class: 'dh' },
      h(
        'div',
        { class: 'dh-main' },
        h('div', { class: 'dh-k' }, sevPill(c.severity), h('span', {}, `${IMPACT[c.impact]} reached in ${D.plural(c.steps.length - 1, 'hop')}`)),
        h('h1', {}, chainText(c)),
        h('p', { class: 'lede' }, chainSentence(c)),
        h('p', { class: 'meta' }, `${snap.account} / ${snap.region}. ${D.collected(snap).text}.`),
      ),
    ),
    h(
      'div',
      { class: 'dgrid' },
      h(
        'div',
        { class: 'dcol' },
        sec(
          'The chain',
          {},
          stepper([
            { k: 'Internet', v: [c.entry.how], state: 'pass' },
            ...c.steps.map((x, k) => ({ k: short(x.name), v: k === 0 ? ['Open to the internet. Assume it can be compromised.'] : [h('code', {}, x.service ?? ''), x.serviceName ? ` ${x.serviceName}` : '', x.category === 'admin' || x.category === 'control' ? ': remote access, so the attacker can move on' : ''], state: (k === c.steps.length - 1 ? 'end' : 'pass') as 'pass' | 'end' })),
          ]),
        ),
        sec('Why', {}, h('ul', { class: 'why' }, ...c.why.map((w) => h('li', {}, w)))),
      ),
      h(
        'div',
        { class: 'dcol' },
        sec(
          'How to cut this chain',
          { id: 'cuts' },
          cuts.length
            ? h(
                'div',
                { class: 'cuts' },
                ...cuts.slice(0, 4).map((x, k) =>
                  h(
                    'div',
                    { class: `cut${k === best ? ' best' : ''}` },
                    h('div', { class: 'cut-h' }, h('span', { class: 'mono strong' }, x.ruleId), k === best ? h('span', { class: 'tag' }, 'Recommended') : h('span', { style: 'margin-right:auto' }), h('span', { class: 'cut-n' }, `cuts ${x.chainsClosed.length} of ${total} chains`)),
                    h('div', { class: 'dim' }, `${x.text} in ${x.groupId}`),
                    ...(() => {
                      const k = hopOf(x.groupId);
                      if (k < 1) return [];
                      const from = short(c.steps[k - 1]!.name);
                      const to = c.steps[k]!;
                      const svc = to.serviceName ? `${to.serviceName} (${to.service})` : to.service ?? '';
                      return [
                        h('div', {}, `Blocks ${from} → ${short(to.name)} on ${svc}.`),
                        k > 1 ? h('div', { class: 'warn' }, `${from} is not internet-facing, so this may be traffic it needs. Check that ${from} does not use ${to.serviceName ?? to.service} on ${short(to.name)} before removing it.`) : null,
                      ];
                    })(),
                    x.exposureClosed.length ? h('div', { class: x.collateral.length ? 'warn' : 'dim' }, `Also changes internet exposure: ${x.exposureClosed.map((d) => `${short(d.resourceName)} ${d.protocol}${d.ports ? `/${d.ports.from === d.ports.to ? d.ports.from : `${d.ports.from}-${d.ports.to}`}` : ''} ${d.status}`).join('; ')}`) : null,
                    h('div', { class: 'cut-a' }, btn([iconSvg('flask', 13), 'Simulate'], 'sm', () => ctx.go('simulator', { simKey: snap.key, changes: [{ kind: 'revoke-sg-rule', ruleId: x.ruleId }] })), btn([iconSvg('copy', 13), 'Copy command'], 'sm', async () => { await D.copyText(x.cli.join('\n')); toast('Copied'); })),
                  ),
                ),
              )
            : h('p', { class: 'dim' }, 'No single security group rule removal cuts this chain. Try the simulator with a network ACL change.'),
          best < 0
            ? h('p', { class: 'dim', style: 'margin:0.75rem 0 0' }, `The other way to cut it is to close the way in. ${c.entries.length > 1 ? `${D.plural(c.entries.length, 'internet-facing server')} reach${c.entries.length === 1 ? 'es' : ''} ${short(c.steps.at(-1)!.name)}: ` : 'Start with '}`, ...c.entries.map((e, n) => [n ? ', ' : '', linkBtn(short(e.name), () => ctx.go('issues', { q: e.eniId, sel: '', cat: '', scope: '', sevOn: new Set(D.SEVERITY_ORDER) }))]).flat(), '.')
            : null,
          h('p', { class: 'faint', style: 'margin:0.75rem 0 0' }, 'Each option was checked by removing the rule from a copy of the snapshot and running the analysis again.'),
        ),
      ),
    ),
    graphBox,
  );
}

// ================================================================== simulator

interface SimResult {
  diff?: ExposureDiff;
  error?: string;
  after?: NetworkModel;
}

const simCache = new Map<string, SimResult>();
function simulate(snap: Snap, changes: Change[]): SimResult {
  const key = `${snap.key}|${JSON.stringify(changes)}`;
  const hit = simCache.get(key);
  if (hit) return hit;
  let r: SimResult;
  try {
    const after = applyChanges(snap.model, changes);
    const e1 = analyzeExposure(after);
    const diff = diffExposure(D.reportOf(snap), e1, { before: D.blastOf(snap), after: analyzeBlastRadius(after, e1) });
    r = { diff, after };
  } catch (e) {
    r = { error: e instanceof ChangeError ? e.message : `Could not apply: ${(e as Error).message}` };
  }
  if (simCache.size > 50) simCache.clear();
  simCache.set(key, r);
  return r;
}

export function simulatorPage(ctx: Ctx): HTMLElement {
  const st = ctx.st;
  if (!st.snaps.length) return h('div', { class: 'page' }, h('div', { class: 'box' }, empty('No snapshots loaded', 'Load a snapshot to try changes against it.')));
  const snap = snapByKey(ctx, st.simKey) ?? st.snaps.find((x) => x.findings.length) ?? st.snaps[0]!;
  const m = snap.model;
  // Changes belong to one snapshot; with none chosen yet, they belong to this one.
  if (!st.simKey) st.simKey = snap.key;
  const changes = st.simKey === snap.key ? st.changes : [];
  const setChanges = (next: Change[]) => {
    st.simKey = snap.key;
    st.changes = next;
    ctx.render();
  };
  const revoked = new Set(changes.filter((c): c is Extract<Change, { kind: 'revoke-sg-rule' }> => c.kind === 'revoke-sg-rule').map((c) => c.ruleId));
  const edited = new Map(changes.filter((c): c is Extract<Change, { kind: 'edit-sg-rule' }> => c.kind === 'edit-sg-rule').map((c) => [c.ruleId, c]));
  const naclOff = new Set(changes.filter((c): c is Extract<Change, { kind: 'remove-nacl-entry' }> => c.kind === 'remove-nacl-entry').map((c) => `${c.naclId}#${c.egress}#${c.ruleNumber}`));
  const ipOff = new Set(changes.filter((c): c is Extract<Change, { kind: 'remove-public-ip' }> => c.kind === 'remove-public-ip').map((c) => c.publicIp));
  const toggle = (match: (c: Change) => boolean, add: Change) => setChanges(changes.some(match) ? changes.filter((c) => !match(c)) : [...changes, add]);

  // ---- left: everything that can be changed
  const q = st.simQuery.trim().toLowerCase();
  const used = new Map<string, number>();
  for (const e of m.enis.values()) for (const g of e.groupIds) used.set(g, (used.get(g) ?? 0) + 1);
  const groups = [...m.securityGroups.values()].filter((g) => used.has(g.id)).sort((a, b) => a.name.localeCompare(b.name));
  const search = h('input', { type: 'search', placeholder: 'Filter rules by ID, group, port or CIDR', value: st.simQuery, 'aria-label': 'Filter rules', id: 'sim-search' }) as HTMLInputElement;
  const list = h('div', { class: 'sim-list' });
  const fill = () => {
    const qq = search.value.trim().toLowerCase();
    list.replaceChildren(
      ...groups.flatMap((g) => {
        const rules = g.ingress.filter((r) => !qq || `${g.id} ${g.name} ${r.id} ${ruleText(r)}`.toLowerCase().includes(qq));
        if (!rules.length) return [];
        return [
          h('div', { class: 'sim-g' }, h('span', { class: 'strong' }, g.name), h('span', { class: 'mono faint' }, g.id), h('span', { class: 'faint' }, `${used.get(g.id)} attached`)),
          ...rules.map((r) => {
            const off = revoked.has(r.id);
            const ed = edited.get(r.id);
            const row = h('div', { class: `sim-r${off ? ' off' : ''}${ed ? ' edited' : ''}` });
            const sw = on(h('button', { type: 'button', class: 'switch', role: 'switch', 'aria-checked': String(!off), 'aria-label': `${off ? 'Restore' : 'Remove'} ${r.id}` }, h('i')), 'click', () => toggle((c) => c.kind === 'revoke-sg-rule' && c.ruleId === r.id, { kind: 'revoke-sg-rule', ruleId: r.id }));
            const text = h('div', { class: 'sim-t' }, h('div', { class: 'mono' }, r.id), h('div', {}, ed ? `${ruleText(r)} → ${ed.cidr ?? r.cidr?.text ?? ''}${ed.fromPort !== undefined ? ` ports ${ed.fromPort}-${ed.toPort}` : ''}` : ruleText(r)));
            const edit = on(h('button', { type: 'button', class: 'btn sm ghost', 'aria-label': `Edit ${r.id}`, disabled: off || !r.cidr, title: !r.cidr ? 'Only rules with an IP range can be edited here. Switch this one off instead.' : off ? 'Switched off' : 'Change the source or ports' }, 'Edit'), 'click', () => {
              const form = h('form', { class: 'sim-edit' });
              const cidr = h('input', { value: ed?.cidr ?? r.cidr?.text ?? '', 'aria-label': 'Source CIDR', class: 'mono', spellcheck: 'false' }) as HTMLInputElement;
              const from = h('input', { value: String(ed?.fromPort ?? r.fromPort ?? ''), 'aria-label': 'From port', class: 'mono', inputmode: 'numeric' }) as HTMLInputElement;
              const to = h('input', { value: String(ed?.toPort ?? r.toPort ?? ''), 'aria-label': 'To port', class: 'mono', inputmode: 'numeric' }) as HTMLInputElement;
              form.append(h('label', {}, 'Source', cidr), h('label', {}, 'Ports', from, '–', to), h('button', { type: 'submit', class: 'btn sm primary' }, 'Apply'), on(h('button', { type: 'button', class: 'btn sm ghost' }, 'Cancel'), 'click', () => form.remove()));
              form.addEventListener('submit', (e) => {
                e.preventDefault();
                const change: Change = { kind: 'edit-sg-rule', ruleId: r.id, ...(cidr.value.trim() && cidr.value.trim() !== r.cidr?.text ? { cidr: cidr.value.trim() } : {}) };
                const fp = Number(from.value);
                const tp = Number(to.value);
                if (from.value !== '' && to.value !== '' && (fp !== r.fromPort || tp !== r.toPort)) Object.assign(change, { fromPort: fp, toPort: tp });
                if (Object.keys(change).length === 2) return form.remove();
                setChanges([...changes.filter((c) => !(c.kind === 'edit-sg-rule' && c.ruleId === r.id)), change]);
              });
              row.append(form);
              cidr.focus();
            });
            row.append(sw, text, edit);
            return row;
          }),
        ];
      }),
    );
    const extra: HTMLElement[] = [];
    const nacls = [...m.nacls.values()].filter((n) => n.entries.some((e) => e.ruleNumber !== 32767));
    const naclRows = nacls.flatMap((n) => n.entries.filter((e) => e.ruleNumber !== 32767 && (!qq || `${n.id} ${e.ruleNumber} ${e.cidr?.text}`.toLowerCase().includes(qq))).map((e) => ({ n, e })));
    if (naclRows.length) {
      extra.push(h('div', { class: 'sim-g' }, h('span', { class: 'strong' }, 'Network ACL entries')));
      for (const { n, e } of naclRows) {
        const key = `${n.id}#${e.egress}#${e.ruleNumber}`;
        const off = naclOff.has(key);
        extra.push(
          h(
            'div',
            { class: `sim-r${off ? ' off' : ''}` },
            on(h('button', { type: 'button', class: 'switch', role: 'switch', 'aria-checked': String(!off), 'aria-label': `${off ? 'Restore' : 'Remove'} ${n.id} rule ${e.ruleNumber}` }, h('i')), 'click', () =>
              toggle((c) => c.kind === 'remove-nacl-entry' && c.naclId === n.id && c.egress === e.egress && c.ruleNumber === e.ruleNumber, { kind: 'remove-nacl-entry', naclId: n.id, egress: e.egress, ruleNumber: e.ruleNumber }),
            ),
            h('div', { class: 'sim-t' }, h('div', { class: 'mono' }, `${n.id} ${e.egress ? 'out' : 'in'} #${e.ruleNumber}`), h('div', {}, `${e.action} ${e.protocol === '-1' ? 'all' : e.protocol === '6' ? 'tcp' : e.protocol === '17' ? 'udp' : `proto ${e.protocol}`}${e.portRange ? ` ${e.portRange.from === e.portRange.to ? e.portRange.from : `${e.portRange.from}-${e.portRange.to}`}` : ''} ${e.egress ? 'to' : 'from'} ${e.cidr?.text ?? ''}`)),
          ),
        );
      }
    }
    const pubs = [...m.enis.values()].filter((e) => isLateralTarget(e) && e.publicAddresses.length).flatMap((e) => e.publicAddresses.map((p) => ({ e, p }))).filter(({ e, p }) => !qq || `${e.id} ${p.publicIp}`.includes(qq));
    if (pubs.length) {
      extra.push(h('div', { class: 'sim-g' }, h('span', { class: 'strong' }, 'Public IPs')));
      for (const { e, p } of pubs) {
        const off = ipOff.has(p.publicIp);
        const inst = e.instanceId ? m.instances.get(e.instanceId) : undefined;
        extra.push(
          h(
            'div',
            { class: `sim-r${off ? ' off' : ''}` },
            on(h('button', { type: 'button', class: 'switch', role: 'switch', 'aria-checked': String(!off), 'aria-label': `${off ? 'Restore' : 'Remove'} ${p.publicIp}` }, h('i')), 'click', () => toggle((c) => c.kind === 'remove-public-ip' && c.publicIp === p.publicIp, { kind: 'remove-public-ip', eniId: e.id, publicIp: p.publicIp })),
            h('div', { class: 'sim-t' }, h('div', { class: 'mono' }, p.publicIp), h('div', {}, `${inst?.name ?? e.id}${p.elastic ? ', Elastic IP' : ''}`)),
          ),
        );
      }
    }
    list.append(...extra);
  };
  search.addEventListener('input', () => {
    st.simQuery = search.value;
    fill();
  });
  fill();

  const sel = snapSelect(ctx, snap.key, (k) => ctx.go('simulator', { simKey: k, changes: [] }));
  const left = h('div', { class: 'list sim-left' }, h('div', { class: 'list-h' }, h('div', { class: 'ph', style: 'margin-bottom:0' }, h('div', {}, h('h1', {}, 'Simulator'), h('p', {}, 'Turn rules off, edit them, or drop public IPs. Everything is re-analysed on a copy; nothing in AWS changes.')), sel ? h('div', { class: 'acts' }, sel) : null)), h('div', { class: 'filters' }, h('label', { class: 'lsearch' }, iconSvg('search', 14), search), h('span', { class: 'count' }, D.plural(changes.length, 'change'))), list);

  // ---- right: the result
  let right: HTMLElement;
  if (!changes.length) {
    right = h('aside', { class: 'panel', id: 'sim-result' }, empty('No changes yet', 'Switch a rule off to see which internet paths and attack chains it closes. Fixes and chain cuts elsewhere in the console open here too.'));
  } else {
    const r = simulate(snap, changes);
    const d = r.diff;
    const tile = (n: number, label: string, tone: string) => h('div', { class: `tile ${tone}` }, h('div', { class: 'tile-v' }, String(n)), h('div', { class: 'tile-k' }, label));
    right = h(
      'aside',
      { class: 'panel', id: 'sim-result', 'aria-label': 'Simulation result' },
      h('div', { class: 'panel-h' }, h('h2', {}, 'Result'), h('p', {}, `${D.plural(changes.length, 'change')} on ${snap.account} / ${snap.region}`)),
      h(
        'div',
        { class: 'panel-b' },
        r.error ? h('div', { class: 'error-bar', style: 'margin:0.75rem' }, r.error) : null,
        d
          ? h(
              'section',
              { class: 'sec' },
              h('div', { class: 'tiles' }, tile(d.closed, 'Exposures closed', d.closed ? 'good' : ''), tile(d.deltas.filter((x) => x.status === 'narrowed').length, 'Narrowed', ''), tile(d.chainsClosed.length, 'Chains cut', d.chainsClosed.length ? 'good' : ''), ((n) => tile(n, 'Newly opened', n ? 'bad' : ''))(d.opened + d.deltas.filter((x) => x.status === 'widened').length + d.chainsOpened.length)),
            )
          : null,
        d && d.deltas.length
          ? h(
              'section',
              { class: 'sec' },
              h('h3', {}, 'Internet exposure'),
              h('div', { class: 'deltas' }, ...d.deltas.map((x) => h('div', { class: `delta ${x.status}` }, h('span', { class: 'st' }, x.status), sevPill(x.severity, `${short(x.resourceName)} ${x.protocol}${x.ports ? `/${x.ports.from === x.ports.to ? x.ports.from : `${x.ports.from}-${x.ports.to}`}` : ''}`), x.status === 'narrowed' || x.status === 'widened' || x.status === 'changed' ? h('span', { class: 'faint mono' }, `${x.before.join(', ').replace(' (every internet address)', '')} → ${x.after.join(', ')}`) : null))),
            )
          : d
            ? h('section', { class: 'sec' }, h('h3', {}, 'Internet exposure'), h('p', { class: 'dim' }, 'No change to what the internet can reach.'))
            : null,
        d && (d.chainsClosed.length || d.chainsOpened.length || d.chainsRevealed.length)
          ? h(
              'section',
              { class: 'sec' },
              h('h3', {}, 'Attack chains'),
              h('div', { class: 'deltas' }, ...d.chainsClosed.map((c) => h('div', { class: 'delta closed' }, h('span', { class: 'st' }, 'cut'), sevPill(c.severity, chainText(c)))), ...d.chainsOpened.map((c) => h('div', { class: 'delta opened' }, h('span', { class: 'st' }, 'new'), sevPill(c.severity, chainText(c)))), ...d.chainsRevealed.map((c) => h('div', { class: 'delta narrowed' }, h('span', { class: 'st' }, 'inside'), sevPill(c.severity, chainText(c))))),
              d.chainsRevealed.length ? h('p', { class: 'dim note' }, `Marked inside: ${d.chainsRevealed.length === 1 ? 'this was' : 'these were'} hidden before because the internet could reach the target directly. With that closed, the target is still reachable from a compromised server inside the VPC. Nothing new was opened.`) : null,
            )
          : null,
        h(
          'section',
          { class: 'sec' },
          h('h3', {}, 'Changes'),
          h(
            'div',
            { class: 'deltas' },
            ...changes.map((c, i) => {
              let text: string;
              try {
                text = describeChange(m, c);
              } catch {
                text = JSON.stringify(c);
              }
              return h('div', { class: 'delta change' }, h('span', {}, text), on(h('button', { type: 'button', class: 'btn sm ghost icon', 'aria-label': 'Undo this change' }, iconSvg('undo', 13)), 'click', () => setChanges(changes.filter((_, j) => j !== i))));
            }),
          ),
        ),
        !r.error
          ? h(
              'section',
              { class: 'sec' },
              h('h3', {}, 'AWS CLI'),
              h('p', { class: 'dim', style: 'margin:0 0 0.5rem' }, 'Review these, then run them yourself. Pinhole never calls AWS write APIs.'),
              cmdBlock(changes.flatMap((c) => cliFor(m, c))),
              h(
                'div',
                { style: 'display:flex;gap:0.375rem;margin-top:0.625rem;flex-wrap:wrap' },
                btn([iconSvg('download', 13), 'Changes as JSON'], 'sm', () => D.saveFile('pinhole-changes.json', `${JSON.stringify(changes, null, 2)}\n`, 'application/json')),
                btn('Clear all', 'sm ghost', () => setChanges([])),
              ),
            )
          : null,
      ),
    );
  }
  return h('div', { class: 'sim-page' }, left, right);
}

// ================================================================== reachability query

function resolveRef(m: NetworkModel, ref: string): string | undefined {
  const r = ref.trim();
  if (!r) return undefined;
  if (m.enis.has(r)) return r;
  const byId = m.instances.get(r);
  if (byId?.primaryEniId) return byId.primaryEniId;
  const named = [...m.instances.values()].filter((i) => i.name?.toLowerCase() === r.toLowerCase());
  if (named.length === 1) return named[0]!.primaryEniId;
  const ip = [...m.enis.values()].find((e) => e.privateIps.includes(r));
  return ip?.id;
}
const isInternet = (ref: string) => /^internet$/i.test(ref.trim()) || (/^\d+\.\d+\.\d+\.\d+$/.test(ref.trim()) && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ref.trim()));
const eniLabel = (m: NetworkModel, id: string) => {
  const e = m.enis.get(id);
  const inst = e?.instanceId ? m.instances.get(e.instanceId) : undefined;
  return inst?.name ? `${inst.name} (${id})` : id;
};

export function askPage(ctx: Ctx): HTMLElement {
  const st = ctx.st;
  if (!st.snaps.length) return h('div', { class: 'page' }, h('div', { class: 'box' }, empty('No snapshots loaded', 'Load a snapshot to query it.')));
  const snap = snapByKey(ctx, st.askKey) ?? st.snaps.find((x) => D.blastOf(x).edges.length) ?? st.snaps[0]!;
  const m = snap.model;
  const names = [...m.enis.values()].filter(isLateralTarget).map((e) => {
    const inst = e.instanceId ? m.instances.get(e.instanceId) : undefined;
    return { id: e.id, label: inst?.name ?? e.id, ip: e.privateIps[0] ?? '' };
  });
  const dl = h('datalist', { id: 'ask-names' }, h('option', { value: 'internet' }, 'Any internet address'), ...names.map((n) => h('option', { value: n.label }, `${n.id} ${n.ip}`)));
  const input = (v: string, label: string, id: string) => h('input', { value: v, list: 'ask-names', 'aria-label': label, id, spellcheck: 'false', autocomplete: 'off', placeholder: 'Name, ID, private IP or internet' }) as HTMLInputElement;
  const from = input(st.askFrom, 'From', 'ask-from');
  const to = input(st.askTo, 'To', 'ask-to');
  const proto = h('select', { 'aria-label': 'Protocol', id: 'ask-proto' }, ...['tcp', 'udp', 'icmp'].map((p) => h('option', { value: p }, p))) as HTMLSelectElement;
  proto.value = st.askProto;
  const port = h('input', { value: st.askPort, 'aria-label': 'Port', id: 'ask-port', placeholder: 'any', inputmode: 'numeric', class: 'port' }) as HTMLInputElement;
  const submit = (e?: Event) => {
    e?.preventDefault();
    ctx.go('ask', { askFrom: from.value, askTo: to.value, askProto: proto.value, askPort: port.value.trim() });
  };
  const mode = (k: 'pair' | 'who', label: string) => on(h('button', { type: 'button', 'aria-pressed': String(st.askMode === k) }, label), 'click', () => ctx.go('ask', { askMode: k }));
  const sel = snapSelect(ctx, snap.key, (k) => ctx.go('ask', { askKey: k }));
  const form = h(
    'form',
    { class: 'ask-form box' },
    h('div', { class: 'seg' }, mode('pair', 'Can A reach B'), mode('who', 'Who can reach B')),
    st.askMode === 'pair' ? h('label', {}, h('span', {}, 'From'), from) : null,
    h('label', {}, h('span', {}, st.askMode === 'pair' ? 'To' : 'Target'), to),
    st.askMode === 'pair' ? h('label', {}, h('span', {}, 'Protocol'), proto) : null,
    st.askMode === 'pair' ? h('label', {}, h('span', {}, 'Port'), port) : null,
    h('button', { type: 'submit', class: 'btn primary' }, 'Check'),
    dl,
  );
  form.addEventListener('submit', submit);

  const results = h('div', { class: 'ask-results' });
  const toId = st.askTo ? resolveRef(m, st.askTo) : undefined;
  if (st.askTo && !toId) results.append(h('div', { class: 'error-bar' }, `"${st.askTo}" is not a name, interface ID, instance ID or private IP in ${snap.account} / ${snap.region}.`));
  else if (toId && st.askMode === 'who') results.append(whoCanReach(m, snap, toId));
  else if (toId && st.askFrom) {
    if (isInternet(st.askFrom)) {
      const ip = /^internet$/i.test(st.askFrom.trim()) ? '198.51.100.1' : st.askFrom.trim();
      if (st.askPort) {
        const r = evaluatePath(m, { from: { internet: ip }, to: { eni: toId }, protocol: st.askProto, port: Number(st.askPort) });
        results.append(verdictBox(r, `${ip === '198.51.100.1' ? 'An internet address' : ip} → ${eniLabel(m, toId)}`));
      } else {
        const rep = analyzeExposure(m, { only: new Set([toId]) });
        results.append(servicesBox(`The internet → ${eniLabel(m, toId)}`, rep.findings.map((f) => ({ label: serviceLabel(f), sev: f.severity, note: `from ${f.sources.join(', ')}`, hops: f.trace }))));
      }
    } else {
      const fromId = resolveRef(m, st.askFrom);
      if (!fromId) results.append(h('div', { class: 'error-bar' }, `"${st.askFrom}" is not a name, interface ID, instance ID or private IP in ${snap.account} / ${snap.region}.`));
      else if (st.askPort) {
        const r = evaluatePath(m, { from: { eni: fromId }, to: { eni: toId }, protocol: st.askProto, port: Number(st.askPort) });
        results.append(verdictBox(r, `${eniLabel(m, fromId)} → ${eniLabel(m, toId)}`));
      } else {
        const reach = reachServices(m, fromId, toId);
        results.append(servicesBox(`${eniLabel(m, fromId)} → ${eniLabel(m, toId)}`, reach.services.map((x) => ({ label: serviceLabel(x), sev: x.severity, note: svcNote(x), hops: x.trace }))));
      }
    }
  } else {
    results.append(
      h(
        'div',
        { class: 'box' },
        empty(
          'Ask a question',
          'Pick two resources to see every service one can open on the other, or a target to see everything that can reach it.',
          ...(names.length > 1 ? [btn(`Try: ${names[0]!.label} → ${names[names.length - 1]!.label}`, '', () => ctx.go('ask', { askMode: 'pair', askFrom: names[0]!.label, askTo: names[names.length - 1]!.label, askPort: '' }))] : []),
        ),
      ),
    );
  }

  return h('div', { class: 'page' }, h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Reachability query'), h('p', {}, 'Exact answers from the same model as the rest of the console: every security group, network ACL and route on the way, both directions.')), sel ? h('div', { class: 'acts' }, sel) : null), form, results);
}

const svcNote = (x: ServiceReach) => [x.name, x.pivot ? 'remote access' : '', x.verdict === 'unknown' ? `unknown: ${x.unknownAt ?? ''}` : '', x.returnPath === 'partial' ? 'responses only for some client ports' : ''].filter(Boolean).join(', ');

function verdictBox(r: PathResult, title: string): HTMLElement {
  const tone = r.verdict === 'reachable' ? 'good' : r.verdict === 'blocked' ? 'bad' : 'warn';
  return h('section', { class: 'box', id: 'ask-verdict' }, boxHead(title), h('div', { class: 'pad' }, h('div', { class: `verdict ${tone}` }, r.verdict === 'reachable' ? 'Reachable' : r.verdict === 'blocked' ? 'Blocked' : 'Unknown'), h('p', { class: 'dim' }, r.summary), traceStepper(r)));
}

function servicesBox(title: string, list: { label: string; sev: Severity; note: string; hops: PathResult['hops'] }[]): HTMLElement {
  const box = h('section', { class: 'box', id: 'ask-services' }, boxHead(title, list.length ? D.plural(list.length, 'service') : 'nothing reachable'));
  box.append(
    h(
      'div',
      { class: 'pad' },
      h('div', { class: `verdict ${list.length ? 'good' : 'bad'}` }, list.length ? `Yes, ${D.plural(list.length, 'service')} reachable` : 'No, nothing reachable'),
      h('p', { class: 'dim', style: 'margin-bottom:0' }, list.length ? 'Each row is a protocol and port range that gets through every security group, network ACL and route, in both directions. Select one for its path.' : 'No protocol or port is reachable. Every candidate was checked through security groups, network ACLs and routes.'),
    ),
  );
  if (!list.length) return box;
  const detailHost = h('div', { class: 'pad' });
  const table = h(
    'table',
    { class: 't' },
    h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Service'), h('th', {}, 'Risk'), h('th', { class: 'last' }, 'Notes'))),
    h(
      'tbody',
      {},
      ...list.map((x, i) => {
        const tr = on(h('tr', { class: 'click', tabindex: 0, 'aria-selected': String(i === 0) }, h('td', { class: 'first mono' }, x.label), h('td', {}, sevPill(x.sev)), h('td', { class: 'last dim' }, x.note)), 'click', () => {
          for (const r of tr.parentElement!.children) r.setAttribute('aria-selected', String(r === tr));
          detailHost.replaceChildren(h('h3', { class: 'mini-h' }, `Path for ${x.label}`), traceStepper({ hops: x.hops }));
        });
        return tr;
      }),
    ),
  );
  detailHost.append(h('h3', { class: 'mini-h' }, `Path for ${list[0]!.label}`), traceStepper({ hops: list[0]!.hops }));
  box.append(table, detailHost);
  return box;
}

function whoCanReach(m: NetworkModel, snap: Snap, toId: string): HTMLElement {
  const rows: { id: string; services: ServiceReach[] }[] = [];
  for (const e of m.enis.values()) {
    if (e.id === toId || !e.privateIps.length) continue;
    const r = reachServices(m, e.id, toId);
    const live = r.services.filter((x) => x.verdict === 'reachable');
    if (live.length) rows.push({ id: e.id, services: live });
  }
  rows.sort((a, b) => D.sevRank(a.services.reduce<Severity>((w, x) => (D.sevRank(x.severity) < D.sevRank(w) ? x.severity : w), 'info')) - D.sevRank(b.services.reduce<Severity>((w, x) => (D.sevRank(x.severity) < D.sevRank(w) ? x.severity : w), 'info')));
  const internet = snap.findings.filter((f) => f.resourceId === toId);
  const box = h('section', { class: 'box', id: 'ask-who' }, boxHead(`Who can reach ${eniLabel(m, toId)}`, `${D.plural(rows.length, 'resource')}${internet.length ? ', and the internet' : ''}`));
  box.append(
    h(
      'table',
      { class: 't' },
      h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Source'), h('th', { class: 'last' }, 'Services it can open'))),
      h(
        'tbody',
        {},
        ...internet.map((f) => h('tr', {}, h('td', { class: 'first strong' }, 'Internet'), h('td', { class: 'last' }, h('div', { class: 'chips' }, sevPill(f.severity, `${serviceLabel(f)} from ${f.sources.join(', ')}`))))),
        ...rows.map((r) => h('tr', {}, h('td', { class: 'first' }, eniLabel(m, r.id)), h('td', { class: 'last' }, h('div', { class: 'chips' }, ...r.services.map((x) => sevPill(x.severity, `${serviceLabel(x)}${x.name ? ` ${x.name}` : ''}`)))))),
        !rows.length && !internet.length ? h('tr', {}, h('td', { class: 'first dim', colspan: 2 }, 'Nothing in the snapshot can reach it.')) : null,
      ),
    ),
  );
  return box;
}

// ================================================================== hygiene

const HYG_LABEL: Record<string, string> = {
  'open-to-world': 'Open to the world',
  'all-ports': 'Every port allowed',
  'broad-internal-source': 'Broad internal source',
  'shadowed-nacl-entry': 'Shadowed NACL entry',
  'redundant-sg-rule': 'Redundant rule',
  'stale-group-reference': 'Stale group reference',
  'unused-security-group': 'Unused group',
};

export function hygienePage(ctx: Ctx): HTMLElement {
  const st = ctx.st;
  const every = D.hygieneRows(st.snaps);
  const dup = every.filter((x) => x.h.inExposure);
  const all = st.hygAll ? every : every.filter((x) => !x.h.inExposure);
  const codes = [...new Set(all.map((x) => x.h.code))];
  const list = all.filter((x) => !st.hygCode || x.h.code === st.hygCode);
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Kind' }, on(h('button', { type: 'button', 'aria-pressed': String(!st.hygCode) }, `All ${all.length}`), 'click', () => ctx.go('hygiene', { hygCode: '' })), ...codes.map((c) => on(h('button', { type: 'button', 'aria-pressed': String(st.hygCode === c) }, `${HYG_LABEL[c] ?? c} ${all.filter((x) => x.h.code === c).length}`), 'click', () => ctx.go('hygiene', { hygCode: c }))));
  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Rule hygiene'), h('p', {}, 'Rules that do nothing, can never match, point at something that is gone, or allow much more than they need to.'))),
    h('div', { class: 'hyg-filter' }, seg),
    dup.length
      ? h(
          'p',
          { class: 'hyg-note dim' },
          st.hygAll
            ? `Including ${D.plural(dup.length, 'rule')} that already let the internet in; those are also under Exposures. `
            : `${D.plural(dup.length, 'more rule')} open to the world already ${dup.length === 1 ? 'lets' : 'let'} the internet in, so ${dup.length === 1 ? 'it is' : 'they are'} under Exposures instead of here. `,
          linkBtn(st.hygAll ? 'Hide them' : 'Show them here too', () => ctx.go('hygiene', { hygAll: !st.hygAll, hygCode: '' })),
        )
      : null,
    h(
      'section',
      { class: 'box', style: 'overflow:auto' },
      list.length
        ? h(
            'table',
            { class: 't hyg' },
            h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Finding'), h('th', { class: 'hide-sm' }, 'Account and region'), h('th', { class: 'last' }, ''))),
            h(
              'tbody',
              {},
              ...list.map((x) =>
                h(
                  'tr',
                  {},
                  h('td', { class: 'first' }, sevPill(x.h.severity)),
                  h('td', {}, h('div', { class: 'strong' }, x.h.title), h('div', { class: 'dim', style: 'max-width:90ch' }, x.h.detail)),
                  h('td', { class: 'mono faint hide-sm' }, `${x.snap.account} ${x.snap.region}`),
                  h(
                    'td',
                    { class: 'last', style: 'white-space:nowrap' },
                    x.h.fix ? btn([iconSvg('flask', 13), 'Simulate fix'], 'sm', () => ctx.go('simulator', { simKey: x.snap.key, changes: x.h.fix! })) : null,
                    x.h.cli ? btn([iconSvg('copy', 13), 'Copy command'], 'sm ghost', async () => { await D.copyText(x.h.cli!.join('\n')); toast('Copied'); }) : null,
                  ),
                ),
              ),
            ),
          )
        : empty('Clean', 'No rule hygiene findings in the loaded snapshots.'),
    ),
  );
}

// ================================================================== fixes in the issue detail

export function fixesSection(ctx: Ctx, row: Row): HTMLElement {
  const fixes = D.fixesOf(row).filter((x) => x.verified).slice(0, 3);
  const sec = h('section', { class: 'sec', id: 'fixes' }, h('h3', {}, 'Verified fixes'));
  if (!fixes.length) {
    sec.append(h('p', { class: 'dim' }, 'No single change was found that closes this path. Use the simulator to try combinations.'));
    return sec;
  }
  sec.append(
    h(
      'div',
      { class: 'cuts' },
      ...fixes.map((x, i) =>
        h(
          'div',
          { class: `cut${i === 0 ? ' best' : ''}` },
          h('div', { class: 'cut-h' }, h('span', { class: 'strong' }, x.changes.length === 1 && x.changes[0]!.kind === 'revoke-sg-rule' && x.steps[0] ? x.steps[0] : x.title), i === 0 ? h('span', { class: 'tag' }, 'Recommended') : null),
          ...(x.changes.length === 1 && x.changes[0]!.kind === 'revoke-sg-rule' ? [] : x.steps.map((s) => h('div', { class: 'dim' }, s))),
          x.bonus.length ? h('div', { class: 'good-t' }, `Also closes ${x.bonus.map((d) => `${short(d.resourceName)} ${d.protocol}${d.ports ? `/${d.ports.from}` : ''}`).join(', ')}`) : null,
          x.stillReachable.length ? h('div', { class: 'warn' }, `Keeps access from inside, but ${[...new Set(x.stillReachable.map((c) => short(c.steps[0]!.name)))].join(' and ')} could still reach it if compromised.`) : null,
          x.collateral.length ? h('div', { class: 'warn' }, `Also affects ${x.collateral.map((d) => `${short(d.resourceName)} ${d.protocol}${d.ports ? `/${d.ports.from}` : ''} (${d.status})`).join(', ')}. Check these are not wanted.`) : null,
          h('div', { class: 'cut-a' }, btn([iconSvg('flask', 13), 'Simulate'], 'sm', () => ctx.go('simulator', { simKey: row.snap.key, changes: x.changes })), btn([iconSvg('copy', 13), 'Copy command'], 'sm', async () => { await D.copyText(x.cli.join('\n')); toast('Copied'); })),
        ),
      ),
    ),
    h('p', { class: 'faint', style: 'margin:0.75rem 0 0' }, 'Verified: each change was applied to a copy of the snapshot and the analysis run again. Nothing in AWS is changed; review the command, then run it yourself.'),
  );
  return sec;
}

// ================================================================== command palette

interface Item {
  label: string;
  hint: string;
  icon: string;
  act: () => void;
}

export function openPalette(ctx: Ctx, pages: { route: string; label: string; icon: string }[]) {
  if (document.querySelector('dialog.palette')) return;
  const items: Item[] = [
    ...pages.map((p) => ({ label: p.label, hint: 'Page', icon: p.icon, act: () => ctx.go(p.route) })),
    ...ctx.rows().slice(0, 300).map((r) => ({ label: `${short(r.f.resourceName)} on ${D.service(r.f)}`, hint: `Issue, ${D.SEV_LABEL[r.f.severity]}`, icon: 'list', act: () => ctx.go('issues', { sel: r.id }) })),
    ...D.chainsOf(ctx.st.snaps).slice(0, 100).map((c) => ({ label: chainText(c.c), hint: `Attack chain, ${D.SEV_LABEL[c.c.severity]}`, icon: 'blast', act: () => ctx.go('blast', { blastKey: c.snap.key, chain: c.id }) })),
    ...ctx.st.snaps.flatMap((sn) => [...sn.model.enis.values()].filter(isLateralTarget).map((e) => ({ label: eniLabel(sn.model, e.id), hint: `Who can reach it, ${sn.account} ${sn.region}`, icon: 'route', act: () => ctx.go('ask', { askKey: sn.key, askMode: 'who', askTo: e.id }) }))),
  ];
  const dlg = h('dialog', { class: 'palette', 'aria-label': 'Command palette' }) as HTMLDialogElement;
  const close = () => (typeof dlg.close === 'function' ? dlg.close() : dlg.remove());
  const input = h('input', { placeholder: 'Go to a page, exposure, attack chain or resource', 'aria-label': 'Search', spellcheck: 'false', autocomplete: 'off' }) as HTMLInputElement;
  const list = h('div', { class: 'pal-list', role: 'listbox' });
  let active = 0;
  let shown: Item[] = [];
  const draw = () => {
    const words = input.value.toLowerCase().split(/\s+/).filter(Boolean);
    shown = items.filter((x) => words.every((w) => `${x.label} ${x.hint}`.toLowerCase().includes(w))).slice(0, 40);
    active = Math.min(active, Math.max(0, shown.length - 1));
    list.replaceChildren(
      ...(shown.length
        ? shown.map((x, i) =>
            on(h('button', { type: 'button', class: 'pal-i', role: 'option', 'aria-selected': String(i === active) }, iconSvg(x.icon, 15), h('span', { class: 'pal-l' }, x.label), h('span', { class: 'pal-h' }, x.hint)), 'click', () => {
              close();
              x.act();
            }),
          )
        : [h('div', { class: 'pal-empty' }, 'Nothing matches.')]),
    );
    (list.children[active] as HTMLElement | undefined)?.scrollIntoView?.({ block: 'nearest' });
  };
  input.addEventListener('input', () => {
    active = 0;
    draw();
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') active = Math.min(active + 1, shown.length - 1);
    else if (e.key === 'ArrowUp') active = Math.max(active - 1, 0);
    else if (e.key === 'Enter') {
      const x = shown[active];
      if (x) {
        close();
        x.act();
      }
      return;
    } else return;
    e.preventDefault();
    draw();
  });
  dlg.append(h('div', { class: 'pal-in' }, iconSvg('search', 16), input, h('kbd', {}, 'Esc')), list);
  dlg.addEventListener('close', () => dlg.remove());
  dlg.addEventListener('click', (e) => e.target === dlg && close());
  document.body.append(dlg);
  draw();
  if (typeof dlg.showModal === 'function') dlg.showModal();
  else dlg.setAttribute('open', '');
  input.focus();
}


// ================================================================== fix plan (dashboard)

export function planBox(ctx: Ctx): HTMLElement {
  const plans = ctx.st.snaps.map((snap) => ({ snap, plan: D.planOf(snap) })).filter((x) => x.plan.before.exposures || x.plan.before.chains);
  const box = h('section', { class: 'box s8', id: 'plan' }, boxHead('Fix plan', 'Fewest changes that close every critical and high risk, each proved by re-analysis'));
  if (!plans.length) {
    box.append(h('div', { class: 'pad' }, h('p', { class: 'plan-sum' }, 'Nothing critical or high to fix.'), h('p', { class: 'dim', style: 'margin:0' }, 'No critical or high exposure and no attack chain in the loaded snapshots.')));
    return box;
  }
  const steps = plans.flatMap(({ snap, plan }) => plan.steps.map((step) => ({ snap, step })));
  const sum = (k: 'before' | 'after', f: 'exposures' | 'chains') => plans.reduce((n, x) => n + x.plan[k][f], 0);
  const coll = steps.reduce((n, x) => n + x.step.collateral.length, 0);
  const closedE = sum('before', 'exposures') - sum('after', 'exposures');
  const closedC = sum('before', 'chains') - sum('after', 'chains');
  const parts = [
    sum('before', 'exposures') ? `${closedE} of ${sum('before', 'exposures')} critical and high exposures` : '',
    sum('before', 'chains') ? `${closedC} of ${sum('before', 'chains')} attack chains` : '',
  ].filter(Boolean);
  box.append(
    h(
      'div',
      { class: 'pad plan-head' },
      h('p', { class: 'plan-sum' }, `${D.plural(steps.length, 'change')} close${steps.length === 1 ? 's' : ''} ${parts.join(' and ')}.`),
      h('p', { class: 'dim', style: 'margin:0' }, coll ? `${D.plural(coll, 'other path')} would also close; each is shown on its step. Check those are not wanted.` : 'Nothing else that is reachable today changes: no web or low-risk path is closed.'),
    ),
  );
  const lab = (d: { resourceName: string; protocol: string; ports?: { from: number; to: number } }) => `${short(d.resourceName)} ${d.protocol}${d.ports ? `/${d.ports.from === d.ports.to ? d.ports.from : `${d.ports.from}-${d.ports.to}`}` : ''}`;
  box.append(
    h(
      'ol',
      { class: 'plan' },
      ...steps.map(({ snap, step }, i) =>
        h(
          'li',
          {},
          h('span', { class: 'plan-n' }, String(i + 1)),
          h(
            'div',
            { class: 'plan-b' },
            ...(() => {
              const said = step.changes.map((c) => { try { return describeChange(snap.model, c); } catch { return ''; } }).filter(Boolean);
              const single = step.changes.length === 1 && step.changes[0]!.kind === 'revoke-sg-rule' && said.length === 1;
              return single ? [h('div', { class: 'plan-t' }, said[0]!)] : [h('div', { class: 'plan-t' }, step.title), said.length ? h('div', { class: 'plan-d' }, said.join('. ')) : null];
            })(),
            h(
              'div',
              { class: 'chips' },
              ...step.closes.map((d) => sevPill(d.severity, `${d.status === 'narrowed' ? 'narrows' : 'closes'} ${lab(d)}`)),
              ...step.chainsCut.map((c) => sevPill(c.severity, `cuts ${chainText(c)}`)),
              ...step.collateral.map((d) => h('span', { class: 'chip warn-chip' }, `also ${d.status} ${lab(d)}`)),
            ),
          ),
          h('span', { class: 'plan-s mono faint hide-sm' }, `${snap.account} ${snap.region}`),
        ),
      ),
    ),
  );
  const unresolved = plans.flatMap((x) => x.plan.unresolved);
  if (unresolved.length) box.append(h('div', { class: 'pad warn' }, `No single change closes ${unresolved.join('; ')}. Try combinations in the simulator.`));
  box.append(
    h(
      'div',
      { class: 'plan-a' },
      ...plans.filter((x) => x.plan.steps.length).map(({ snap, plan }) =>
        btn([iconSvg('flask', 13), plans.length > 1 ? `Open ${snap.account} ${snap.region} in simulator` : 'Open plan in simulator'], 'sm primary', () => ctx.go('simulator', { simKey: snap.key, changes: plan.steps.flatMap((x) => x.changes) })),
      ),
      btn([iconSvg('copy', 13), 'Copy all commands'], 'sm', async () => {
        await D.copyText(plans.map(({ snap, plan }) => [`# ${snap.account} ${snap.region}`, ...plan.steps.flatMap((x) => x.cli)].join('\n')).join('\n\n'));
        toast('Copied');
      }),
    ),
  );
  return box;
}
