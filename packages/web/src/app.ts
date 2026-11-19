/**
 * Pinhole web console. A static page: snapshots are read with FileReader
 * and analysed in this tab by the engine. Nothing is sent anywhere.
 *
 * Pages: dashboard, attack graph, issues, resources, coverage, connect.
 * Rendering builds DOM nodes and inserts snapshot values as text only.
 */
import './style.css';
import { h, s, on, filePicker, toast } from './dom.js';
import type { Child } from './dom.js';
import * as D from './data.js';
import type { Category, Row, Severity, Snap } from './data.js';
import { iconFor, iconSvg, renderGraph } from './graph.js';
import { ALL, boxHead, btn, empty, linkBtn, sevPill, sevVar, softVar } from './ui.js';
import { reportDoc, reportHtml, REPORT_CSS } from './report.js';
import { comparePage } from './compare.js';
import { policyPage } from './policy.js';
import { egressOf, egressPage } from './egress.js';
import { savingsPage, savingsTotal, usd } from './savings.js';
import * as S from './store.js';
import type { Stored } from './store.js';
import { trashPage } from './trash.js';
import { onPremOf, onPremPage } from './onprem.js';
import { privateLinkOf, privateLinkPage } from './privatelink.js';
import { askPage, blastPage, fixesSection, hygienePage, openPalette, planBox, simulatorPage } from './pages.js';
import type { Ctx } from './pages.js';
import type { Change } from '@pinhole/engine';
import { assertChanges } from '@pinhole/engine';


type Route = 'dashboard' | 'graph' | 'blast' | 'issues' | 'resources' | 'hygiene' | 'policy' | 'savings' | 'trash' | 'egress' | 'onprem' | 'privatelink' | 'coverage' | 'simulator' | 'compare' | 'ask' | 'report' | 'connect';
const ROUTES: Route[] = ['dashboard', 'graph', 'blast', 'issues', 'resources', 'hygiene', 'policy', 'savings', 'trash', 'egress', 'onprem', 'privatelink', 'coverage', 'simulator', 'compare', 'ask', 'report', 'connect'];
const PAGES: { route: Route; label: string; icon: string; keys?: string }[] = [
  { route: 'dashboard', label: 'Dashboard', icon: 'home' },
  { route: 'graph', label: 'Attack graph', icon: 'graph' },
  { route: 'blast', label: 'Blast radius', icon: 'blast', keys: 'attack chains lateral movement crown jewels' },
  { route: 'issues', label: 'Exposures', icon: 'list' },
  { route: 'resources', label: 'Resources', icon: 'box' },
  { route: 'egress', label: 'Outbound', icon: 'outbound', keys: 'egress exfiltration nat gateway internet out' },
  { route: 'onprem', label: 'On-premises', icon: 'onprem', keys: 'vpn direct connect hybrid datacenter office vgw' },
  { route: 'privatelink', label: 'PrivateLink', icon: 'link', keys: 'endpoint service vpce private link' },
  { route: 'hygiene', label: 'Rule hygiene', icon: 'broom', keys: 'cleanup redundant shadowed unused firewall rules' },
  { route: 'policy', label: 'Policies', icon: 'policy', keys: 'rules deny require compliance' },
  { route: 'savings', label: 'Savings', icon: 'coin', keys: 'cost money bill elastic ip nat gateway idle unused load balancer s3 endpoint' },
  { route: 'coverage', label: 'Coverage', icon: 'shield' },
  { route: 'simulator', label: 'Simulator', icon: 'flask', keys: 'what if change' },
  { route: 'compare', label: 'Compare snapshots', icon: 'compare' },
  { route: 'ask', label: 'Reachability query', icon: 'route', keys: 'can reach path fix repair why blocked' },
  { route: 'report', label: 'Report', icon: 'file' },
  { route: 'trash', label: 'Trash', icon: 'trash', keys: 'deleted removed restore recycle bin' },
  { route: 'connect', label: 'Connect an account', icon: 'plug' },
];
type CatFilter = Category | 'world' | '';

const st = {
  /** The navigation menu is open (phones and tablets). */
  menu: false,
  /** Every loaded snapshot, including older ones of the same account and region. */
  all: [] as Snap[],
  /** The latest snapshot of each account and region: what every analysis page uses. */
  snaps: [] as Snap[],
  cmpOld: '',
  cmpNew: '',
  demo: true,
  route: 'dashboard' as Route,
  sel: '' as string,
  sevOn: new Set<Severity>(D.SEVERITY_ORDER),
  cat: '' as CatFilter,
  scope: '',
  q: '',
  gq: '',
  showTargets: true,
  regions: 'us-east-1',
  blastKey: '',
  chain: '',
  simKey: '',
  changes: [] as Change[],
  simQuery: '',
  askKey: '',
  askMode: 'pair' as 'pair' | 'who',
  askFrom: '',
  askTo: '',
  askProto: 'tcp',
  askPort: '',
  hygCode: '',
  hygAll: false,
  error: '',
  /** Notes from reading the last files (comments removed, secrets removed, a file cut short by paging). */
  notes: [] as string[],
  /** Snapshots in the trash (kept in this browser). */
  trash: [] as Stored[],
};
let rows: Row[] = [];

const pathTitle = (r: Row) => `${D.shortName(r.f)} on ${D.service(r.f)}${r.f.family === 'ipv6' ? ' over IPv6' : ''}`;
const scopeOf = (r: Row) => `${r.snap.account} / ${r.snap.region}`;

// ---------------------------------------------------------------- data in

function setSnaps(all: Snap[], demo: boolean) {
  st.all = all;
  const snaps = D.latestPerScope(all);
  st.snaps = snaps;
  st.demo = demo;
  st.cmpOld = '';
  st.cmpNew = '';
  rows = D.rowsOf(snaps);
  st.sel = '';
  st.cat = '';
  st.scope = '';
  st.q = '';
  st.gq = '';
  st.blastKey = '';
  st.chain = '';
  st.simKey = '';
  st.changes = [];
  st.askKey = '';
  st.askFrom = '';
  st.askTo = '';
  st.askPort = '';
}

function addSnaps(loaded: D.Loaded) {
  st.error = loaded.errors.join(' ');
  st.notes = loaded.notes;
  const list = loaded.snaps;
  if (list.length) {
    const keep = st.demo ? [] : st.all.filter((x) => !list.some((n) => n.key === x.key));
    setSnaps([...keep, ...list], false);
    st.route = 'dashboard';
    // Kept in this browser so a refresh does not lose them; a snapshot loaded again replaces its copy, and leaves the trash.
    st.trash = st.trash.filter((r) => !loaded.records.some((n) => n.id === r.id));
    void S.put(loaded.records).then(() => S.keep());
    toast(`Loaded ${D.plural(list.length, 'snapshot')}`);
  }
  render();
}

function loadText(text: string, name: string): boolean {
  const loaded = D.parseText(text, name);
  addSnaps(loaded);
  return loaded.snaps.length > 0 && !loaded.errors.length;
}

const pick = filePicker((files) => {
  void D.readFiles(files).then(addSnaps, (e) => addSnaps({ snaps: [], records: [], notes: [], errors: [String((e as Error)?.message ?? e)] }));
});

/** Moves the snapshots of one account and region to the trash, with Undo. */
function removeScope(account: string, region: string) {
  const gone = st.all.filter((y) => y.account === account && y.region === region);
  setSnaps(st.all.filter((y) => !gone.includes(y)), false);
  const ids = gone.map((x) => x.key);
  void S.setDeleted(ids, true).then(refreshTrash);
  render();
  toast(`Moved ${account} / ${region} to the trash`, 'toast', { label: 'Undo', run: () => void restore(ids) });
}
async function refreshTrash() {
  st.trash = (await S.all()).filter((r) => r.deletedAt !== undefined);
  render();
}
async function restore(ids: string[]) {
  await S.setDeleted(ids, false);
  const back = (await S.all()).filter((r) => ids.includes(r.id)).map(D.fromStored);
  const snaps = back.filter((x): x is Snap => typeof x !== 'string');
  const errors = back.filter((x): x is string => typeof x === 'string');
  if (snaps.length) setSnaps([...(st.demo ? [] : st.all.filter((x) => !snaps.some((n) => n.key === x.key))), ...snaps], false);
  st.error = errors.join(' ');
  if (snaps.length) toast(`Restored ${D.plural(snaps.length, 'snapshot')}`);
  await refreshTrash();
}
async function purge(ids: string[]) {
  await S.remove(ids);
  await refreshTrash();
  toast(`Deleted ${D.plural(ids.length, 'snapshot')}`);
}
async function forgetAll() {
  await S.clear();
  st.trash = [];
  setSnaps(D.demoSnaps(), true);
  render();
  toast('Everything this browser kept was deleted');
}

/** On start: the snapshots kept from last time, or the demo when there are none. */
async function restoreSaved() {
  const saved = await S.all();
  st.trash = saved.filter((r) => r.deletedAt !== undefined);
  const live = saved.filter((r) => r.deletedAt === undefined).map(D.fromStored);
  const snaps = live.filter((x): x is Snap => typeof x !== 'string');
  const errors = live.filter((x): x is string => typeof x === 'string');
  // Something loaded in the meantime (a quick drop, or the test API) wins over what was kept.
  if (snaps.length && st.demo) {
    const route = st.route;
    setSnaps(snaps, false);
    st.route = route;
    loadSim();
  }
  if (errors.length) st.error = `Some kept snapshots could not be read again and were skipped: ${errors.join(' ')}`;
  render();
}
document.addEventListener('dragenter', () => document.body.classList.add('dragging'));
document.addEventListener('dragleave', (e) => !e.relatedTarget && document.body.classList.remove('dragging'));
document.addEventListener('drop', () => document.body.classList.remove('dragging'));

// ---------------------------------------------------------------- navigation

function go(route: Route, patch: Partial<typeof st> = {}) {
  Object.assign(st, patch);
  st.route = route;
  st.menu = false;
  try {
    if (location.hash !== `#/${route}`) history.replaceState(null, '', `#/${route}`);
  } catch {
    /* file:// in some browsers */
  }
  scrollMemo.delete(`${st.route}|${st.sel}|${st.chain}`);
  render();
  document.querySelector('main.view')?.scrollTo?.(0, 0);
  window.scrollTo?.(0, 0);
}
const ctx: Ctx = {
  st,
  go: (route, patch = {}) => go(route as Route, patch as Partial<typeof st>),
  render: () => render(),
  rows: () => rows,
};

function routeFromHash(): Route | undefined {
  const r = location.hash.replace(/^#\/?/, '') as Route;
  return ROUTES.includes(r) ? r : undefined;
}
window.addEventListener('hashchange', () => {
  const r = routeFromHash();
  if (r && r !== st.route) go(r);
});
document.addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target as HTMLElement)?.tagName ?? '');
  if ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !typing)) {
    e.preventDefault();
    openPalette(ctx, PAGES);
    return;
  }
  // Clickable table rows behave like buttons from the keyboard.
  const t = e.target as HTMLElement | null;
  if ((e.key === 'Enter' || e.key === ' ') && t?.matches?.('tr.click')) {
    e.preventDefault();
    t.click();
    return;
  }
  if (e.key === 'Escape' && !document.querySelector('dialog[open]')) {
    if (st.sel) {
      st.sel = '';
      render();
    } else if (st.route === 'blast' && st.chain) go('blast', { chain: '' });
  }
});

// ---------------------------------------------------------------- theme

function theme(): 'light' | 'dark' {
  return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
}
function setTheme(t: 'light' | 'dark') {
  document.documentElement.dataset.theme = t;
  try {
    localStorage.setItem('pinhole-theme', t);
  } catch {
    /* storage may be unavailable */
  }
}
// A choice made with the button wins; otherwise follow the system setting.
let savedTheme: string | null = null;
try {
  savedTheme = localStorage.getItem('pinhole-theme');
} catch {
  /* storage blocked: follow the system */
}
if (savedTheme === 'dark' || (savedTheme !== 'light' && window.matchMedia?.('(prefers-color-scheme: dark)').matches)) document.documentElement.dataset.theme = 'dark';

// ---------------------------------------------------------------- filters

function hay(r: Row): string {
  const f = r.f;
  return [f.resourceName, f.resourceId, f.vpcId, D.service(f), D.serviceName(f), r.snap.account, r.snap.region, f.sources.join(' '), f.publicIps.join(' '), ...f.trace.flatMap((x) => [x.resourceId, ...(x.ruleIds ?? [])]), ...(f.targets ?? []).map((t) => t.targetId)]
    .join(' ')
    .toLowerCase();
}
function filtered(): Row[] {
  const q = st.q.trim().toLowerCase();
  return rows.filter(
    (r) =>
      st.sevOn.has(r.f.severity) &&
      (!st.cat || (st.cat === 'world' ? D.isWorld(r.f) : D.category(r.f) === st.cat)) &&
      (!st.scope || scopeOf(r) === st.scope) &&
      (!q || hay(r).includes(q)),
  );
}
const selectedRow = () => rows.find((r) => r.id === st.sel);
// A sticky filter bar whose height varies (it wraps on narrow screens): table headers stick
// directly beneath it, at an offset kept up to date here.
function stickyBar(bar: HTMLElement): HTMLElement {
  const set = () => bar.parentElement?.style.setProperty('--sticky', `${bar.offsetHeight}px`);
  if (typeof ResizeObserver !== 'undefined') new ResizeObserver(set).observe(bar);
  (typeof requestAnimationFrame === 'function' ? requestAnimationFrame : (f: () => void) => setTimeout(f, 0))(set);
  return bar;
}
const scrollTop = () => document.querySelector('main.view')?.scrollTo?.(0, 0);

// ---------------------------------------------------------------- shared pieces

function whyChips(f: D.ExposureFinding): HTMLElement {
  const items = [
    { t: D.isWorld(f) ? 'Open to any address' : `Open to ${f.sources.join(', ')}`, hot: D.isWorld(f) },
    ...D.riskList(f, 3).map((x) => ({ t: x, hot: f.severity === 'critical' && !x.startsWith('and ') })),
    ...(f.returnPath === 'partial' ? [{ t: 'Responses partly blocked', hot: false }] : []),
  ];
  return h('div', { class: 'chips' }, ...items.map((w) => h('span', { class: `chip${w.hot ? ' hot' : ''}` }, w.t)));
}

function detail(r: Row, back: { label: string; act: () => void }, extra: Child[] = [], nav?: { prev?: () => void; next?: () => void; pos: string }): HTMLElement {
  const f = r.f;
  const stepIcon = (d: string) => (d === 'pass' ? iconSvg('check', 10) : d === 'block' ? iconSvg('x', 10) : null);
  const blocked = (f.targets ?? []).filter((t) => t.verdict !== 'reachable');
  const age = D.collected(r.snap);
  const blast = D.blastOf(r.snap);
  const fp = blast.footprints.find((x) => x.entry.eniId === f.resourceId);
  const chains = blast.chains.filter((c) => c.entries.some((e) => e.eniId === f.resourceId));
  const sec = (title: string, ...body: Child[]) => h('section', { class: 'box dbox' }, h('header', {}, h('h2', {}, title)), h('div', { class: 'pad' }, ...body));
  // On one column the boxes are reordered so the verdict and the fix come first.
  const o = <T extends HTMLElement | null>(n: number, el: T): T => { if (el) el.style.order = String(n); return el; };
  return h(
    'div',
    { class: 'page detail-page', id: 'detail', 'aria-label': 'Exposure detail' },
    h(
      'nav',
      { class: 'crumbs', 'aria-label': 'Exposure navigation' },
      on(h('button', { type: 'button', class: 'back' }, iconSvg('chevl', 14), back.label), 'click', back.act),
      nav ? h('div', { class: 'stepnav' }, h('span', { class: 'faint' }, nav.pos), btn('Previous', 'sm', () => nav.prev?.(), nav.prev ? {} : { disabled: '' }), btn('Next', 'sm', () => nav.next?.(), nav.next ? {} : { disabled: '' })) : null,
    ),
    h(
      'header',
      { class: 'dh' },
      h(
        'div',
        { class: 'dh-main' },
        h('div', { class: 'dh-k' }, sevPill(f.severity), h('span', {}, D.kind(f)), h('span', { class: 'mono faint' }, f.resourceId)),
        h('h1', {}, pathTitle(r)),
        h('p', { class: 'lede' }, D.sentence(f)),
        h('p', { class: `meta${age.days !== undefined && age.days > D.STALE_DAYS ? ' stale' : ''}` }, `${f.vpcId}, account ${r.snap.account}, ${r.snap.region}. ${age.text}.`),
      ),
      extra.length ? h('div', { class: 'acts' }, ...extra) : null,
    ),
    h(
      'div',
      { class: 'dtl-grid' },
      h(
        'div',
        { class: 'dcol' },
        o(3, sec(
          'How traffic gets in',
          h(
            'ol',
            { class: 'ap' },
            h('li', { class: 'pass' }, h('span', { class: 'dot' }, iconSvg('check', 10)), h('div', { class: 'k' }, 'Internet'), h('div', { class: 'v' }, h('code', {}, f.sources.join(', ')))),
            ...D.pathHops(f).map((x) => h('li', { class: x.decision }, h('span', { class: 'dot' }, stepIcon(x.decision)), h('div', { class: 'k' }, D.STAGE[x.stage] ?? x.stage), h('div', { class: 'v' }, h('code', {}, D.hopId(x)), ' ', D.hopDetail(x)))),
            h('li', { class: 'end' }, h('span', { class: 'dot' }), h('div', { class: 'k' }, f.kind === 'load-balancer' ? 'Listener' : D.shortName(f)), h('div', { class: 'v' }, D.service(f), D.serviceName(f) ? `, ${D.serviceName(f)}` : '')),
          ),
        )),
        f.targets?.length
          ? o(4, sec(
              `Behind this listener: ${blocked.length ? `${f.targets.length - blocked.length} of ${f.targets.length}` : 'all'} targets reachable`,
              h(
                'div',
                { class: 'targets' },
                ...f.targets.map((t) =>
                  h(
                    'div',
                    { class: 'tg' },
                    h('div', {}, h('div', { class: 'mono' }, `${t.targetId}:${t.port}`), t.blockedAt ? h('div', { class: 'why' }, `Stopped at ${t.blockedAt.resourceId}: ${t.blockedAt.detail}`) : h('div', { class: 'why' }, `${t.nodesReachable} of ${t.nodesTotal} load balancer nodes${t.clientIpPreserved ? ', client IP preserved' : ''}`)),
                    sevPill(t.verdict === 'reachable' ? 'low' : t.verdict === 'blocked' ? 'critical' : 'medium', t.verdict),
                  ),
                ),
              ),
            ))
          : null,
        o(7, sec(
          'Properties',
          h(
            'dl',
            { class: 'kv' },
            h('dt', {}, 'Resource'), h('dd', {}, f.resourceName),
            h('dt', {}, 'Resource ID'), h('dd', { class: 'mono' }, f.resourceId),
            h('dt', {}, 'Public IPs'), h('dd', { class: 'mono' }, f.publicIps.join(', ') || 'none'),
            h('dt', {}, 'Source range'), h('dd', { class: 'mono' }, f.sourceRanges.slice(0, 6).join(', ') + (f.sourceRanges.length > 6 ? ` and ${f.sourceRanges.length - 6} more` : '')),
            h('dt', {}, 'Responses'), h('dd', {}, f.returnPath === 'all' ? 'Allowed for all client port ranges' : f.returnPath === 'partial' ? 'Allowed for some client port ranges' : 'Blocked'),
            ...(f.inspectedBy?.length ? [h('dt', {}, 'Inspected by'), h('dd', {}, f.inspectedBy.join(', '))] : []),
            h('dt', {}, 'Snapshot'), h('dd', {}, r.snap.name),
          ),
        )),
      ),
      h(
        'div',
        { class: 'dcol' },
        ...(f.caveats?.length ? [o(1, h('div', { class: 'box dbox caveat-box', role: 'note' }, h('div', { class: 'pad' }, h('strong', {}, 'Not decided exactly'), ...f.caveats.map((c) => h('p', { class: 'dim', style: 'margin:0.25rem 0 0' }, c)))))] : []),
        o(1, sec('Why it matters', whyChips(f), fp && fp.reachable.length ? h('p', { class: 'dim', style: 'margin:0.75rem 0 0' }, `If this server is compromised, it can reach ${D.plural(fp.reachable.length, 'other resource')} inside the network${fp.dataStores ? `, ${D.plural(fp.dataStores, 'data store')} among them` : ''}.`) : null)),
        o(2, h('div', { class: 'box dbox' }, fixesSection(ctx, r))),
        chains.length
          ? o(5, sec(
              'Attack chains from here',
              h(
                'ul',
                { class: 'links' },
                ...chains.slice(0, 6).map((c) => h('li', {}, on(h('button', { type: 'button', class: 'linkrow' }, sevPill(c.severity), h('span', {}, c.steps.map((x) => x.name.replace(/ \(.*\)$/, '')).join(' → '))), 'click', () => go('blast', { blastKey: r.snap.key, chain: `${r.snap.key}#${c.id}` })))),
              ),
            ))
          : null,
        o(6, h('section', { class: 'box dbox fix' }, h('header', {}, h('h2', {}, 'Guidance')), h('div', { class: 'pad' }, ...D.remediation(f, r.snap.model).map((x) => h('p', {}, x))))),
        o(8, sec(
          'How sure is this',
          h('p', { class: 'dim', style: 'margin-top:0' }, `Pinhole evaluated every security group rule, network ACL entry and route on this path, in both directions, from the snapshot. ${age.text}${age.days !== undefined && age.days > D.STALE_DAYS ? '; collect a fresh one before acting on it' : ''}.`),
          h('p', { class: 'dim' }, 'It does not see host firewalls, the application itself, AWS WAF or Shield, or IAM. A path here means the network lets the connection through, not that the service will accept it.'),
          r.snap.warnings.length ? h('p', { class: 'warn', style: 'margin-bottom:0' }, `This snapshot has ${D.plural(r.snap.warnings.length, 'coverage note')}: parts of the network that are not analysed. `, linkBtn('See coverage', () => go('coverage'))) : null,
        )),
      ),
    ),
  );
}

// ---------------------------------------------------------------- dashboard


function chain(r: Row): HTMLElement {
  const sep = () => h('span', { class: 'sep' }, iconSvg('chev', 12));
  const entry = D.entryPoint(r.f).replace(/ \(.*\)$/, '');
  const via = r.f.inspectedBy ?? [];
  const parts = r.f.kind === 'load-balancer' ? ['Internet', entry] : ['Internet', entry, ...via, D.shortName(r.f)];
  const el = h('span', { class: 'chain' });
  parts.forEach((x, i) => {
    if (i) el.append(sep());
    el.append(h('span', { class: `hop${i === parts.length - 1 ? ' end' : ''}` }, x));
  });
  return el;
}

function dashboard(): HTMLElement {
  const accounts = new Set(st.snaps.map((x) => x.account));
  const regions = new Set(st.snaps.map((x) => x.region));
  const res = D.resources(rows);
  const chainRows = D.chainsOf(st.snaps);
  const page = h('div', { class: 'page' });
  page.append(
    h(
      'div',
      { class: 'ph' },
      h('div', {}, h('h1', {}, 'Dashboard'), h('p', {}, `Internet exposure across ${D.plural(accounts.size, 'account')} and ${D.plural(regions.size, 'Region')}.`, ...(() => {
        const ages = st.snaps.map((x) => ({ x, c: D.collected(x) }));
        const known = ages.filter((a) => a.c.days !== undefined).sort((a, b) => b.c.days! - a.c.days!);
        if (!known.length) return [];
        const old = known[0]!;
        const stale = old.c.days! > D.STALE_DAYS;
        return [' ', h('span', { class: stale ? 'stale-t' : 'faint' }, `${ages.length > 1 ? 'Oldest snapshot: ' : ''}${old.c.text.replace(/^Collected/, ages.length > 1 ? 'collected' : 'Collected')}.${stale ? ' The network may have changed since; collect fresh snapshots before acting.' : ''}`)];
      })())),
      st.snaps.length ? h('div', { class: 'acts' }, btn([iconSvg('file', 14), 'Report'], '', () => go('report')), btn([iconSvg('graph', 14), 'Attack graph'], '', () => go('graph')), btn('All exposures', '', () => go('issues', { sevOn: ALL(), cat: '', scope: '', q: '', sel: '' }))) : null,
    ),
  );
  if (!st.snaps.length) {
    page.append(h('div', { class: 'box' }, empty('No snapshots loaded', 'Collect a snapshot with the CloudShell script, then load it here.', btn('Connect an account', 'primary', () => go('connect')), btn('Load snapshots', '', pick))));
    return page;
  }
  const toIssues = (patch: Partial<typeof st>) => () => go('issues', { sevOn: ALL(), cat: '', scope: '', q: '', sel: '', ...patch });
  // Two columns: what to act on (plan, exposures, chains, graph) and the breakdowns beside it.
  // Each column stacks on its own, so a long fix plan never leaves holes in the other column.
  const mainCol = h('div', { class: 'dash-main' });
  const sideCol = h('div', { class: 'dash-side' });
  const grid = { append: (...els: HTMLElement[]) => mainCol.append(...els) };

  // Summary: exposures by severity, then the supporting counts.
  const bar = h('div', { class: 'sbar', 'aria-hidden': 'true' });
  const legend = h('div', { class: 'slegend' });
  for (const sv of D.SEVERITY_ORDER) {
    const n = rows.filter((r) => r.f.severity === sv).length;
    if (!n) continue;
    bar.append(h('span', { style: `flex:${n};background:${sevVar(sv)}` }));
    legend.append(on(h('button', { type: 'button', 'data-sev': sv }, h('i', { style: `background:${sevVar(sv)}` }), D.SEV_LABEL[sv], h('b', {}, String(n))), 'click', toIssues({ sevOn: new Set([sv]) })));
  }
  if (!rows.length) bar.append(h('span', { style: 'flex:1;background:var(--line2)' }));
  const world = rows.filter((r) => D.isWorld(r.f)).length;
  const warn = st.snaps.reduce((n, x) => n + x.warnings.length, 0);
  const crit = chainRows.filter((c) => c.c.severity === 'critical').length;
  const stopped = D.withJoined(st.snaps).some((x) => D.blastOf(x).stats.truncated);
  const saving = savingsTotal(st.snaps);
  const targets = new Set(chainRows.map((c) => `${c.snap.key}|${c.c.targetId}`)).size;
  // A link inside a sentence: the count is the thing you click.
  const ln = (text: string, act: () => void, id?: string) => on(h('button', { type: 'button', class: 'inl', ...(id ? { id } : {}) }, text), 'click', act);
  const lead = rows.length
    ? h('p', { class: 'sum-lead' }, h('button', { type: 'button', class: 'inl' }, h('span', { id: 'total' }, String(rows.length)), rows.length === 1 ? ' service' : ' services'), ` on `, ln(D.plural(res.length, 'resource'), () => go('resources')), ` ${rows.length === 1 ? 'is' : 'are'} reachable from the internet`, world ? h('span', {}, ', ', ln(`${world} of them`, toIssues({ cat: 'world' })), ' from any address') : null, '.')
    : h('p', { class: 'sum-lead' }, 'Nothing is reachable from the internet', h('span', { id: 'total', hidden: true }, '0'), '.');
  const first = lead.querySelector('button.inl');
  if (first) on(first as HTMLElement, 'click', toIssues({ sevOn: ALL() }));
  const more = h(
    'p',
    { class: 'sum-more' },
    chainRows.length ? h('span', {}, 'If one of those servers is compromised, ', ln(`${D.plural(chainRows.length, 'attack chain')}`, () => go('blast')), ` lead to ${D.plural(targets, 'internal resource')}${crit ? ` (${crit} critical)` : ''}. `) : stopped ? '' : 'No attack chain leads further in from them. ',
    stopped ? h('span', {}, 'The attack chain analysis stopped early on a large network; ', ln('finish it on Blast radius', () => go('blast')), '. ') : null,
    warn ? h('span', {}, ln(D.plural(warn, 'coverage note'), () => go('coverage')), ' mark configuration that could not be fully analysed.') : 'Everything loaded was analysed.',
    saving.count ? h('span', {}, ' ', ln(`${D.plural(saving.count, 'unused network resource')} ${saving.count === 1 ? 'costs' : 'cost'} about ${usd(saving.monthly)} a month`, () => go('savings')), '.') : null,
  );
  page.append(h('section', { class: 'box summary', id: 'summary' }, lead, more, rows.length ? h('div', { class: 'sum-sev' }, bar, legend) : null));

  // What to do: the smallest verified set of changes.
  // On a large network the plan takes a while: show the page first, then the plan.
  const large = st.snaps.reduce((n, x) => n + x.model.enis.size, 0) > 300;
  if (!large || D.withJoined(st.snaps).every(D.planReady)) grid.append(planBox(ctx));
  else {
    const wait = h('section', { class: 'box', id: 'plan' }, boxHead('Fix plan', 'Fewest changes that close every critical and high risk, each proved by re-analysis'), h('div', { class: 'pad' }, h('p', { class: 'dim', style: 'margin:0' }, 'Working out the fix plan. On a large network this takes a few seconds.')));
    grid.append(wait);
    setTimeout(() => {
      if (wait.isConnected) wait.replaceWith(planBox(ctx));
    }, 30);
  }

  const cats: { key: CatFilter; label: string }[] = [
    { key: 'admin', label: 'Remote administration' },
    { key: 'data', label: 'Databases and caches' },
    { key: 'control', label: 'Cluster control planes' },
    { key: 'wide', label: 'Wide port ranges' },
    { key: 'other', label: 'Other services' },
    { key: 'web', label: 'Web' },
  ];
  const catRows = cats.map((c) => ({ ...c, list: rows.filter((r) => D.category(r.f) === c.key) }));
  const max = Math.max(1, ...catRows.map((c) => c.list.length));
  sideCol.append(
    h(
      'section',
      { class: 'box', id: 'categories' },
      boxHead('By kind of service', 'Exposures per category'),
      h(
        'ul',
        { class: 'bars' },
        ...catRows.map((c) =>
          h(
            'li',
            {},
            on(
              h('button', { type: 'button', 'data-cat': c.key }, h('span', { class: 'l' }, c.label), h('span', { class: 'c' }, String(c.list.length)), h('span', { class: 'track' }, h('span', { class: 'fill', style: `width:${(c.list.length / max) * 100}%;background:${c.list.length ? sevVar(c.list[0]!.f.severity) : 'transparent'}` }))),
              'click',
              toIssues({ cat: c.key }),
            ),
          ),
        ),
      ),
    ),
  );

  // Top paths and where they are.
  grid.append(
    h(
      'section',
      { class: 'box', id: 'top-paths' },
      boxHead('Top exposures', 'What the internet can reach, most severe first', linkBtn(`View all ${rows.length}`, toIssues({}))),
      h(
        'table',
        { class: 't' },
        h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Path'), h('th', {}, 'Service'), h('th', { class: 'hide-sm' }, 'Open to'), h('th', { class: 'last hide-sm' }, 'Account and Region'))),
        h(
          'tbody',
          {},
          ...rows.slice(0, 8).map((r) =>
            on(
              h(
                'tr',
                { class: 'click', tabindex: 0 },
                h('td', { class: 'first' }, sevPill(r.f.severity)),
                h('td', { style: 'max-width:0;width:40%' }, chain(r)),
                h('td', {}, h('span', { class: 'mono' }, D.service(r.f)), r.f.family === 'ipv6' ? h('span', { class: 'tag v6' }, 'IPv6') : null, D.serviceName(r.f) ? h('span', { class: 'faint' }, `  ${D.serviceName(r.f)}`) : null),
                h('td', { class: 'mono hide-sm' }, D.openTo(r.f)),
                h('td', { class: 'last mono faint hide-sm nowrap' }, `${r.snap.account} ${r.snap.region}`),
              ),
              'click',
              toIssues({ sel: r.id }),
            ),
          ),
        ),
      ),
    ),
  );

  const accs = [...accounts].sort();
  const regs = [...regions].sort();
  // Region columns keep a readable minimum width; with many Regions the grid scrolls sideways instead of overlapping.
  const matrix = h('div', { class: 'matrix', style: `grid-template-columns:minmax(6.5rem,1.2fr) repeat(${regs.length},minmax(2.75rem,1fr))` }, h('span'), ...regs.map((x) => h('span', { class: 'hd', title: x }, shortRegion(x))));
  for (const a of accs) {
    const inAcc = rows.filter((r) => r.snap.account === a);
    matrix.append(h('span', { class: 'lab' }, h('b', {}, a), D.plural(inAcc.length, 'exposure')));
    for (const g of regs) {
      const here = inAcc.filter((r) => r.snap.region === g);
      const has = st.snaps.some((x) => x.account === a && x.region === g);
      if (!here.length) {
        matrix.append(h('span', { class: 'c zero', title: has ? 'Collected, nothing exposed' : 'Not collected' }, has ? '0' : ''));
        continue;
      }
      const worst = here[0]!.f.severity;
      matrix.append(on(h('button', { type: 'button', class: 'c', style: `background:${softVar(worst)};color:${worst === 'medium' ? 'var(--medium-ink)' : sevVar(worst)}`, 'aria-label': `${here.length} paths in ${a} ${g}` }, String(here.length)), 'click', toIssues({ scope: `${a} / ${g}` })));
    }
  }
  sideCol.append(h('section', { class: 'box', id: 'matrix' }, boxHead('Accounts and Regions', 'Exposures, coloured by the worst one'), matrix));

  // Lateral movement: the worst chains, and the rules that cut the most of them.
  if (chainRows.length) {
    const top = chainRows.slice(0, 6);
    grid.append(
      h(
        'section',
        { class: 'box', id: 'chains' },
        boxHead('Attack chains', 'Internal resources reachable after one server is compromised', linkBtn(`View all ${chainRows.length}`, () => go('blast', { chain: '' }))),
        h(
          'table',
          { class: 't' },
          h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Chain'), h('th', {}, 'Ends at'), h('th', { class: 'last hide-sm' }, 'Account and Region'))),
          h(
            'tbody',
            {},
            ...top.map((c) => {
              const last = c.c.steps.at(-1)!;
              const el = h('span', { class: 'chain' }, h('span', { class: 'hop' }, 'Internet'));
              c.c.steps.forEach((x, i) => el.append(h('span', { class: 'sep' }, iconSvg('chev', 12)), h('span', { class: `hop${i === c.c.steps.length - 1 ? ' end' : ''}` }, x.name.replace(/ \(.*\)$/, ''))));
              return on(
                h('tr', { class: 'click', tabindex: 0 }, h('td', { class: 'first' }, sevPill(c.c.severity)), h('td', { style: 'max-width:0;width:46%' }, el), h('td', {}, h('span', { class: 'mono' }, last.service ?? ''), last.serviceName ? h('span', { class: 'faint' }, `  ${last.serviceName}`) : null), h('td', { class: 'last mono faint hide-sm' }, `${c.snap.account} ${c.snap.region}`)),
                'click',
                () => go('blast', { blastKey: c.snap.key, chain: c.id }),
              );
            }),
          ),
        ),
      ),
    );
  }

  // Which services are exposed.
  const bySvc = new Map<string, Row[]>();
  for (const r of rows) bySvc.set(D.service(r.f), [...(bySvc.get(D.service(r.f)) ?? []), r]);
  const svcs = [...bySvc.entries()].sort((a, b) => D.sevRank(a[1][0]!.f.severity) - D.sevRank(b[1][0]!.f.severity) || b[1].length - a[1].length).slice(0, 8);
  sideCol.append(
    h(
      'section',
      { class: 'box', id: 'services' },
      boxHead('Exposed services'),
      h(
        'table',
        { class: 't' },
        h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Service'), h('th', {}, 'Port'), h('th', { class: 'r last' }, 'Resources'))),
        h(
          'tbody',
          {},
          ...svcs.map(([k, list]) =>
            on(
              h('tr', { class: 'click', tabindex: 0 }, h('td', { class: 'first' }, sevPill(list[0]!.f.severity, D.serviceName(list[0]!.f) || k)), h('td', { class: 'mono' }, k), h('td', { class: 'r last' }, String(new Set(list.map((x) => x.f.resourceId)).size))),
              'click',
              toIssues({ q: k }),
            ),
          ),
        ),
      ),
    ),
  );
  // Attack surface preview and categories.
  const top = rows.filter((r) => r.f.severity === 'critical' || r.f.severity === 'high');
  const surface = h('div', { class: 'surface', role: 'link', tabindex: 0, 'aria-label': 'Open the attack graph' });
  on(surface, 'click', () => go('graph'));
  on(surface, 'keydown', (e) => e.key === 'Enter' && go('graph'));
  if (rows.length) renderGraph(surface, (top.length ? top : rows).slice(0, 10), { compact: true, showTargets: false });
  else surface.append(h('p', { class: 'dim' }, 'Nothing is reachable from the internet.'));
  grid.append(h('section', { class: 'box', id: 'surface' }, boxHead('Attack surface', top.length ? `${D.plural(Math.min(top.length, 10), 'critical or high exposure')}` : 'All exposures', linkBtn('Open attack graph', () => go('graph'))), surface));
  page.append(h('div', { class: 'dash' }, mainCol, sideCol));
  return page;
}

// ---------------------------------------------------------------- attack graph

function graphPage(): HTMLElement {
  const vis = rows.filter((r) => st.sevOn.has(r.f.severity));
  const canvas = h('div', { class: 'canvas', id: 'canvas' });
  const host = h('div', { style: 'position:absolute;inset:0' });
  const sel = selectedRow();
  const tools = h('div', { class: 'gtools' });
  for (const sv of D.SEVERITY_ORDER) {
    const c = rows.filter((r) => r.f.severity === sv).length;
    if (!c) continue;
    tools.append(on(h('button', { type: 'button', class: 'tog', 'aria-pressed': String(st.sevOn.has(sv)) }, h('i', { style: `background:${sevVar(sv)}` }), `${D.SEV_LABEL[sv]} ${c}`), 'click', () => { if (st.sevOn.has(sv)) st.sevOn.delete(sv); else st.sevOn.add(sv); render(); }));
  }
  tools.append(on(h('button', { type: 'button', class: 'tog', 'aria-pressed': String(st.showTargets) }, iconSvg('target', 14), 'Load balancer targets'), 'click', () => { st.showTargets = !st.showTargets; render(); }));
  const find = h('input', { type: 'search', placeholder: 'Highlight a resource or IP', value: st.gq, 'aria-label': 'Highlight in graph', id: 'gfind' }) as HTMLInputElement;
  tools.append(h('label', { class: 'gfind' }, iconSvg('search', 14), find));
  canvas.append(
    host,
    tools,
    h('div', { class: 'glegend hide-sm' }, h('span', {}, h('i', { style: 'background:var(--critical)' }), 'Critical'), h('span', {}, h('i', { style: 'background:var(--high)' }), 'High'), h('span', {}, h('i', { style: 'background:var(--low)' }), 'Target reachable'), h('span', {}, h('i', { style: 'background:repeating-linear-gradient(90deg,var(--critical) 0 0.25rem,transparent 0.25rem 0.5rem)' }), 'Target blocked')),
  );
  const draw = () =>
    renderGraph(host, vis, {
      showTargets: st.showTargets,
      selected: sel,
      focus: st.gq,
      onSelect: (r) => {
        st.sel = r.id;
        render();
      },
    });
  find.addEventListener('input', () => {
    st.gq = find.value;
    draw();
  });
  const dock: HTMLElement[] = [];
  if (sel) {
    const hops = [h('span', { class: 'hop' }, 'Internet'), ...D.pathHops(sel.f).filter((x) => x.decision === 'pass').map((x) => h('span', { class: 'hop' }, D.SHORT_STAGE[x.stage] ?? D.STAGE[x.stage] ?? x.stage, ' ', h('code', {}, D.hopId(x)))), h('span', { class: 'hop end' }, D.shortName(sel.f), ' ', h('code', {}, D.service(sel.f)))];
    const chainEl = h('div', { class: 'chain wrap' });
    hops.forEach((x, i) => { if (i) chainEl.append(h('span', { class: 'sep' }, iconSvg('chev', 12))); chainEl.append(x); });
    dock.push(
      h(
        'section',
        { class: 'gsel', id: 'gsel', 'aria-label': 'Selected exposure' },
        h('div', { class: 'gsel-h' }, sevPill(sel.f.severity), h('strong', {}, pathTitle(sel)), h('span', { class: 'faint' }, scopeOf(sel))),
        h('p', { class: 'gsel-s' }, D.sentence(sel.f)),
        chainEl,
        h('div', { class: 'gsel-a' }, btn('Open details and fixes', 'sm primary', () => go('issues', { sel: sel.id })), btn('Clear selection', 'sm', () => { st.sel = ''; render(); })),
      ),
    );
  } else if (vis.length) {
    canvas.append(h('p', { class: 'ghint' }, 'Select a resource in the graph to trace its path from the internet.'));
  } else {
    canvas.append(h('div', { class: 'ghint' }, empty('Nothing to show', 'Turn on a severity above to see its exposures.')));
  }
  const wrap = h('div', { class: 'graph-page' }, h('h1', { class: 'sr-only' }, 'Attack graph'), canvas, ...dock);
  draw();
  // Fit again once the canvas has its real size.
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(draw);
  return wrap;
}

// ---------------------------------------------------------------- issues

function issuesPage(): HTMLElement {
  const list = filtered();
  const sel = selectedRow();
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Severity' });
  for (const sv of D.SEVERITY_ORDER) {
    const c = rows.filter((r) => r.f.severity === sv).length;
    if (!c) continue;
    seg.append(on(h('button', { type: 'button', 'data-sev': sv, 'aria-pressed': String(st.sevOn.has(sv)) }, h('i', { style: `background:${sevVar(sv)}` }), `${D.SEV_LABEL[sv]} ${c}`), 'click', () => { if (st.sevOn.has(sv)) st.sevOn.delete(sv); else st.sevOn.add(sv); render(); }));
  }
  const search = h('input', { type: 'search', id: 'search', placeholder: 'Filter by name, ID, IP, port or rule', value: st.q, 'aria-label': 'Filter exposures' }) as HTMLInputElement;
  const catSel = h('select', { 'aria-label': 'Category', id: 'cat' }, h('option', { value: '' }, 'All categories'), h('option', { value: 'world' }, 'Open to any address'), ...(Object.keys(D.CATEGORY_LABEL) as Category[]).map((c) => h('option', { value: c }, D.CATEGORY_LABEL[c]))) as HTMLSelectElement;
  catSel.value = st.cat;
  catSel.addEventListener('change', () => { st.cat = catSel.value as CatFilter; render(); });
  const scopes = [...new Set(rows.map(scopeOf))].sort();
  const scopeSel = h('select', { 'aria-label': 'Account and Region', id: 'scope' }, h('option', { value: '' }, 'All accounts and Regions'), ...scopes.map((x) => h('option', { value: x }, x))) as HTMLSelectElement;
  scopeSel.value = st.scope;
  scopeSel.addEventListener('change', () => { st.scope = scopeSel.value; render(); });

  const tbody = h('tbody');
  const fill = () => {
    const now = filtered();
    tbody.replaceChildren(
      ...now.map((r) => {
        const name = D.serviceName(r.f);
        const open = D.openTo(r.f);
        return on(
          h(
            'tr',
            { class: 'click', tabindex: 0, 'aria-selected': String(st.sel === r.id), 'aria-label': `${D.SEV_LABEL[r.f.severity]}: ${D.shortName(r.f)} ${D.service(r.f)}` },
            h('td', { class: 'first c-sev' }, sevPill(r.f.severity)),
            h('td', { class: 'c-res' }, h('span', { class: 'xt-name' }, D.shortName(r.f)), h('span', { class: 'xt-sub' }, D.kind(r.f))),
            h('td', { class: 'c-svc' }, h('span', { class: 'xt-port mono' }, D.service(r.f)), r.f.family === 'ipv6' ? h('span', { class: 'tag v6' }, 'IPv6') : null, name ? h('span', { class: 'xt-sub' }, name) : null),
            h('td', { class: 'c-open mono', title: open }, open),
            h('td', { class: 'c-where mono faint' }, `${r.snap.account} ${r.snap.region}`),
            h('td', { class: 'last c-go', 'aria-hidden': 'true' }, iconSvg('chev', 14)),
          ),
          'click',
          () => { st.sel = r.id; render(); scrollTop(); },
        );
      }),
    );
    count.textContent = `${now.length} of ${D.plural(rows.length, 'exposure')}`;
  };
  tbody.addEventListener('keydown', (e) => {
    const tr = (e.target as HTMLElement).closest('tr');
    if (!tr) return;
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); tr.click(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); (tr.nextElementSibling as HTMLElement | null)?.focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); (tr.previousElementSibling as HTMLElement | null)?.focus(); }
  });
  const count = h('span', { class: 'count' });
  search.addEventListener('input', () => { st.q = search.value; fill(); });

  const exportCsv = () => D.saveFile('pinhole-exposures.csv', D.csv(filtered()), 'text/csv');
  const exportJson = () => D.saveFile('pinhole-exposures.json', `${JSON.stringify(filtered().map((r) => ({ account: r.snap.account, region: r.snap.region, ...r.f })), null, 2)}\n`, 'application/json');
  const table = h(
    'table',
    { class: 't xt' },
    h('colgroup', {}, h('col', { class: 'w-sev' }), h('col', { class: 'w-res' }), h('col', { class: 'w-svc' }), h('col', { class: 'w-open' }), h('col', { class: 'w-where' }), h('col', { class: 'w-go' })),
    h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Resource'), h('th', {}, 'Service'), h('th', {}, 'Open to'), h('th', {}, 'Account and Region'), h('th', { class: 'last' }, h('span', { class: 'sr' }, 'Open')))),
    tbody,
  );
  fill();
  const left = h(
    'div',
    { class: 'list' },
    h('div', { class: 'list-h' }, h('div', { class: 'ph', style: 'margin-bottom:0' }, h('div', {}, h('h1', {}, 'Internet exposures'), h('p', {}, 'Every service the internet can open a connection to, most severe first. Select one for the exact path and a verified fix.')), h('div', { class: 'acts' }, btn([iconSvg('download', 14), 'CSV'], 'sm', exportCsv), btn([iconSvg('download', 14), 'JSON'], 'sm', exportJson)))),
    stickyBar(h('div', { class: 'filters' }, seg, h('label', { class: 'lsearch' }, iconSvg('search', 14), search), catSel, scopes.length > 1 ? scopeSel : null, count)),
    list.length || !rows.length ? table : null,
    !rows.length ? empty('No internet exposures', 'Nothing in the loaded snapshots is reachable from the internet.') : !list.length ? empty('No exposures match these filters', 'Clear the filters to see everything.', btn('Clear filters', '', () => go('issues', { sevOn: new Set(D.SEVERITY_ORDER), cat: '', scope: '', q: '' }))) : null,
  );
  if (sel) {
    const i = list.findIndex((r) => r.id === sel.id);
    const pick = (r: Row | undefined) => (r ? () => { st.sel = r.id; render(); scrollTop(); } : undefined);
    return detail(
      sel,
      { label: 'All exposures', act: () => { st.sel = ''; render(); } },
      [btn([iconSvg('graph', 14), 'Show in graph'], 'sm', () => go('graph', { sevOn: new Set(D.SEVERITY_ORDER), sel: sel.id })), btn([iconSvg('copy', 14), 'Copy as JSON'], 'sm', async () => { await D.copyText(JSON.stringify({ account: sel.snap.account, region: sel.snap.region, ...sel.f }, null, 2)); toast('Copied'); })],
      i >= 0 ? { pos: `${i + 1} of ${list.length}`, prev: pick(list[i - 1]), next: pick(list[i + 1]) } : undefined,
    );
  }
  return h('div', { class: 'list-page' }, left);
}

// ---------------------------------------------------------------- resources

function resourcesPage(): HTMLElement {
  const res = D.resources(rows);
  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Resources'), h('p', {}, 'Servers, databases and load balancers that the internet can reach, with every open port.'))),
    h(
      'section',
      { class: 'box', style: 'overflow:auto' },
      res.length
        ? h(
            'table',
            { class: 't' },
            h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Resource'), h('th', {}, 'Open ports'), h('th', { class: 'hide-sm' }, 'Public IPs'), h('th', { class: 'hide-sm' }, 'VPC'), h('th', { class: 'hide-sm' }, 'Account and Region'), h('th', { class: 'last' }, 'Worst'))),
            h(
              'tbody',
              {},
              ...res.map((x) =>
                on(
                  h(
                    'tr',
                    { class: 'click', tabindex: 0 },
                    h('td', { class: 'first' }, h('div', { style: 'display:flex;gap:0.625rem;align-items:center' }, h('span', { class: 'faint', style: 'display:grid' }, iconSvg(iconFor(x.rows[0]!), 16)), h('div', { style: 'min-width:0' }, h('div', { style: 'font-weight:600' }, x.name.replace(/ \(.*\)$/, '')), h('div', { class: 'faint mono', style: 'font-size:0.7188rem;overflow-wrap:anywhere' }, x.kind.includes('Load') ? x.kind : x.id)))),
                    h('td', {}, h('div', { class: 'chips' }, ...x.rows.slice(0, 6).map((r) => h('span', { class: `chip${r.f.severity === 'critical' ? ' hot' : ''}` }, D.service(r.f))), x.rows.length > 6 ? h('span', { class: 'chip' }, `+${x.rows.length - 6}`) : null)),
                    h('td', { class: 'mono hide-sm' }, x.publicIps.join(', ') || 'none'),
                    h('td', { class: 'mono hide-sm' }, x.vpc),
                    h('td', { class: 'hide-sm' }, `${x.snap.account} / ${x.snap.region}`),
                    h('td', { class: 'last' }, sevPill(x.worst)),
                  ),
                  'click',
                  () => go('issues', { q: x.id, sel: x.rows[0]!.id, cat: '', scope: '', sevOn: new Set(D.SEVERITY_ORDER) }),
                ),
              ),
            ),
          )
        : empty('No exposed resources', 'Nothing in the loaded snapshots is reachable from the internet.'),
    ),
  );
}

// ---------------------------------------------------------------- coverage

const NOT_MODELLED: [string, string][] = [
  ['Third-party appliances', 'Traffic through a Gateway Load Balancer endpoint is followed, but the appliance\'s rules are not visible: it is assumed to pass, and every path through it says so.'],
  ['Firewall rules that read the traffic', 'Network Firewall rules that match content, host names or application protocols are followed both ways; the path is marked when the answer depends on the traffic.'],
  ['The on-premises side of VPN and Direct Connect', 'Followed up to the AWS gateway. Routers and firewalls on-premises are not visible and are assumed to pass.'],
  ['IPv6 beyond exposure', 'Internet exposure is analysed over IPv6 for TCP and UDP. ICMPv6 and IPv6 movement between servers are not.'],
  ['Instances acting as routers, Global Accelerator, CloudFront, Classic Load Balancers', 'Detected and listed on this page. Paths through them are reported as unknown, never as safe.'],
];

function reportPage(): HTMLElement {
  if (!st.snaps.length) return h('div', { class: 'page' }, h('div', { class: 'box' }, empty('No snapshots loaded', 'Load snapshots to build a report.')));
  const doc = reportDoc(st.snaps, rows);
  const accounts = [...new Set(st.snaps.map((x) => x.account))].sort();
  const day = new Date().toISOString().slice(0, 10);
  const title = `Pinhole report, ${accounts.join(', ')}, ${day}`;
  // Contents rail on wide screens: the report is long, and this is how a reader finds a section.
  const view = () => document.querySelector('main.view') as HTMLElement | null;
  const toc = h('nav', { class: 'r-toc no-print', 'aria-label': 'Report sections' }, h('div', { class: 'r-toc-h' }, 'Contents'));
  for (const sec of [...doc.querySelectorAll('section[id]')] as HTMLElement[]) {
    const label = sec.querySelector('h2')?.textContent ?? '';
    toc.append(on(h('a', { href: `#${sec.id}` }, label), 'click', (e) => {
      e.preventDefault();
      const top = sec.getBoundingClientRect().top - (view()?.getBoundingClientRect().top ?? 0) + (view()?.scrollTop ?? 0) - 16;
      view()?.scrollTo({ top, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
    }));
  }
  return h(
    'div',
    { class: 'page report-page' },
    h(
      'div',
      { class: 'ph no-print' },
      h('div', {}, h('h1', {}, 'Report'), h('p', {}, 'Everything on one page for someone who will not open the console: the summary, the fix plan with commands, every exposure and chain, and what the analysis could not see.')),
      h('div', { class: 'acts' }, btn([iconSvg('file', 14), 'Print or save as PDF'], 'primary', () => window.print()), btn([iconSvg('download', 14), 'Download HTML'], '', () => D.saveFile(`pinhole-report-${day}.html`, reportHtml(doc, title), 'text/html'))),
    ),
    st.demo ? h('p', { class: 'no-print stale-t demo-note' }, 'This is the demo environment. Load your own snapshots for a real report.') : null,
    h('style', {}, REPORT_CSS),
    h('div', { class: 'report-wrap' }, toc, h('div', { class: 'paper' }, doc)),
  );
}

function coveragePage(): HTMLElement {
  const items = st.snaps.flatMap((x) => x.warnings.map((w) => ({ w, x })));
  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Coverage'), h('p', {}, 'What each snapshot contains, and anything found that this version does not analyse.'))),
    h(
      'section',
      { class: 'box', style: 'margin-bottom:1rem;overflow:auto' },
      boxHead('Snapshots'),
      h(
        'table',
        { class: 't' },
        h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Account and Region'), h('th', { class: 'hide-sm' }, 'Collected'), h('th', {}, 'Interfaces'), h('th', {}, 'Load balancers'), h('th', {}, 'Open paths'), h('th', { class: 'last' }, 'Notes'))),
        h(
          'tbody',
          {},
          ...st.snaps.map((x) =>
            h(
              'tr',
              {},
              h('td', { class: 'first' }, h('div', { class: 'mono' }, `${x.account} / ${x.region}`), h('div', { class: 'faint', style: 'font-size:0.75rem' }, x.name)),
              h('td', { class: 'hide-sm mono' }, x.collectedAt ? x.collectedAt.replace('T', ' ').replace(/:\d\d(\.\d+)?Z$/, ' UTC') : 'unknown'),
              h('td', { class: 'mono' }, String(x.model.enis.size), h('span', { class: 'faint' }, ` (${x.stats.interfacesWithPublicIp} with a public IPv4)`)),
              h('td', { class: 'mono' }, String(x.stats.loadBalancersAnalysed)),
              h('td', { class: 'mono' }, String(x.findings.length)),
              h('td', { class: 'last' }, x.warnings.length ? sevPill('medium', String(x.warnings.length)) : sevPill('low', 'none')),
            ),
          ),
        ),
      ),
    ),
    h(
      'div',
      { class: 'grid2' },
      h(
        'section',
        { class: 'box', id: 'notes' },
        boxHead('Notes from the analysis', 'Resources whose exposure could not be fully decided'),
        items.length
          ? h(
              'div',
              {},
              ...items.map(({ w, x }) =>
                h(
                  'div',
                  { class: 'sec' },
                  h('div', { style: 'display:flex;justify-content:space-between;gap:0.625rem;margin-bottom:0.25rem' }, h('span', { class: 'mono', style: 'font-weight:600' }, w.code), h('span', { class: 'faint', style: 'font-size:0.75rem' }, `${x.account} / ${x.region}`)),
                  h('div', {}, w.message),
                  w.resourceIds.length ? h('div', { class: 'chips', style: 'margin-top:0.5rem' }, ...w.resourceIds.slice(0, 8).map((id) => h('span', { class: 'chip mono' }, id))) : null,
                  w.docUrl && /^https:\/\/docs\.aws\.amazon\.com\//.test(w.docUrl) ? h('a', { href: w.docUrl, target: '_blank', rel: 'noopener noreferrer', style: 'display:inline-block;margin-top:0.5rem;font-size:0.7812rem' }, 'AWS documentation') : null,
                ),
              ),
            )
          : h('div', { class: 'pad dim' }, 'No notes. Everything in the loaded snapshots was analysed.'),
      ),
      h(
        'section',
        { class: 'box' },
        boxHead('Not modelled in this version', 'Detected and flagged, never treated as safe'),
        h('ul', { class: 'trust' }, ...NOT_MODELLED.map(([t, d]) => h('li', {}, iconSvg('info', 15), h('span', {}, h('b', { style: 'color:var(--ink);font-weight:600' }, t), h('br'), d)))),
      ),
    ),
  );
}

// ---------------------------------------------------------------- connect

function codeDialog(tab: 'script' | 'policy' = 'script') {
  const dlg = h('dialog', { 'aria-label': 'Collector files' }) as HTMLDialogElement;
  const body = h('pre', { class: 'code', id: 'code' });
  const tabs = h('div', { class: 'seg' });
  const show = (t: 'script' | 'policy') => {
    tab = t;
    const text = (t === 'script' ? D.SCRIPT : D.POLICY).replace(/\n$/, '');
    body.replaceChildren(...text.split('\n').map((l) => h('span', { class: 'l' }, l.startsWith('#') ? h('span', { class: 'c' }, l) : l || ' ')));
    for (const b of tabs.querySelectorAll('button')) b.setAttribute('aria-pressed', String(b.dataset.tab === t));
  };
  tabs.append(on(h('button', { type: 'button', 'data-tab': 'script' }, 'cloudshell-collect.sh'), 'click', () => show('script')), on(h('button', { type: 'button', 'data-tab': 'policy' }, 'iam-policy.json'), 'click', () => show('policy')));
  const file = () => (tab === 'script' ? ['cloudshell-collect.sh', D.SCRIPT, 'text/x-shellscript'] : ['iam-policy.json', D.POLICY, 'application/json']) as [string, string, string];
  dlg.append(
    h(
      'div',
      { class: 'dlg-h' },
      tabs,
      h('div', { style: 'display:flex;flex-wrap:wrap;gap:0.375rem' }, btn('Copy', 'sm', async () => { await D.copyText(file()[1]); toast('Copied'); }), btn([iconSvg('download', 14), 'Download'], 'sm', () => D.saveFile(...file())), btn(iconSvg('x', 15), 'sm ghost icon', () => dlg.close(), { 'aria-label': 'Close' })),
    ),
    body,
  );
  show(tab);
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  if (typeof dlg.showModal === 'function') dlg.showModal();
  else dlg.setAttribute('open', '');
}

function connectPage(): HTMLElement {
  const regions = () => D.regionList(st.regions);
  const first = () => regions()[0] ?? 'us-east-1';
  const p = () => h('span', { class: 'p' }, '$ ');
  const cmd = (display: Child[], copy: () => string) => h('div', { class: 'cmd' }, h('pre', {}, ...display), on(h('button', { type: 'button' }, 'Copy'), 'click', async () => { await D.copyText(copy()); toast('Copied'); }));
  const runHost = h('div');
  const outHost = h('div');
  const cs = h('a', { class: 'btn', target: '_blank', rel: 'noopener noreferrer', href: D.cloudShellUrl(first()) }, iconSvg('open', 14), 'Open CloudShell');
  const draw = () => {
    const r = regions().length ? regions() : ['us-east-1'];
    runHost.replaceChildren(cmd([p(), D.runCommand(r)], () => D.runCommand(r)));
    outHost.replaceChildren(h('div', { class: 'out' }, ...r.flatMap((g) => [`Done. Snapshot written to:\n  /home/cloudshell-user/pinhole-snapshot-111122223333-${g}.json\n`])));
    cs.setAttribute('href', D.cloudShellUrl(first()));
  };
  const rin = h('input', { class: 'rin', id: 'region', value: st.regions, 'aria-label': 'Regions to collect, separated by commas', spellcheck: 'false' }) as HTMLInputElement;
  rin.addEventListener('input', () => { st.regions = rin.value; draw(); });
  draw();
  const step = (n: number, title: string, body: string, ...extra: Child[]) => h('li', { class: 'wstep' }, h('span', { class: 'n' }, String(n)), h('div', { style: 'min-width:0' }, h('h2', {}, title), h('p', {}, body), ...extra));

  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Connect an AWS account'), h('p', {}, 'Collect a read-only snapshot in AWS CloudShell, then load it here. About five minutes per account.'))),
    h(
      'div',
      { class: 'connect' },
      h(
        'section',
        { class: 'box' },
        h(
          'ol',
          { class: 'wiz', id: 'wizard', style: 'list-style:none;margin:0' },
          step(1, 'Open AWS CloudShell in the account to check', 'Sign in to the AWS console with a role that can read EC2 and Elastic Load Balancing configuration. CloudShell already has the AWS CLI and jq, and runs as you.', h('div', { style: 'display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap' }, h('label', { class: 'dim', for: 'region', style: 'font-size:0.7812rem' }, 'Regions'), rin, cs)),
          step(2, 'Put the collector script into CloudShell', 'Paste this into the terminal. It writes cloudshell-collect.sh to your home folder. If CloudShell warns about a multi-line paste, choose Paste.', cmd([p(), `cat > cloudshell-collect.sh <<'PINHOLE_EOF'\n`, h('span', { class: 'c' }, `  ${D.scriptLines()} lines, read it with View script\n`), 'PINHOLE_EOF\n', p(), 'chmod +x cloudshell-collect.sh'], D.heredoc), h('div', { style: 'display:flex;flex-wrap:wrap;gap:0.5rem;margin-top:0.5rem' }, btn([iconSvg('file', 14), 'View script'], 'sm', () => codeDialog('script')), btn([iconSvg('shield', 14), 'View IAM policy'], 'sm', () => codeDialog('policy')))),
          step(3, 'Run it', 'It makes only Describe and Get calls, writes one JSON file per Region and prints where it saved it. Nothing in the account changes.', runHost, h('p', { style: 'margin:0.625rem 0 0;font-size:0.7812rem' }, 'When it finishes you will see something like:'), outHost),
          step(4, 'Download the snapshot to your computer', 'In CloudShell choose Actions, then Download file, and paste the path the script printed. Repeat for each Region. To list the files again:', cmd([p(), D.LIST_CMD], () => D.LIST_CMD)),
          step(5, 'Load the snapshots here', 'Drop the files anywhere on this page, or choose them. They are read and analysed in this browser tab and never uploaded.', btn([iconSvg('upload', 14), 'Choose snapshot files'], 'primary', pick)),
          step(6, 'Optional: clean up CloudShell', 'Remove the snapshots and the script from your CloudShell home folder.', cmd([p(), D.CLEAN_CMD], () => D.CLEAN_CMD)),
        ),
      ),
      h(
        'div',
        { style: 'display:flex;flex-direction:column;gap:1.125rem;min-width:0' },
        h('section', { class: 'box' }, h('div', { class: 'drop', style: 'margin:1rem' }, iconSvg('upload', 26), h('h3', { style: 'margin:0.5rem 0 0.25rem;font-size:0.9375rem' }, 'Drop snapshot files'), h('p', { class: 'dim', style: 'margin:0 0 0.75rem;font-size:0.7812rem' }, 'pinhole-snapshot-*.json, one or many'), btn('Choose files', 'primary', pick))),
        h(
          'section',
          { class: 'box' },
          boxHead('What the collector does'),
          h(
            'ul',
            { class: 'trust' },
            ...[
              'Calls only read-only Describe and Get APIs, listed in the IAM policy',
              'Reads network configuration: VPCs, subnets, routes, network ACLs, security groups, interfaces and load balancers',
              'Does not read instance data, secrets, logs or object storage',
              'Writes one JSON file in your CloudShell home folder and sends nothing anywhere',
            ].map((t) => h('li', {}, iconSvg('check', 15), h('span', {}, t))),
          ),
        ),
        h(
          'section',
          { class: 'box' },
          boxHead('Troubleshooting'),
          ...[
            ['AccessDenied or UnauthorizedOperation', 'The role is missing a permission. The script carries on and records the failed call; the Coverage page lists what is incomplete. Attach the IAM policy to fix it.'],
            ['"jq is required" outside CloudShell', 'Install jq and the AWS CLI v2, or use CloudShell where both are already installed.'],
            ['Several accounts', 'Run the script once in each account and load all the files together. The dashboard shows them side by side.'],
            ['Region not enabled', 'Opt-in Regions must be enabled in the account before they can be collected.'],
          ].map(([q, a]) => h('details', { class: 'faq' }, h('summary', {}, q!), h('p', {}, a!))),
        ),
      ),
    ),
  );
}

// ---------------------------------------------------------------- shell

const LOGO = () => s('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true' }, s('path', { d: 'M3 17h5l4-10h4l2 5h3', fill: 'none', stroke: '#fff', 'stroke-width': 2.4, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));

// render() rebuilds the page. Without care that would throw the reader back to the top and drop
// keyboard focus whenever a filter changes. So: keep the scroll position while on the same page,
// remember where a list was when opening one of its rows, and put focus back on the same control.
const scrollMemo = new Map<string, number>();
let lastKey = '';
function focusKey(el: Element | null): string {
  if (!(el instanceof HTMLElement) || el === document.body) return '';
  if (el.id) return `#${el.id}`;
  for (const a of ['data-sev', 'data-cat', 'data-route', 'aria-label']) {
    const v = el.getAttribute(a);
    if (v) return `${el.tagName.toLowerCase()}[${a}="${v.replace(/["\\]/g, '\\$&')}"]`;
  }
  return '';
}

/** Simulator changes, kept with the snapshot they apply to so a refresh does not lose them. */
const SIM_KEY = 'pinhole-sim';
let simSaved = '';
function saveSim() {
  if (st.demo) return;
  const v = st.changes.length ? JSON.stringify({ key: st.simKey, changes: st.changes }) : '';
  if (v === simSaved) return;
  simSaved = v;
  try {
    if (v) localStorage.setItem(SIM_KEY, v);
    else localStorage.removeItem(SIM_KEY);
  } catch {
    /* storage refused: the changes last for this tab */
  }
}
function loadSim() {
  try {
    const v = localStorage.getItem(SIM_KEY);
    if (!v) return;
    const o = JSON.parse(v) as { key?: unknown; changes?: unknown };
    if (typeof o.key !== 'string' || !st.all.some((x) => x.key === o.key)) return;
    assertChanges(o.changes);
    st.simKey = o.key;
    st.changes = o.changes;
    simSaved = v;
  } catch {
    /* damaged or from another version: ignore */
  }
}

function render() {
  saveSim();
  const before = document.querySelector('main.view') as HTMLElement | null;
  if (before && lastKey) scrollMemo.set(lastKey, before.scrollTop);
  const key = `${st.route}|${st.sel}|${st.chain}`;
  const keep = key === lastKey;
  const restore = keep || !st.sel ? scrollMemo.get(key) : undefined;
  const focus = focusKey(document.activeElement);
  lastKey = key;
  renderNow();
  const after = document.querySelector('main.view') as HTMLElement | null;
  if (after && restore) after.scrollTop = restore;
  if (focus) (document.querySelector(focus) as HTMLElement | null)?.focus?.({ preventScroll: true });
}

function renderNow() {
  const root = document.getElementById('root')!;
  const crit = rows.filter((r) => r.f.severity === 'critical').length;
  const warn = st.snaps.reduce((n, x) => n + x.warnings.length, 0);
  const allChains = D.chainsOf(st.snaps);
  const chains = allChains.length;
  const chainsCrit = allChains.filter((c) => c.c.severity === 'critical').length;
  const hyg = D.hygieneRows(st.snaps).filter((x) => !x.h.inExposure).length;
  const egressOpen = st.snaps.reduce((n, x) => n + egressOf(x).wide, 0);
  const onpremReach = st.snaps.reduce((n, x) => n + onPremOf(x).reachable, 0);
  const plServices = st.snaps.reduce((n, x) => n + privateLinkOf(x).services.filter((s) => s.severity !== 'info').length, 0);
  const link = (route: Route, icon: string, label: string, n?: number, hot = false) =>
    on(h('a', { href: `#/${route}`, 'aria-current': st.route === route ? 'page' : undefined, 'data-route': route }, iconSvg(icon, 18), label, n ? h('span', { class: `n${hot ? ' crit' : ''}` }, String(n)) : null), 'click', (e) => { e.preventDefault(); go(route, { sel: '', ...(route === 'blast' ? { chain: '' } : {}) }); });

  const scope = h('div', { class: 'scope' });
  if (st.demo) scope.append(h('span', { class: 'scope-chip' }, 'Demo environment'));
  else
    for (const x of st.snaps)
      scope.append(h('span', { class: 'scope-chip chip-snap', title: x.name }, h('span', { class: 'k' }, x.account), x.region, on(h('button', { type: 'button', 'aria-label': `Move ${x.account} ${x.region} to the trash`, title: 'Move to the trash' }, iconSvg('x', 12)), 'click', () => removeScope(x.account, x.region))));
    const older = st.all.length - st.snaps.length;
    if (older > 0) scope.append(on(h('button', { type: 'button', class: 'scope-chip chip-older', title: 'Older snapshots of the same account and Region are kept for Compare and left out of every other page.' }, `+${older} older`), 'click', () => go('compare')));
  const mac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform ?? '');

  let view: HTMLElement;
  switch (st.route) {
    case 'graph': view = graphPage(); break;
    case 'blast': view = blastPage(ctx); break;
    case 'hygiene': view = hygienePage(ctx); break;
    case 'policy': view = policyPage(ctx); break;
    case 'egress': view = egressPage(ctx); break;
    case 'savings': view = savingsPage(ctx); break;
    case 'trash': view = trashPage({ trash: st.trash, savedCount: st.demo ? 0 : st.all.length, persistent: S.persistent, restore: (ids) => void restore(ids), purge: (ids) => void purge(ids), forgetAll: () => void forgetAll() }); break;
    case 'onprem': view = onPremPage(ctx); break;
    case 'privatelink': view = privateLinkPage(ctx); break;
    case 'simulator': view = simulatorPage(ctx); break;
    case 'ask': view = askPage(ctx); break;
    case 'issues': view = issuesPage(); break;
    case 'resources': view = resourcesPage(); break;
    case 'coverage': view = coveragePage(); break;
    case 'report': view = reportPage(); break;
    case 'compare': view = comparePage({ st, go: (r, p = {}) => go(r as Route, p as Partial<typeof st>) }); break;
    case 'connect': view = connectPage(); break;
    default: view = dashboard();
  }
  const banners: HTMLElement[] = [];
  const close = (label: string, run: () => void) => on(h('button', { type: 'button', class: 'bar-x', 'aria-label': label }, iconSvg('x', 14)), 'click', () => { run(); render(); });
  if (st.error) banners.push(h('div', { class: 'error-bar', id: 'error', role: 'alert' }, h('span', {}, st.error), close('Dismiss the error', () => { st.error = ''; })));
  if (st.notes.length)
    banners.push(h('div', { class: 'note-bar', id: 'notes', role: 'status' }, h('div', {}, st.notes.length === 1 ? st.notes[0]! : h('ul', {}, ...st.notes.slice(0, 8).map((n) => h('li', {}, n)), st.notes.length > 8 ? h('li', {}, `and ${st.notes.length - 8} more`) : null)), close('Dismiss these notes', () => { st.notes = []; })));
  if (banners.length) {
    const holder = view.classList.contains('page') ? view : view.querySelector('.page, .list-h');
    if (holder) holder.prepend(...banners);
    else view.querySelector('.panel')?.prepend(h('div', { style: 'padding:0.75rem 0.75rem 0' }, ...banners));
  }
  const isFull = st.route === 'graph' || st.route === 'simulator';

  const ribbon = st.demo
    ? h('div', { class: 'ribbon', id: 'demo', role: 'region', 'aria-label': 'Demo environment' }, h('b', {}, 'Demo environment'), h('span', { class: 'hide-sm' }, `Sample data from ${D.plural(st.all.length, 'snapshot')}. Load your own to replace it.`), h('span', { class: 'sp' }), on(h('button', { type: 'button' }, 'Load snapshots'), 'click', pick), on(h('button', { type: 'button' }, 'Connect an account'), 'click', () => go('connect')))
    : null;
  root.replaceChildren(
    h(
      'div',
      { class: 'frame' },
      ribbon,
    h(
      'div',
      { class: 'app' },
      h(
        'nav',
        { class: `side${st.menu ? ' open' : ''}`, 'aria-label': 'Main' },
        h(
          'div',
          { class: 'brand' },
          h('span', { class: 'm' }, LOGO()),
          'Pinhole',
          h('small', {}, `v${D.VERSION}`),
          on(h('button', { type: 'button', class: 'menu-btn', 'aria-expanded': String(st.menu), 'aria-controls': 'main-nav' }, iconSvg(st.menu ? 'x' : 'menu', 18), h('span', {}, st.menu ? 'Close' : PAGES.find((p) => p.route === st.route)?.label ?? 'Menu')), 'click', () => {
            st.menu = !st.menu;
            render();
          }),
        ),
        h(
          'div',
          { class: 'nav', id: 'main-nav' },
          link('dashboard', 'home', 'Dashboard'),
          h('div', { class: 'grp' }, 'From the internet'),
          link('issues', 'list', 'Exposures', rows.length, crit > 0),
          link('graph', 'graph', 'Attack graph'),
          link('blast', 'blast', 'Blast radius', chains, chainsCrit > 0),
          link('resources', 'box', 'Resources', D.resources(rows).length),
          h('div', { class: 'grp' }, 'Other paths'),
          link('egress', 'outbound', 'Outbound', egressOpen),
          link('onprem', 'onprem', 'On-premises', onpremReach),
          link('privatelink', 'link', 'PrivateLink', plServices),
          h('div', { class: 'grp' }, 'Rules'),
          link('hygiene', 'broom', 'Rule hygiene', hyg),
          link('policy', 'policy', 'Policies'),
          link('coverage', 'shield', 'Coverage', warn),
          h('div', { class: 'grp' }, 'Cost'),
          link('savings', 'coin', 'Savings', savingsTotal(st.snaps).count),
          h('div', { class: 'grp' }, 'Tools'),
          link('simulator', 'flask', 'Simulator', st.changes.length),
          link('compare', 'compare', 'Compare', st.all.length - st.snaps.length),
          link('ask', 'route', 'Reachability query'),
          link('report', 'file', 'Report'),
          link('trash', 'trash', 'Trash', st.trash.length),
          link('connect', 'plug', 'Connect an account'),
          // The documentation is a separate page published next to the console (site/docs/).
          h('a', { href: 'docs/', id: 'docs-link' }, iconSvg('file', 18), 'Documentation'),
        ),
        h('div', { class: 'side-foot' }, iconSvg('shield', 14), h('span', {}, 'Runs in this browser tab. Snapshots are never uploaded.')),
      ),
      h(
        'header',
        { class: 'top' },
        scope,
        h('span', { class: 'sp' }),
        on(h('button', { type: 'button', class: 'gsearch', id: 'palette', 'aria-label': 'Search or jump to' }, iconSvg('search', 15), h('span', {}, 'Search or jump to'), h('kbd', {}, mac ? '⌘K' : 'Ctrl K')), 'click', () => openPalette(ctx, PAGES)),
        btn(iconSvg(theme() === 'dark' ? 'sun' : 'moon', 16), 'icon ghost', () => { setTheme(theme() === 'dark' ? 'light' : 'dark'); render(); }, { 'aria-label': theme() === 'dark' ? 'Switch to light theme' : 'Switch to dark theme', id: 'theme' }),
        btn([iconSvg('upload', 15), h('span', { class: 'hide-sm' }, 'Load snapshots')], 'primary', pick),
      ),
      h('main', { class: `view${isFull ? ' full' : ''}`, id: 'view' }, view),
    ),
    ),
  );
}

/** us-east-1 → us-e-1, ap-southeast-2 → ap-se-2: short enough for a matrix column; the full name is the title. */
function shortRegion(r: string): string {
  const COMPASS: Record<string, string> = { northeast: 'ne', southeast: 'se', northwest: 'nw', southwest: 'sw', north: 'n', south: 's', east: 'e', west: 'w', central: 'c', gov: 'gov', iso: 'iso', isob: 'isob' };
  const parts = r.split('-');
  return parts.map((p, i) => (i === 0 || /^\d+$/.test(p) ? p : COMPASS[p] ?? p.slice(0, 2))).join('-');
}

// ---------------------------------------------------------------- start

setSnaps(D.demoSnaps(), true);
const ready = restoreSaved();
st.route = routeFromHash() ?? 'dashboard';
render();
let resizeT = 0;
window.addEventListener('resize', () => {
  clearTimeout(resizeT);
  resizeT = window.setTimeout(() => st.route === 'graph' && render(), 150);
});

(window as unknown as { pinhole: unknown }).pinhole = { loadText, go, state: st, ready, reportHtml: () => reportHtml(reportDoc(st.snaps, rows), 'Pinhole report') };
