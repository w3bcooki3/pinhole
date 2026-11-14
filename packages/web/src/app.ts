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
import { askPage, blastPage, fixesSection, hygienePage, openPalette, planBox, simulatorPage } from './pages.js';
import type { Ctx } from './pages.js';
import type { Change } from '@pinhole/engine';


type Route = 'dashboard' | 'graph' | 'blast' | 'issues' | 'resources' | 'hygiene' | 'coverage' | 'simulator' | 'ask' | 'report' | 'connect';
const ROUTES: Route[] = ['dashboard', 'graph', 'blast', 'issues', 'resources', 'hygiene', 'coverage', 'simulator', 'ask', 'report', 'connect'];
const PAGES: { route: Route; label: string; icon: string }[] = [
  { route: 'dashboard', label: 'Dashboard', icon: 'home' },
  { route: 'graph', label: 'Attack graph', icon: 'graph' },
  { route: 'blast', label: 'Blast radius', icon: 'blast' },
  { route: 'issues', label: 'Exposures', icon: 'list' },
  { route: 'resources', label: 'Resources', icon: 'box' },
  { route: 'hygiene', label: 'Rule hygiene', icon: 'broom' },
  { route: 'coverage', label: 'Coverage', icon: 'shield' },
  { route: 'simulator', label: 'Simulator', icon: 'flask' },
  { route: 'ask', label: 'Reachability query', icon: 'route' },
  { route: 'report', label: 'Report', icon: 'file' },
  { route: 'connect', label: 'Connect an account', icon: 'plug' },
];
type CatFilter = Category | 'world' | '';

const st = {
  snaps: [] as Snap[],
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
};
let rows: Row[] = [];

const port = (r: Row) => D.service(r.f).split('/')[1] ?? D.service(r.f);
const pathTitle = (r: Row) => `${D.shortName(r.f)} on ${D.service(r.f)}`;
const scopeOf = (r: Row) => `${r.snap.account} / ${r.snap.region}`;

// ---------------------------------------------------------------- data in

function setSnaps(snaps: Snap[], demo: boolean) {
  st.snaps = snaps;
  st.demo = demo;
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

function addSnaps(list: Snap[], errors: string[]) {
  st.error = errors.join(' ');
  if (list.length) {
    const keep = st.demo ? [] : st.snaps.filter((x) => !list.some((n) => n.key === x.key));
    setSnaps([...keep, ...list], false);
    st.route = 'dashboard';
    toast(`Loaded ${D.plural(list.length, 'snapshot')}`);
  }
  render();
}

function loadText(text: string, name: string): boolean {
  try {
    addSnaps([D.parseFile(text, name)], []);
    return true;
  } catch (e) {
    addSnaps([], [`${name}: ${(e as Error).message}`]);
    return false;
  }
}

const pick = filePicker((files) => D.readFiles(files, addSnaps));
document.addEventListener('dragenter', () => document.body.classList.add('dragging'));
document.addEventListener('dragleave', (e) => !e.relatedTarget && document.body.classList.remove('dragging'));
document.addEventListener('drop', () => document.body.classList.remove('dragging'));

// ---------------------------------------------------------------- navigation

function go(route: Route, patch: Partial<typeof st> = {}) {
  Object.assign(st, patch);
  st.route = route;
  try {
    if (location.hash !== `#/${route}`) history.replaceState(null, '', `#/${route}`);
  } catch {
    /* file:// in some browsers */
  }
  render();
  document.querySelector('main.view')?.scrollTo?.(0, 0);
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
try {
  if (localStorage.getItem('pinhole-theme') === 'dark') document.documentElement.dataset.theme = 'dark';
} catch {
  /* light stays the default */
}

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
      { class: 'dgrid' },
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
            h('dt', {}, 'Snapshot'), h('dd', {}, r.snap.name),
          ),
        )),
      ),
      h(
        'div',
        { class: 'dcol' },
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

function sevSegments(list: Severity[]): HTMLElement {
  const bar = h('div', { class: 'bar', 'aria-hidden': 'true' });
  for (const sv of D.SEVERITY_ORDER) {
    const n = list.filter((x) => x === sv).length;
    if (n) bar.append(h('span', { style: `flex:${n};background:${sevVar(sv)}` }));
  }
  if (!list.length) bar.append(h('span', { style: 'flex:1;background:var(--line2)' }));
  return bar;
}

// ---------------------------------------------------------------- dashboard


function chain(r: Row): HTMLElement {
  const sep = () => h('span', { class: 'sep' }, iconSvg('chev', 12));
  const entry = D.entryPoint(r.f).replace(/ \(.*\)$/, '');
  const parts = r.f.kind === 'load-balancer' ? ['Internet', entry] : ['Internet', entry, D.shortName(r.f)];
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
      h('div', {}, h('h1', {}, 'Dashboard'), h('p', {}, `Internet exposure across ${D.plural(accounts.size, 'account')} and ${D.plural(regions.size, 'region')}.`, ...(() => {
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
  const grid = h('div', { class: 'dgrid' });
  page.append(grid);

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
  const lbs = res.filter((x) => x.kind.includes('Load')).length;
  const cell = (k: string, v: string, sub: string, act?: () => void) => {
    const kids = [h('div', { class: 'k' }, k), h('div', { class: 'v' }, v), h('div', { class: 'sub' }, sub)];
    return act ? on(h('button', { type: 'button', class: 'cell' }, ...kids), 'click', act) : h('div', {}, ...kids);
  };
  grid.append(
    h(
      'section',
      { class: 'box summary s12', id: 'summary' },
      h('div', {}, h('div', { class: 'k' }, 'Internet exposures'), h('div', { class: 'v', id: 'total' }, String(rows.length)), bar, legend),
      cell('Exposed resources', String(res.length), `${D.plural(lbs, 'load balancer')}, ${D.plural(res.length - lbs, 'interface')}`, () => go('resources')),
      cell('Open to any address', String(world), 'Exposures open to 0.0.0.0/0', toIssues({ cat: 'world' })),
      cell('Attack chains', String(chainRows.length), chainRows.length ? `${chainRows.filter((c) => c.c.severity === 'critical').length} critical, reaching ${new Set(chainRows.map((c) => `${c.snap.key}|${c.c.targetId}`)).size} resources` : 'No lateral movement found', () => go('blast')),
      cell('Coverage notes', String(warn), warn ? 'Configuration not fully analysed' : 'Everything was analysed', () => go('coverage')),
    ),
  );

  // What to do: the smallest verified set of changes.
  grid.append(planBox(ctx));

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
  grid.append(
    h(
      'section',
      { class: 'box s4', id: 'categories' },
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
      { class: 'box s8', id: 'top-paths' },
      boxHead('Top exposures', 'What the internet can reach, most severe first', linkBtn(`View all ${rows.length}`, toIssues({}))),
      h(
        'table',
        { class: 't' },
        h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Path'), h('th', {}, 'Service'), h('th', { class: 'hide-sm' }, 'Open to'), h('th', { class: 'last hide-sm' }, 'Account and region'))),
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
                h('td', {}, h('span', { class: 'mono' }, D.service(r.f)), D.serviceName(r.f) ? h('span', { class: 'faint' }, `  ${D.serviceName(r.f)}`) : null),
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
  const matrix = h('div', { class: 'matrix', style: `grid-template-columns:minmax(6.5rem,1.2fr) repeat(${regs.length},minmax(0,1fr))` }, h('span'), ...regs.map((x) => h('span', { class: 'hd', title: x }, x)));
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
  grid.append(h('section', { class: 'box s4', id: 'matrix' }, boxHead('Accounts and regions', 'Exposures, coloured by the worst one'), matrix));

  // Lateral movement: the worst chains, and the rules that cut the most of them.
  if (chainRows.length) {
    const top = chainRows.slice(0, 6);
    grid.append(
      h(
        'section',
        { class: 'box s8', id: 'chains' },
        boxHead('Attack chains', 'Internal resources reachable after one server is compromised', linkBtn(`View all ${chainRows.length}`, () => go('blast', { chain: '' }))),
        h(
          'table',
          { class: 't' },
          h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Chain'), h('th', {}, 'Ends at'), h('th', { class: 'last hide-sm' }, 'Account and region'))),
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
  grid.append(
    h(
      'section',
      { class: 'box s4', id: 'services' },
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
              h('tr', { class: 'click' }, h('td', { class: 'first' }, sevPill(list[0]!.f.severity, D.serviceName(list[0]!.f) || k)), h('td', { class: 'mono' }, k), h('td', { class: 'r last' }, String(new Set(list.map((x) => x.f.resourceId)).size))),
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
  grid.append(h('section', { class: 'box s12', id: 'surface' }, boxHead('Attack surface', top.length ? `${D.plural(Math.min(top.length, 10), 'critical or high exposure')}` : 'All exposures', linkBtn('Open attack graph', () => go('graph'))), surface));

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
  const find = h('input', { type: 'search', placeholder: 'Highlight a resource, IP or port', value: st.gq, 'aria-label': 'Highlight in graph', id: 'gfind' }) as HTMLInputElement;
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
  const wrap = h('div', { class: 'graph-page' }, canvas, ...dock);
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
  const scopeSel = h('select', { 'aria-label': 'Account and region', id: 'scope' }, h('option', { value: '' }, 'All accounts and regions'), ...scopes.map((x) => h('option', { value: x }, x))) as HTMLSelectElement;
  scopeSel.value = st.scope;
  scopeSel.addEventListener('change', () => { st.scope = scopeSel.value; render(); });

  const tbody = h('tbody');
  const fill = () => {
    const now = filtered();
    tbody.replaceChildren(
      ...now.map((r) =>
        on(
          h(
            'tr',
            { class: 'click', tabindex: 0, 'aria-selected': String(st.sel === r.id) },
            h('td', { class: 'first' }, sevPill(r.f.severity)),
            h('td', {}, h('div', { style: 'font-weight:600' }, D.shortName(r.f)), h('div', { class: 'faint', style: 'font-size:0.75rem' }, D.kind(r.f))),
            h('td', {}, h('span', { class: 'mono' }, D.service(r.f)), h('div', { class: 'faint', style: 'font-size:0.75rem' }, D.serviceName(r.f))),
            h('td', { class: 'mono' }, D.openTo(r.f)),
            h('td', { class: 'mono faint hide-sm' }, `${r.snap.account} ${r.snap.region}`),
          ),
          'click',
          () => { st.sel = r.id; render(); scrollTop(); },
        ),
      ),
    );
    count.textContent = `${now.length} of ${D.plural(rows.length, 'exposure')}`;
  };
  const count = h('span', { class: 'count' });
  search.addEventListener('input', () => { st.q = search.value; fill(); });

  const exportCsv = () => D.saveFile('pinhole-exposures.csv', D.csv(filtered()), 'text/csv');
  const exportJson = () => D.saveFile('pinhole-exposures.json', `${JSON.stringify(filtered().map((r) => ({ account: r.snap.account, region: r.snap.region, ...r.f })), null, 2)}\n`, 'application/json');
  const table = h('table', { class: 't' }, h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Severity'), h('th', {}, 'Resource'), h('th', {}, 'Service'), h('th', {}, 'Open to'), h('th', { class: 'hide-sm' }, 'Account and region'))), tbody);
  fill();
  const left = h(
    'div',
    { class: 'list' },
    h('div', { class: 'list-h' }, h('div', { class: 'ph', style: 'margin-bottom:0' }, h('div', {}, h('h1', {}, 'Internet exposures'), h('p', {}, 'Every service the internet can open a connection to, most severe first. Select one for the exact path and a verified fix.')), h('div', { class: 'acts' }, btn([iconSvg('download', 14), 'CSV'], 'sm', exportCsv), btn([iconSvg('download', 14), 'JSON'], 'sm', exportJson)))),
    h('div', { class: 'filters' }, seg, h('label', { class: 'lsearch' }, iconSvg('search', 14), search), catSel, scopes.length > 1 ? scopeSel : null, count),
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
            h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Resource'), h('th', {}, 'Open ports'), h('th', { class: 'hide-sm' }, 'Public IPs'), h('th', { class: 'hide-sm' }, 'VPC'), h('th', { class: 'hide-sm' }, 'Account and region'), h('th', { class: 'last' }, 'Worst'))),
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
  ['AWS Network Firewall and Gateway Load Balancer', 'Traffic routed through an inspection appliance is reported as unknown past that hop.'],
  ['IPv6', 'Only IPv4 paths are analysed. IPv6 CIDRs and egress-only gateways are detected and listed here.'],
  ['Global Accelerator and CloudFront', 'Entry through these services is detected where possible but not traced.'],
  ['VPN, Direct Connect and VPC endpoints', 'Routes to these targets are reported as unknown rather than blocked.'],
];

function reportPage(): HTMLElement {
  if (!st.snaps.length) return h('div', { class: 'page' }, h('div', { class: 'box' }, empty('No snapshots loaded', 'Load snapshots to build a report.')));
  const doc = reportDoc(st.snaps, rows);
  const accounts = [...new Set(st.snaps.map((x) => x.account))].sort();
  const day = new Date().toISOString().slice(0, 10);
  const title = `Pinhole report, ${accounts.join(', ')}, ${day}`;
  return h(
    'div',
    { class: 'page report-page' },
    h(
      'div',
      { class: 'ph no-print' },
      h('div', {}, h('h1', {}, 'Report'), h('p', {}, 'Everything on one page for someone who will not open the console: the summary, the fix plan with commands, every exposure and chain, and what the analysis could not see.')),
      h('div', { class: 'acts' }, btn([iconSvg('file', 14), 'Print or save as PDF'], 'primary', () => window.print()), btn([iconSvg('download', 14), 'Download HTML'], '', () => D.saveFile(`pinhole-report-${day}.html`, reportHtml(doc, title), 'text/html'))),
    ),
    st.demo ? h('p', { class: 'no-print stale-t', style: 'margin:0 0 1rem' }, 'This is the demo environment. Load your own snapshots for a real report.') : null,
    h('style', {}, REPORT_CSS),
    h('div', { class: 'paper' }, doc),
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
        h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Account and region'), h('th', { class: 'hide-sm' }, 'Collected'), h('th', {}, 'Interfaces'), h('th', {}, 'Load balancers'), h('th', {}, 'Open paths'), h('th', { class: 'last' }, 'Notes'))),
        h(
          'tbody',
          {},
          ...st.snaps.map((x) =>
            h(
              'tr',
              {},
              h('td', { class: 'first' }, h('div', { class: 'mono' }, `${x.account} / ${x.region}`), h('div', { class: 'faint', style: 'font-size:0.75rem' }, x.name)),
              h('td', { class: 'hide-sm' }, x.collectedAt ? x.collectedAt.replace('T', ' ').replace(/\.\d+Z$|Z$/, ' UTC') : 'unknown'),
              h('td', { class: 'mono' }, `${x.stats.interfacesAnalysed} of ${x.stats.interfacesWithPublicIp} public`),
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
      h('div', { style: 'display:flex;gap:0.375rem' }, btn('Copy', 'sm', async () => { await D.copyText(file()[1]); toast('Copied'); }), btn([iconSvg('download', 14), 'Download'], 'sm', () => D.saveFile(...file())), btn(iconSvg('x', 15), 'sm ghost icon', () => dlg.close(), { 'aria-label': 'Close' })),
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
  const step = (n: number, title: string, body: string, ...extra: Child[]) => h('li', { class: 'wstep' }, h('span', { class: 'n' }, String(n)), h('div', { style: 'min-width:0' }, h('h3', {}, title), h('p', {}, body), ...extra));

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
          step(2, 'Put the collector script into CloudShell', 'Paste this into the terminal. It writes cloudshell-collect.sh to your home folder. If CloudShell warns about a multi-line paste, choose Paste.', cmd([p(), `cat > cloudshell-collect.sh <<'PINHOLE_EOF'\n`, h('span', { class: 'c' }, `  ${D.scriptLines()} lines, read it with View script\n`), 'PINHOLE_EOF\n', p(), 'chmod +x cloudshell-collect.sh'], D.heredoc), h('div', { style: 'display:flex;gap:0.5rem;margin-top:0.5rem' }, btn([iconSvg('file', 14), 'View script'], 'sm', () => codeDialog('script')), btn([iconSvg('shield', 14), 'View IAM policy'], 'sm', () => codeDialog('policy')))),
          step(3, 'Run it', 'It makes only Describe and Get calls, writes one JSON file per region and prints where it saved it. Nothing in the account changes.', runHost, h('p', { style: 'margin:0.625rem 0 0;font-size:0.7812rem' }, 'When it finishes you will see something like:'), outHost),
          step(4, 'Download the snapshot to your computer', 'In CloudShell choose Actions, then Download file, and paste the path the script printed. Repeat for each region. To list the files again:', cmd([p(), D.LIST_CMD], () => D.LIST_CMD)),
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
            ['Region not enabled', 'Opt-in regions must be enabled in the account before they can be collected.'],
          ].map(([q, a]) => h('details', { class: 'faq' }, h('summary', {}, q!), h('p', {}, a!))),
        ),
      ),
    ),
  );
}

// ---------------------------------------------------------------- shell

const LOGO = () => s('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true' }, s('path', { d: 'M3 17h5l4-10h4l2 5h3', fill: 'none', stroke: '#fff', 'stroke-width': 2.4, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));

function render() {
  const root = document.getElementById('root')!;
  const crit = rows.filter((r) => r.f.severity === 'critical').length;
  const warn = st.snaps.reduce((n, x) => n + x.warnings.length, 0);
  const allChains = D.chainsOf(st.snaps);
  const chains = allChains.length;
  const chainsCrit = allChains.filter((c) => c.c.severity === 'critical').length;
  const hyg = D.hygieneRows(st.snaps).filter((x) => !x.h.inExposure).length;
  const link = (route: Route, icon: string, label: string, n?: number, hot = false) =>
    on(h('a', { href: `#/${route}`, 'aria-current': st.route === route ? 'page' : undefined, 'data-route': route }, iconSvg(icon, 18), label, n ? h('span', { class: `n${hot ? ' crit' : ''}` }, String(n)) : null), 'click', (e) => { e.preventDefault(); go(route, { sel: '', ...(route === 'blast' ? { chain: '' } : {}) }); });

  const scope = h('div', { class: 'scope' });
  if (st.demo) scope.append(h('span', { class: 'scope-chip' }, 'Demo environment'));
  else
    for (const x of st.snaps)
      scope.append(h('span', { class: 'scope-chip chip-snap', title: x.name }, h('span', { class: 'k' }, x.account), x.region, on(h('button', { type: 'button', 'aria-label': `Remove ${x.account} ${x.region}` }, iconSvg('x', 12)), 'click', () => { setSnaps(st.snaps.filter((y) => y !== x), false); render(); })));
  const mac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform ?? '');

  let view: HTMLElement;
  switch (st.route) {
    case 'graph': view = graphPage(); break;
    case 'blast': view = blastPage(ctx); break;
    case 'hygiene': view = hygienePage(ctx); break;
    case 'simulator': view = simulatorPage(ctx); break;
    case 'ask': view = askPage(ctx); break;
    case 'issues': view = issuesPage(); break;
    case 'resources': view = resourcesPage(); break;
    case 'coverage': view = coveragePage(); break;
    case 'report': view = reportPage(); break;
    case 'connect': view = connectPage(); break;
    default: view = dashboard();
  }
  const banners: HTMLElement[] = [];
  if (st.error) banners.push(h('div', { class: 'error-bar', id: 'error', role: 'alert' }, st.error));
  if (banners.length) {
    const holder = view.classList.contains('page') ? view : view.querySelector('.page, .list-h');
    if (holder) holder.prepend(...banners);
    else view.querySelector('.panel')?.prepend(h('div', { style: 'padding:0.75rem 0.75rem 0' }, ...banners));
  }
  const isFull = st.route === 'graph' || st.route === 'simulator';

  const ribbon = st.demo
    ? h('div', { class: 'ribbon', id: 'demo', role: 'note' }, h('b', {}, 'Demo environment'), h('span', {}, 'Sample data from five snapshots. Load your own to replace it.'), h('span', { class: 'sp' }), on(h('button', { type: 'button' }, 'Load snapshots'), 'click', pick), on(h('button', { type: 'button' }, 'Connect an account'), 'click', () => go('connect')))
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
        { class: 'side', 'aria-label': 'Main' },
        h('div', { class: 'brand' }, h('span', { class: 'm' }, LOGO()), 'Pinhole', h('small', {}, `v${D.VERSION}`)),
        h(
          'div',
          { class: 'nav' },
          h('div', { class: 'grp' }, 'Analysis'),
          link('dashboard', 'home', 'Dashboard'),
          link('graph', 'graph', 'Attack graph'),
          link('blast', 'blast', 'Blast radius', chains, chainsCrit > 0),
          link('issues', 'list', 'Exposures', rows.length, crit > 0),
          link('resources', 'box', 'Resources', D.resources(rows).length),
          link('hygiene', 'broom', 'Rule hygiene', hyg),
          link('coverage', 'shield', 'Coverage', warn),
          h('div', { class: 'grp' }, 'Tools'),
          link('simulator', 'flask', 'Simulator', st.changes.length),
          link('ask', 'route', 'Reachability query'),
          link('report', 'file', 'Report'),
          link('connect', 'plug', 'Connect an account'),
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

// ---------------------------------------------------------------- start

setSnaps(D.demoSnaps(), true);
st.route = routeFromHash() ?? 'dashboard';
render();
let resizeT = 0;
window.addEventListener('resize', () => {
  clearTimeout(resizeT);
  resizeT = window.setTimeout(() => st.route === 'graph' && render(), 150);
});

(window as unknown as { pinhole: unknown }).pinhole = { loadText, go, state: st, reportHtml: () => reportHtml(reportDoc(st.snaps, rows), 'Pinhole report') };
