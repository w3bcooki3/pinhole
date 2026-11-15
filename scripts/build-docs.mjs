#!/usr/bin/env node
// Builds the documentation into site/docs/index.html: one self-contained page
// with the same fonts, colours and Content Security Policy as the console.
//
// The examples are not typed by hand. Every <!--run ARGS--> in the content is
// replaced by the real output of the Pinhole CLI on the repository's fixtures,
// so the documentation cannot drift from what the tool does.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'packages/web/docs');
const version = JSON.parse(readFileSync(join(root, 'packages/cli/package.json'), 'utf8')).version;
const alias = { '@pinhole/engine': join(root, 'packages/engine/src/index.ts') };

// ---------------------------------------------------------------- the CLI, built from source
const tmp = mkdtempSync(join(tmpdir(), 'pinhole-docs-'));
await build({ entryPoints: [join(root, 'packages/cli/src/index.ts')], bundle: true, platform: 'node', format: 'esm', target: 'node22', outfile: join(tmp, 'cli.mjs'), alias, logLevel: 'error' });
const { run } = await import(pathToFileURL(join(tmp, 'cli.mjs')).href);
rmSync(tmp, { recursive: true, force: true });

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
async function cli(args) {
  let out = '';
  const cwd = process.cwd();
  process.chdir(root);
  try {
    await run(args, { stdout: (s) => (out += s), stderr: (s) => (out += s) });
  } finally {
    process.chdir(cwd);
  }
  return out.replace(/\s+$/, '');
}
// Colour severity tags and verdicts in terminal output; everything else stays plain.
const tint = (line) =>
  esc(line)
    .replace(/\[(CRITICAL)\]/g, '<span class="sev-c">[$1]</span>')
    .replace(/\[(HIGH)\]/g, '<span class="sev-h">[$1]</span>')
    .replace(/\[(MEDIUM)\]/g, '<span class="sev-m">[$1]</span>')
    .replace(/\[(LOW)\]/g, '<span class="sev-l">[$1]</span>')
    .replace(/\b(reachable|Verified)\b/g, '<span class="ok">$1</span>')
    .replace(/\b(blocked|NOT verified)\b/g, '<span class="no">$1</span>');

let content = readFileSync(join(src, 'content.html'), 'utf8').replace(/^<!--[\s\S]*?-->\s*/, '');
const runs = [...content.matchAll(/<!--run(?: lines=(\d+))?(?: from=(\w+))? ([^>]*?)-->/g)];
for (const m of runs) {
  const args = m[3].trim().split(/\s+/);
  const out = await cli(args);
  if (!out) throw new Error(`docs: "pinhole ${m[3]}" printed nothing`);
  let lines = out.split('\n');
  // from=Word: start the shown output at the first line beginning with Word.
  let skipped = '';
  if (m[2]) {
    const at = lines.findIndex((l) => l.startsWith(m[2]));
    if (at < 0) throw new Error(`docs: "pinhole ${m[3]}" has no line starting with ${m[2]}`);
    if (at > 0) skipped = `<i class="more">… ${at} lines about each snapshot on its own</i>\n`;
    lines = lines.slice(at);
  }
  let more = '';
  const max = m[1] ? Number(m[1]) : Infinity;
  if (lines.length > max) {
    more = `\n<i class="more">… ${lines.length - max} more lines</i>`;
    lines = lines.slice(0, max);
  }
  const shown = m[3].trim().replace(/fixtures\/(?:plans\/)?(?:\d\d-[\w-]+\/)?/g, '').replace(/\b\d\d-plan\.json/, 'plan.json');
  const html = `<pre class="term"><code><span class="prompt">pinhole ${esc(shown)}</span>\n${skipped}${lines.map(tint).join('\n')}${more}</code></pre>`;
  content = content.replace(m[0], () => html);
}

// ---------------------------------------------------------------- the example trace (fixture 09)
const STAGE = { 'public-ip': 'Public IP', igw: 'Internet gateway', 'dest-nacl-ingress': 'Network ACL in', 'dest-sg-ingress': 'Security group', 'return-route': 'Route back', 'return-nacl': 'Network ACL out' };
const report = JSON.parse(await cli(['exposure', 'fixtures/09-lateral-movement/snapshot.json', '--format', 'json']));
const f = report.findings.find((x) => x.protocol === 'tcp' && x.ports.from === 22 && /bastion/.test(x.resourceName));
if (!f) throw new Error('docs: fixture 09 no longer has the bastion SSH exposure used in the example');
const check = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>';
// AWS IDs in the detail are set in code; the detail already names the resource, so it is not repeated.
const ids = (t) => esc(t).replace(/\b((?:eni|igw|acl|sgr?|rtb|vpc|subnet)-[\w-]+)/g, '<code>$1</code>');
const hops = f.trace.filter((h) => STAGE[h.stage]).map((h) => `<li><span class="dot">${check}</span><span class="k">${esc(STAGE[h.stage])}</span><span class="v">${ids(h.detail.replace(/ from 1\.0\.0\.0| to 1\.0\.0\.0/g, '').replace(/ -> /g, ' → '))}</span></li>`);
const name = f.resourceName.replace(/ \(.*\)$/, '');
hops.push(`<li class="end"><span class="dot">!</span><span class="k">Critical</span><span class="v">SSH on ${esc(name)} is open to ${esc(f.sources.join(', '))}. The verified fix narrows or removes <code>${esc(f.trace.find((h) => h.stage === 'dest-sg-ingress')?.ruleIds?.[0] ?? '')}</code>.</span></li>`);
content = content.replace('<!--trace-->', `<ol class="trace reveal">${hops.join('')}</ol>`);

// ---------------------------------------------------------------- IAM policy
content = content.replace('<!--policy-->', `<pre class="code"><code>${esc(readFileSync(join(root, 'docs/iam-policy.json'), 'utf8').trim())}</code></pre>`);
if (/<!--(run|trace|policy)/.test(content)) throw new Error('docs: a placeholder was not filled');

// ---------------------------------------------------------------- sections, navigation
const sections = [...content.matchAll(/<section id="([\w-]+)" data-group="([^"]+)" data-title="([^"]+)">/g)].map((m) => ({ id: m[1], group: m[2], title: m[3] }));
content = content.replace(/<section id="/g, '<section class="page" id="').replace(/<(h[12])>/g, '<$1 tabindex="-1">');
const groups = [];
for (const s of sections) {
  let g = groups.find((x) => x.name === s.group);
  if (!g) groups.push((g = { name: s.group, items: [] }));
  g.items.push(s);
}
const nav = groups.map((g) => `<h5>${esc(g.name)}</h5>${g.items.map((s) => `<a href="#${s.id}" data-page="${s.id}">${esc(s.title)}</a>`).join('')}`).join('');

// ---------------------------------------------------------------- script and styles
const bundled = await build({
  entryPoints: [join(src, 'docs.ts')],
  bundle: true,
  write: false,
  outdir: join(root, '.docs-build'),
  format: 'iife',
  target: 'es2020',
  minify: true,
  legalComments: 'none',
  loader: { '.woff2': 'dataurl' },
  logLevel: 'error',
});
const pick = (ext) => bundled.outputFiles.filter((x) => x.path.endsWith(ext)).map((x) => x.text).join('\n');
const js = pick('.js').replace(/<\/script/gi, '<\\/script');
const css = pick('.css').replace(/<\/style/gi, '<\\/style');
const hash = createHash('sha256').update(js).digest('base64');

const icon = {
  search: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>',
  theme: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg>',
  menu: '<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>',
};

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-${hash}'; style-src 'unsafe-inline'; font-src data:; img-src data:; base-uri 'none'; form-action 'none'; connect-src 'none'">
<meta name="referrer" content="no-referrer">
<meta name="description" content="Pinhole documentation: what the internet can reach in your AWS network, what an attacker can reach next, and the fewest verified changes that close it.">
<title>Pinhole documentation</title>
<style>${css}</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top">
  <button class="icon-btn menu-btn" id="menu" aria-label="Sections" aria-expanded="false" aria-controls="nav">${icon.menu}</button>
  <a class="brand" href="#overview"><span class="mark"><span></span></span>Pinhole<span class="docs-label">Docs</span><small>v${esc(version)}</small></a>
  <div class="search" role="search">
    ${icon.search}
    <input id="q" type="search" placeholder="Search the docs" aria-label="Search the docs" autocomplete="off" role="combobox" aria-expanded="false" aria-controls="results">
    <kbd>/</kbd>
    <div class="results" id="results" role="listbox" hidden></div>
  </div>
  <nav class="top-links" aria-label="Elsewhere">
    <a class="tlink hide-sm" href="https://github.com/w3bcooki3/pinhole">GitHub</a>
    <button class="icon-btn" id="theme" aria-label="Switch theme">${icon.theme}</button>
    <a class="btn primary" href="../">Open the console</a>
  </nav>
</header>
<div class="scrim" id="scrim" hidden></div>
<div class="shell">
  <nav class="nav" id="nav" aria-label="Documentation">
    ${nav}
    <p class="nav-foot">Pinhole ${esc(version)}, MIT licence. Everything here is also in the <a href="https://github.com/w3bcooki3/pinhole#readme">README</a>.</p>
  </nav>
  <main id="main">
    <article class="doc">
${content}
      <nav class="pager" id="pager" aria-label="Previous and next"></nav>
      <p class="edit">Found something wrong or unclear? <a href="https://github.com/w3bcooki3/pinhole/issues/new/choose">Open an issue</a>.</p>
    </article>
  </main>
  <aside class="toc" id="toc" aria-label="On this page"><h5>On this page</h5><div id="toc-list"></div></aside>
</div>
<script>${js}</script>
</body>
</html>
`;

mkdirSync(join(root, 'site/docs'), { recursive: true });
writeFileSync(join(root, 'site/docs/index.html'), html);
console.log(`site/docs/index.html written (${Math.round(html.length / 1024)} KB, ${sections.length} sections, ${runs.length} live examples)`);
