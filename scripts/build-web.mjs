#!/usr/bin/env node
// Builds the web console into site/index.html: one self-contained file with
// the engine, the UI, embedded fonts and a demo environment. Open it from
// disk or publish the site/ folder with GitHub Pages. No network at runtime.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DEMO } from './demo-data.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const version = JSON.parse(readFileSync(join(root, 'packages/cli/package.json'), 'utf8')).version;
const script = readFileSync(join(root, 'scripts/cloudshell-collect.sh'), 'utf8');
const policy = readFileSync(join(root, 'docs/iam-policy.json'), 'utf8');

const result = await build({
  entryPoints: [join(root, 'packages/web/src/app.ts')],
  bundle: true,
  write: false,
  outdir: join(root, '.web-build'),
  format: 'iife',
  target: 'es2020',
  minify: true,
  legalComments: 'none',
  // Fonts (Inter and Geist Mono, SIL Open Font License 1.1) become data: URLs.
  loader: { '.woff2': 'dataurl' },
  // Use the engine's TypeScript sources directly; no build of the engine needed.
  alias: { '@pinhole/engine': join(root, 'packages/engine/src/index.ts') },
  define: { __DEMO__: JSON.stringify(DEMO), __VERSION__: JSON.stringify(version), __SCRIPT__: JSON.stringify(script), __POLICY__: JSON.stringify(policy) },
  logLevel: 'error',
});
const pick = (ext) => result.outputFiles.filter((f) => f.path.endsWith(ext)).map((f) => f.text).join('\n');
// "</script" or "</style" inside the bundle would end the inline element early.
const js = pick('.js').replace(/<\/script/gi, '<\\/script');
const css = pick('.css').replace(/<\/style/gi, '<\\/style');
// Only this exact script may run: the CSP allows it by hash, not 'unsafe-inline'.
const scriptHash = createHash('sha256').update(js).digest('base64');
const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-${scriptHash}'; style-src 'unsafe-inline'; font-src data:; img-src data:; base-uri 'none'; form-action 'none'; connect-src 'none'">
<meta name="referrer" content="no-referrer">
<meta name="description" content="Pinhole shows what the internet can reach in your AWS network, and through which rules. Runs entirely in your browser.">
<title>Pinhole</title>
<style>${css}</style>
</head>
<body>
<div id="root"></div>
<noscript>Pinhole needs JavaScript. It runs entirely in this page and sends nothing anywhere.</noscript>
<script>${js}</script>
</body>
</html>
`;

const out = join(root, 'site');
mkdirSync(out, { recursive: true });
writeFileSync(join(out, 'index.html'), html);
writeFileSync(join(out, '.nojekyll'), '');
// Also publish the script and policy next to the page, for direct links.
copyFileSync(join(root, 'scripts/cloudshell-collect.sh'), join(out, 'cloudshell-collect.sh'));
copyFileSync(join(root, 'docs/iam-policy.json'), join(out, 'iam-policy.json'));
console.log(`site/index.html written (${Math.round(html.length / 1024)} KB)`);
