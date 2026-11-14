#!/usr/bin/env node
// Prints the release notes for a tag, taken from CHANGELOG.md, and checks that
// the tag matches the version in every package and in the CLI.
//
//   node scripts/release-notes.mjs v0.2.0          notes to stdout
//   node scripts/release-notes.mjs --check v0.2.0  only check; exit 1 on mismatch
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const check = args.includes('--check');
const tag = args.find((a) => !a.startsWith('--')) ?? '';
const fail = (msg) => {
  console.error(`release: ${msg}`);
  process.exit(1);
};

const m = /^v(\d+\.\d+\.\d+)$/.exec(tag);
if (!m) fail(`"${tag}" is not a tag like v1.2.3`);
const version = m[1];

for (const p of ['packages/engine', 'packages/collector', 'packages/cli']) {
  const v = JSON.parse(readFileSync(join(root, p, 'package.json'), 'utf8')).version;
  if (v !== version) fail(`${p}/package.json is ${v}, the tag is ${version}`);
}
const cliSrc = readFileSync(join(root, 'packages/cli/src/version.ts'), 'utf8');
const cliVersion = /VERSION = '([^']+)'/.exec(cliSrc)?.[1];
if (cliVersion !== version) fail(`the CLI reports ${cliVersion}, the tag is ${version}`);

const log = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');
const start = log.search(new RegExp(`^## \\[${version.replace(/\./g, '\\.')}\\]`, 'm'));
if (start < 0) fail(`CHANGELOG.md has no "## [${version}]" section`);
const rest = log.slice(start);
const next = rest.slice(3).search(/^## \[/m);
const section = (next < 0 ? rest : rest.slice(0, next + 3)).replace(/^## .*\n/, '').replace(/\n\[[^\]]+\]: .*$/gm, '').trim();
if (!section) fail(`the ${version} section of CHANGELOG.md is empty`);
if (check) process.exit(0);

process.stdout.write(`${section}

## Downloads

| File | What it is |
|---|---|
| \`pinhole-${version}.html\` | The console as one file. Open it in a browser; it works offline and makes no network requests. |
| \`cloudshell-collect.sh\` | The read-only collector to run in AWS CloudShell. |
| \`pinhole-iam-policy.json\` | The minimal read-only IAM policy the collector needs. |
| \`SHA256SUMS\` | Checksums. Verify with \`sha256sum -c SHA256SUMS\`. |

The same console is published at https://w3bcooki3.github.io/pinhole/.
`);
