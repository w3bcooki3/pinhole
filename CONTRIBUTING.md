# Contributing to Pinhole

Thanks for helping. Pinhole is used to decide whether a network is safe, so the bar is correctness first: every answer must follow from documented AWS behaviour, and every change must be tested.

## Ways to help

- **Report a wrong result.** This is the most valuable contribution. Open a [bug report](https://github.com/w3bcooki3/pinhole/issues/new/choose) with a small hand-written snapshot that shows it. Never attach a real snapshot.
- **Ask for coverage.** If Pinhole warns that something is not modelled and you need it, open a feature request with a link to the AWS documentation.
- **Fix something.** Small, focused pull requests are easiest to review. For anything large, open an issue first so we can agree on the approach.
- **Security problems** go through [private reporting](SECURITY.md), not issues.

## Set up

You need Node.js 22 or later, and `jq` and `bash` for the CloudShell script tests.

```sh
git clone https://github.com/w3bcooki3/pinhole.git
cd pinhole
npm ci
npm run build
npm test
```

Useful commands:

| Command | What it does |
|---|---|
| `npm test` | Every unit test, fixture, collector test and web console test |
| `npm run test:fixtures` | The hand-written scenarios only |
| `npm run build:web` | Builds the console into `site/index.html`; open it from disk |
| `npm run typecheck:web` | Type-checks the console |
| `npm run fixture-count` | Updates the fixture count in the README (CI checks it) |
| `npm run bench` | Times the engine on a large synthetic account |

Run `npm run build` again after changing `packages/engine`, `collector` or `cli`; the CLI tests use the built output.

## Where things live

| Path | What |
|---|---|
| `packages/engine` | Pure analysis: no I/O, no AWS SDK, runs in Node and browsers |
| `packages/collector` | Read-only AWS SDK collector |
| `packages/cli` | The `pinhole` command |
| `packages/web` | The console, built into one HTML file |
| `scripts/cloudshell-collect.sh` | The CloudShell collector; the console embeds it |
| `fixtures/` | Scenarios with expected answers and AWS documentation links |
| `docs/model.md` | Every behaviour modelled, and every simplification |

## Rules for changes

1. **Tests first.** A change in evaluation needs a failing test before the fix. A new AWS behaviour needs a fixture: `fixtures/NN-name/` with `snapshot.json`, `expected.json` and a `README.md` that links the AWS documentation.
2. **Cite AWS.** Code that models AWS behaviour has a comment linking the page that documents it. If AWS does not document it, say so and choose the answer that reports more exposure, not less.
3. **Never guess quietly.** When the snapshot lacks what an answer depends on, the verdict is `unknown` and the reason is shown.
4. **Collection stays read-only.** Only `Describe*`, `Get*` and `Search*` calls. Adding one means updating `docs/iam-policy.json`; a test checks they match.
5. **Untrusted input.** Snapshots come from files people share. Snapshot text goes into pages as text only, and into commands only through the quoting helpers. New snapshot fields need a rule in the validator in `packages/engine/src/snapshot.ts`.
6. **No new runtime dependencies** in the engine. Others need a good reason.
7. **Changelog.** Add a line under "Unreleased" in `CHANGELOG.md` for anything users will notice.

## Commits and pull requests

- One topic per pull request. Keep commits small and say what changed and why in plain words.
- CI must pass: tests on Node 22 and 24, the web type check, `npm audit` on runtime dependencies, and the fixture count.
- Fill in the checklist in the pull request template.

## Writing style

Docs and interface text use plain words and short sentences. Name things the way a person using AWS would, not the way the code is built. Say what Pinhole cannot see as clearly as what it can.

## Licence

By contributing you agree that your contribution is licensed under the [MIT licence](LICENSE).
