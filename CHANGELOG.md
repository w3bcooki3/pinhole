# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-13

### Added
- Service reachability between any two interfaces (`pinhole can`, console
  Reachability query), decided exactly over every protocol and port.
- Blast radius: from each internet-facing resource, the resources an attacker
  reaches by moving through remote administration and control-plane services,
  ranked as attack chains (`pinhole blast`, console Blast radius page with a
  traced chain).
- Chokepoints: the single security group rules whose removal cuts the most
  chains, proved by re-running both analyses.
- Fix finder: candidate fixes for each finding (cut ports out of a wider rule,
  remove a rule, network ACL deny, remove the public IP), each verified by
  re-analysis, with bonus and collateral paths and AWS CLI commands
  (`pinhole fix`, console issue detail).
- What-if: apply changes to a copy of the model and diff exposure and attack
  chains (`pinhole whatif`, console Simulator).
- Rule hygiene: redundant, shadowed, stale, unused and overly broad rules
  (`pinhole hygiene`, console Rule hygiene page).
- Command palette in the console (Ctrl+K or /).
- Report page: a summary, the fix plan with commands, every exposure and
  chain, rule hygiene, and method and limits, ready to print or save as PDF,
  or download as one HTML file with no script.
- Fixture 09 (lateral movement) with expected chains, hygiene, fixes and
  what-if results.

- Fix plan on the dashboard and `pinhole fix --plan`: the fewest verified
  changes that close every critical and high exposure and attack chain, each
  showing what it closes, what else it affects and its AWS CLI command.
- Fixes that restrict a rule to the VPC, keeping internal access.

- Release workflow: pushing a version tag tests, builds and publishes a
  GitHub release with the console as one HTML file, the CloudShell script,
  the IAM policy and SHA-256 checksums, with notes from this changelog. The
  tag must match the package versions.
- Contributor guide, code of conduct, issue forms (wrong result, feature)
  that remind reporters never to attach a real snapshot, and a pull request
  checklist.
- `npm run check` runs everything CI runs.

- `pinhole diff OLD NEW`: what changed between two snapshots of one account
  and region. New, wider, narrower and closed internet exposure; new and
  closed attack chains; and the security group rule, network ACL, route,
  public IP, load balancer and listener changes behind them. Text, JSON or
  Markdown, and `--fail-on LEVEL` for pipelines.
- Compare page in the console for the same comparison. Older snapshots of an
  account and region are kept for it; every other page uses only the latest,
  so loading last week's file next to today's no longer doubles findings.
- `pinhole exposure --format sarif`: SARIF 2.1.0 for GitHub code scanning,
  with a rule per kind of service, security severities and a stable
  fingerprint per exposed service.
- `pinhole exposure --format markdown` for tickets and pull request comments.

- `pinhole plan SNAPSHOT PLAN.json`: what a Terraform plan would do to
  internet exposure and attack chains before it is applied, from
  `terraform show -json` output. Security groups and their rules, network
  ACLs, routes, security group attachments and Elastic IP associations are
  placed on the snapshot; anything that cannot be placed exactly is listed as
  not analysed, with the reason. Text, JSON or Markdown, and `--fail-on`.
  Security groups the plan creates are followed through the plan's
  references, including module outputs, so a new group, its rules and its
  attachment to an existing server are checked together.
- GitHub Action (`uses: w3bcooki3/pinhole@v0.2.0`) to run the exposure, diff
  or plan check in another repository's workflow, with a job summary,
  optional SARIF, and a failing step on new exposure. CI tests it end to end.
- Simulator and change lists can attach security groups, add routes and add
  public IPs, and rules can reference prefix lists.

- `pinhole collect --region a,b,c --out-dir DIR` collects several regions in
  one run, one file each; a region that fails does not stop the others.

- IPv6 internet exposure of network interfaces, for TCP and UDP: exact over
  ports and 128-bit source ranges, through the internet gateway route, IPv6
  network ACL rules in both directions and IPv6 security group rules. IPv6
  addresses need no public IP, so dual-stack subnets are no longer a blind
  spot. Findings are marked IPv6 in every output; fixes, plans, diffs and the
  console handle them. Fixture 10 covers it.

### Changed
- One vocabulary across the console: Exposures (what the internet reaches),
  Attack chains (what a compromised server reaches next) and Rule hygiene.
  Labels and help text rewritten in plain language.
- Attack chains are merged per target; a chain is not reported when the
  internet already reaches its target directly. The demo goes from 59 chains
  to 7.
- A fix that keeps access from inside the VPC is ranked below removing the
  rule when another internet-facing server could still reach the resource,
  and says so.
- The simulator lists chains revealed by a change (hidden before because the
  internet reached the target directly) as still reachable from inside, not
  as new.
- Rule hygiene leaves out rules already reported as exposures, behind a toggle.
- Reachability query answers with a plain yes or no first.
- Exposure and attack chain details are full pages instead of narrow side
  panels: a one-sentence verdict, the evidence, verified fixes, and previous
  and next. On one column the verdict and fix come first.
- The attack graph keeps the selected path in view and shows it in a bar
  below the graph.
- Type and spacing scale with the screen, from 16px on a laptop to 20px on a
  2560px display, and follow browser zoom.
- Every detail page says when the snapshot was collected, what was and was not
  checked, and links to coverage notes. Snapshots older than a week are
  flagged.
- A chain cut on an internal hop is no longer marked recommended: it may be
  traffic the servers need, and the page says so and points to the entry
  points instead.
- Clickable rows work from the keyboard.
- Exposure findings for the same resource, protocol, ports and return path
  are merged, with the union of their sources, instead of one per deciding rule.
- The demo environment has a fifth snapshot built from fixture 09.

- README opens with the console link, a screenshot, three questions Pinhole
  answers and a quick start.
- Line endings are fixed to LF for every checkout, including on Windows.
- CI cancels superseded runs on the same branch.
- Exposure analysis is about 3 to 7 times faster on large accounts:
  interfaces that share a subnet, security groups and interface type are
  analysed once and checked per interface, and address-set comparisons no
  longer build CIDR strings. Added `npm run bench`.
- Renamed the project from CloudPath to Pinhole (the name is a registered
  trademark of another network software vendor). The CLI command is now
  `pinhole`, packages are `@pinhole/engine` and `@pinhole/collector`, and
  snapshots are written as `pinhole-snapshot-<account>-<region>.json`.
- New web console, replacing the first static page: still one offline HTML
  file with no server or network access, light by default with a dark theme,
  Inter and Geist Mono fonts (SIL OFL 1.1) embedded, a labelled demo
  environment built from the fixtures, and a six-step Connect page with the
  script and IAM policy viewer and troubleshooting notes. The design
  prototypes and their React and Cloudscape development dependencies were
  removed.

### Security
- Snapshots are validated field by field before analysis (types, ranges, ID
  and ARN shapes, account, region and time formats, sizes); failures name the
  field. Control characters are refused in structural fields and replaced in
  free text; reserved keys are refused; keyed lookups use own properties only.
- Generated AWS CLI commands pass structured parameters as JSON, so a hostile
  rule description cannot change what a fix command sets. Numbers are checked,
  comment lines are kept to one line, and hygiene commands are shell-quoted.
- `pinhole whatif --changes` validates the change list before use.
- Collector error messages are kept to one line with control characters
  removed.
- CSV export also guards cells starting with tab or carriage return; the web
  console reads at most 200 files at once.
- Web console: the Content Security Policy now allows only the page's own
  script by SHA-256 hash (no `'unsafe-inline'` for scripts), blocks all
  connections, and sends no referrer. Documentation links are shown only for
  `https://docs.aws.amazon.com/` URLs. Files over 200 MB are refused.
- CloudShell script: snapshots are written with mode 0600, and the region
  argument must look like a region name.
- CLI: control characters from snapshot text are replaced in text output, so
  tags cannot inject terminal escape sequences.
- `.gitignore` now matches `pinhole-snapshot-*.json` (it previously only
  matched names starting with `snapshot`).
- CI: GitHub Actions pinned to commit SHAs, checkout without persisted
  credentials, `npm audit` on runtime dependencies, `pages: write` limited to
  the deploy job, and Dependabot for npm and Actions. Added SECURITY.md.

### Fixed
- Snapshots of VPCs with IPv6 were refused: the IPv6 network ACL `*` rule is
  number 32768, one above the IPv4 one.
- A what-if or diff no longer reports an attack chain as closed when its
  target became directly reachable from the internet; that is shown as new
  exposure instead.
- CI now runs on Node 22 and 24 (Node 20 is end of life and the test runner
  needs Node 21 or later). Node.js 22 is the minimum supported version.
  GitHub Actions updated to current major versions, still pinned by SHA.
- Transit gateway route search is not paginated by AWS. A route table with
  more than 1000 routes is now left out with a collection error, so paths
  through it are `unknown`, instead of being analysed from a partial list.
- Classic Load Balancers were silently skipped. They are now reported as a
  coverage warning (`classic-load-balancer`).

## [0.1.0] - M1: engine and internet exposure

### Added
- Snapshot format (schema version 1) that keeps AWS API field names, so the
  SDK collector, the CloudShell script and later the Terraform adapter emit
  the same file.
- `@pinhole/engine`, with no I/O and no dependencies:
  - security group evaluation: OR'ed allow rules, CIDR / prefix list / group
    references, reference scope across peering, inter-Region peering and
    transit gateways;
  - NACL evaluation: first match by rule number, the `*` rule, and port-range
    evaluation for ephemeral return traffic;
  - routing: longest prefix, static > prefix list > propagated, blackholes,
    VPC peering (non-transitive), transit gateway route tables, AZ coverage,
    and attachment-subnet NACL rules;
  - `evaluatePath()` with forward and return checks and a three-valued
    verdict;
  - `analyzeExposure()`: exact internet exposure per interface and per load
    balancer listener, with per-target reachability and NLB client IP
    preservation;
  - port risk ranking;
  - warnings for Network Firewall, Gateway Load Balancer, appliance routes,
    ingress routing, VPN, IPv6, Global Accelerator, CloudFront, and data
    missing from the snapshot.
- `@pinhole/collector`: read-only AWS SDK v3 collector with an operation
  allow-list; failed calls are recorded in the snapshot.
- `scripts/cloudshell-collect.sh`: collector that needs only the AWS CLI and jq.
- `docs/iam-policy.json`: the 26 read-only actions the collector uses.
- `pinhole` CLI: `collect`, `exposure` (text or JSON, `--min-severity`,
  `--fail-on`), `validate`.
- Eight fixtures with expected answers and AWS documentation links; unit and
  scenario tests; CI on Node 20 and 22; README pass count checked in CI.
- `docs/model.md`: every modelled behaviour with its documentation source.
- Static web page (`packages/web`, built to `site/index.html` with
  `npm run build:web`): drop a snapshot and get the exposure report, all in
  the browser, with no network access (enforced by Content Security Policy).
  Brought forward from M4 so the tool can be used without installing Node.
- GitHub Pages workflow that tests, builds and publishes the page.
- Web console:
  - Navigation between Overview (KPIs, highest risks, severity, exposed
    services), Exposure findings (sortable, filterable table with a detail
    panel: path trace with rule IDs, targets, what to change, every check with
    AWS doc links), Attack surface map (internet, way in, resources and
    targets, grouped by VPC), Coverage, and Connect an AWS account.
  - Connect an AWS account: six guided CloudShell steps, with copy-ready
    commands that follow the chosen regions, a paste-in command that writes
    the script, download and clean-up instructions, permissions, and
    troubleshooting.
  - Several snapshots (accounts and regions) loaded side by side; JSON and
    CSV export (CSV cells are protected against formula injection); light and
    dark themes; phone layout. IBM Plex is embedded (SIL OFL 1.1).
- The collector script now prints the full path of the snapshot and the next
  step when it finishes.

[Unreleased]: https://github.com/w3bcooki3/pinhole/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/w3bcooki3/pinhole/releases/tag/v0.2.0
