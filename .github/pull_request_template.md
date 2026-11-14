## What this changes

<!-- One or two sentences. Link the issue it fixes, if any: "Fixes #12". -->

## How it was checked

- [ ] `npm test` passes
- [ ] New or changed behaviour has a test (and a fixture, for a change in AWS evaluation)
- [ ] AWS behaviour is backed by a link to the AWS documentation in a code comment or fixture README
- [ ] `CHANGELOG.md` has an entry under "Unreleased", if users will notice

## Safety

- [ ] Collection stays read-only (no new AWS calls other than `Describe*`, `Get*`, `Search*`)
- [ ] No real snapshot, account ID, credential or IP address is included
- [ ] Snapshot text is only ever inserted into pages as text, and quoted in generated commands
