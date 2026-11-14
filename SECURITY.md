# Security

## Reporting a vulnerability

Please report security problems privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, and do not attach real snapshots to any report; a hand-written snapshot that shows the problem is enough.

You can expect an acknowledgement within a week. Fixes are released as a new version and noted in the changelog.

## What Pinhole does with your data

**Collection is read-only.**

- `docs/iam-policy.json` grants only `Describe*`, `Get*` and `Search*` actions on EC2 and Elastic Load Balancing.
- The SDK collector imports only those commands, and refuses to call any operation whose name is not read-only. A test checks that the policy and the collector's command list match exactly.
- The CloudShell script calls only `describe-*`, `get-*` and `search-*` commands, and uses the credentials CloudShell already has. It stores no credentials anywhere.

**Snapshots stay where you put them.**

- The CLI and the CloudShell script write snapshots with file mode 0600.
- Nothing is uploaded. The web console reads files with the browser's file reader and analyses them in the tab.
- The console's Content Security Policy blocks all network connections (`default-src 'none'`, `connect-src 'none'`) and allows only its own script, by SHA-256 hash.
- Snapshot content is inserted into the page as text, never as HTML.
- Links to AWS documentation are shown only for `https://docs.aws.amazon.com/` URLs.
- The theme choice (light or dark) is the only thing stored in the browser.

**What a snapshot contains.**

- VPCs, subnets, route tables, gateways, network ACLs, security groups and their rules, prefix lists, network interfaces, instances and load balancers, with their tags.
- No instance data, user data, secrets, logs or object storage.
- Tags can hold sensitive values, so treat the whole file as confidential.

## Supply chain

- The engine has no runtime dependencies. The collector depends only on the AWS SDK for JavaScript v3.
- CI runs `npm audit` on runtime dependencies.
- GitHub Actions are pinned to commit SHAs. Dependabot proposes weekly updates for both npm packages and Actions.
- The Pages workflow grants `pages: write` only to its deploy job.
