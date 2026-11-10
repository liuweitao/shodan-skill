# Troubleshooting

## Command or option is rejected

Root options must come before the command group:

```bash
shodan-skill --output human --read-timeout 45 host info 8.8.8.8
```

Use `shodan-skill GROUP ACTION --help` for the installed parameter contract. Long-option abbreviations are rejected intentionally. Deprecated underscore command names may emit a compatibility warning.

## Authentication failure, exit 3

Check that `SHODAN_API_KEY`, `~/.shodan/api_key`, or `~/.config/shodan/api_key` contains the intended key. Do not print the key while diagnosing. If both files exist, the legacy `.shodan` path wins.

## Authorization failure, exit 4

The account is authenticated but lacks an entitlement or permission. Common cases include global streams, Trends, datasets, organization membership, and Internet-wide scans. Confirm the account plan with `shodan-skill account api-info`.

## Credit failure, exit 5

Review the account balance and requested operation. Credit-consuming GET requests are not automatically retried. Do not assume a failed request is safe to repeat until the service result and account state have been reviewed.

## Network or timeout failure, exits 6 and 8

The CLI ignores ambient proxies. If your network requires a proxy, set a reviewed `SHODAN_PROXY` value or root `--proxy`. Adjust the finite connect/read/stream timeouts only when the expected service behavior justifies it.

For a stream, a clean EOF before `--limit` is reached is still a network failure. Use bounded reconnects when continuation is desired.

## Download or integrity failure, exit 7

Keep the `.part` file for an intentional `--resume`, or use `--overwrite` only when replacing it is acceptable. A size or SHA-1 mismatch prevents finalization. Avoid `--no-verify` unless integrity metadata is knowingly unsuitable and the risk is accepted.

## Strict-mode gate, exit 2

Add the exact `--confirm` or `--yes` option. Scans and monitored networks also need the exact `--acknowledge-authorization` option. Alternatively, return to the default direct mode if that is the intended policy.

## Reporting a problem

Include the version, platform, command structure with secrets removed, exit code, and redacted stderr. Never attach an API key, proxy credential, signed URL, notifier secret, account response, or unreviewed host dataset. Report security issues privately through the repository's security policy.

## Repository maintenance and failed Actions

The weekly official-documentation check keeps a failing status for real upstream drift. Before investigating,
open its job summary and download the `official-documentation-review` artifact. It contains a candidate snapshot
and an explanation of changed text and added/removed operations. Transient network and selected HTTP failures
retry up to three times; permanent HTTP failures fail immediately. A fetch failure never replaces the accepted snapshot.

Review changed official sources even when all method/path pairs match: hashes cannot distinguish parameter,
permission, credit, and response-contract changes. After accepting the candidate, synchronize `references/api-coverage.yaml` field `official_retrieved` with the
snapshot retrieval date. Then regenerate platform bundles with
`python scripts/build_bundles.py` and run all verification scripts. `--write` leaves an unchanged snapshot untouched,
including its retrieval date, so a weekly check does not create date-only updates.

Every PR now exercises the release extra, an isolated wheel installation, and actual CycloneDX SBOM generation.
`Required CI` aggregates quality, all nine OS/Python combinations, and the release smoke test; a failed or skipped
prerequisite fails the aggregate. The bilingual documentation build runs on every PR so it can be a required check.
Dependabot groups only minor/patch updates; major upgrades remain separate for review.

### Proposed write-enabled automation (requires repository-owner approval)

The current workflows retain read-only repository permissions. No automatic merges, approvals, or snapshot PRs
are enabled by this change. Before enabling them, review and approve these concrete settings and policies:

1. Enable repository `allow_auto_merge` and protect `master`, including administrators, with strict/up-to-date
   required checks `Required CI`, `Build bilingual manual`, `Analyze Python` (GitHub Actions app ID 15368),
   and `CodeQL` (GitHub Code Scanning app ID 57789). Block force pushes and branch deletion. Do not bypass gates.
2. Add a `pull_request_target` workflow limited to same-repository Dependabot PRs targeting the default branch.
   Do not check out or execute PR code. Pin `dependabot/fetch-metadata` to a reviewed full commit SHA, keep its
   signed-commit verification, and only queue `gh pr merge --auto --squash --match-head-commit` for verified
   semver minor/patch metadata without maintainer changes. Unknown metadata and major upgrades remain manual.
   The workflow must fail closed if required-check protection is absent. Do not auto-approve changes.
3. Allow the docs drift job `contents: write` and `pull-requests: write` solely to maintain one fixed snapshot PR
   branch. Restrict changed files to the canonical snapshot, the coverage-manifest retrieval date, and regenerated platform copies. Include the report,
   run normal CI, and require human review; never auto-merge upstream text or operation changes. Creating a PR
   with `GITHUB_TOKEN` can leave its checks waiting for approval under GitHub's event rules. A dedicated narrowly
   scoped GitHub App token can remove that extra approval if unattended CI is required; never store a personal
   token in source or bypass the CI gates.

Keep automatic source-code fixes, widening failing assertions, live Shodan calls, credit-consuming operations,
major dependency upgrades, and releases outside this policy. A failed test is evidence to investigate, not a
reason for an action to weaken validation. Release publishing stays behind the existing tag and environment gates.
