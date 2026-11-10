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

The weekly official-documentation job retries transient network and selected HTTP failures up to three times.
Permanent failures or invalid documents fail without replacing the accepted snapshot. Each run publishes an
`official-documentation-review` artifact containing the report and candidate snapshot.

When upstream content changes, the job maintains one PR from `automation/official-documentation`. Its write
permissions are limited to repository contents and PRs; the commit allowlist contains the canonical snapshot,
the coverage manifest, and generated platform copies. The preparation helper changes only the manifest retrieval
date, preserving implementation and test claims. New operations therefore leave coverage checks failing until
someone implements and reviews the new contract. No content or retrieval-date-only change means no update PR.
A successfully created review PR handles drift without a repeated red scheduled job; fetch or PR-creation errors
still fail visibly. The report and candidate artifact are uploaded even after failure.

Review changed official sources even when all method/path pairs match: hashes cannot distinguish parameter,
permission, credit, and response-contract changes. Documentation PRs are never automatically merged. GitHub may
require approval before running PR checks created by `GITHUB_TOKEN`; approve those checks during human review.
Do not bypass the required checks or add a personal token merely to remove this review step.

Every PR exercises the release extra, an isolated wheel installation, and actual CycloneDX SBOM generation.
`Required CI` aggregates quality, all nine OS/Python combinations, and release smoke; a failed or skipped
prerequisite fails the aggregate. The bilingual manual builds on every PR so it can be a required check.
Dependabot groups only minor/patch updates; major upgrades remain separate for review.

### Approved automation and repository settings

The approved policy is implemented by `dependabot-automerge.yml` and `docs-drift.yml`. Repository settings are
recorded in `.github/maintenance-settings.json` and must be applied by a credential with Administration:write
and Actions:write permissions, or in the corresponding GitHub settings pages:

1. Enable `allow_auto_merge`. Convert the classic `master` protection to an active branch ruleset, leave its
   bypass list empty (including administrators), and retain strict/up-to-date required checks
   `Required CI`, `Build bilingual manual`, `Analyze Python` (GitHub Actions app ID 15368), and `CodeQL` (GitHub
   Code Scanning app ID 57789). Require PR conversation resolution (zero mandatory approvals is sufficient);
   enable deletion and non-fast-forward protection. The exact ruleset is recorded in the settings JSON.
2. Keep default workflow permissions read-only and enable Actions to create pull requests. This GitHub setting
   is named “Allow GitHub Actions to create and approve pull requests”; none of these workflows approves PRs.
   Only the two specific automation jobs declare their required contents/PR write permissions.
3. The Dependabot workflow handles same-repository, non-draft PRs targeting the default branch. It never checks
   out PR code. The pinned metadata action verifies Dependabot identity and signed commits. Only verified
   semver minor/patch updates in the configured ecosystems, without maintainer changes, can queue auto-merge.
4. Before queueing `gh pr merge --auto --squash --match-head-commit`, the workflow reads effective protection
   through Metadata-readable REST rules endpoints and requires an active no-bypass ruleset and every setting
   and check source above. Classic protection details require Administration:read, which GITHUB_TOKEN lacks.
   Missing, unreadable, or weakened
   protection fails closed. Major upgrades and unknown metadata remain manual. Native branch protection
   enforces the full current checks before a merge can happen.

Official guidance: [Dependabot automation](https://docs.github.com/en/code-security/tutorials/secure-your-dependencies/automate-dependabot-with-actions)
and [workflow event/token rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

Automatic source-code fixes, widening failing assertions, live Shodan calls, credit-consuming operations,
major dependency upgrades, and releases stay outside this policy. Release publishing retains the existing
version-tag and environment gates.

The read-only `Audit maintenance protection` job reuses the production gate, without checking out code or
queueing merges. It runs when the policy workflow changes and can be requested with the fixed
`maintenance-audit` repository-dispatch event. `official-documentation-check` requests a documentation run.
These events require authenticated repository write access to trigger; they do not grant runtime permissions.
Audit and PR-target runs use separate concurrency groups so one cannot cancel the other.
