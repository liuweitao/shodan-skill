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
