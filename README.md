# Shodan Skill

An unofficial, safety-focused command-line client and universal Agent Skill for the documented Shodan APIs. One portable `shodan-skill` implementation supports OpenClaw, Codex, Claude Code, and Hermes.

This project is not affiliated with, endorsed by, or sponsored by Shodan. Shodan names and service references are used only to describe API compatibility.

[English](README.md) | [Chinese](README_CN.md)

[Full documentation](https://liuweitao.github.io/shodan-skill/) | [Chinese documentation](https://liuweitao.github.io/shodan-skill/zh/)

The bilingual user manual contains task-oriented guides, command reference, recipes, and troubleshooting. This README remains the concise project and installation entry point.

## Verified scope

Version 2.0.0 maps and contract-tests all 58 operations re-enumerated from the official developer documentation on 2026-07-27:

- 45 REST operations covering hosts, search, DNS, scans, alerts, notifiers, datasets, organizations, account, and tools
- 8 Streaming operations with JSON Lines and SSE handling
- 3 Trends operations routed to the separate Trends service
- 2 Exploits operations routed to the Exploits service

Version 2.0.0 is the major portable rewrite following the earlier OpenClaw-only v1 release. Installation, command structure, output, API coverage, and safety behavior have changed; migrate existing workflows to the grouped CLI documented below.

The checked-in [official API snapshot](references/official-api-snapshot.yaml) records each operation, source URL, retrieval date, and normalized document hash. The coverage manifest maps every operation to a unique CLI command and a collected pytest contract node. The default suite is deterministic and offline: it does not require an API key, spend credits, scan a target, open a live stream, download live data, or mutate an account.

Raw documented HTTP APIs are canonical. See the [coverage manifest](references/api-coverage.yaml), [SDK compatibility baseline](references/sdk-baseline.md), and explicitly excluded [SDK-only convenience routes](references/sdk-only.md). Response-field references are linked from [data schemas](references/data-schemas.md), including Datapedia's banner schema and the official Exploits and Threatnet event specifications.

## Install and authenticate

Python 3.10 or newer is required.

```bash
python -m pip install .
shodan-skill --version
shodan-skill --help
```

For development:

```bash
python -m pip install -e ".[dev]"
```

Set the API key in the environment:

```bash
export SHODAN_API_KEY="your-key"
```

PowerShell:

```powershell
$env:SHODAN_API_KEY = "your-key"
```

The CLI can also reuse an official Shodan CLI configuration at `~/.shodan/api_key` or `~/.config/shodan/api_key`; the legacy path takes precedence when both exist. Never put a key in source files, prompts, fixtures, or command arguments that may be logged.

## Runtime controls

The CLI deliberately ignores ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `.netrc` settings. This prevents an inherited proxy from receiving Shodan query authentication unexpectedly. Configure a proxy only through `SHODAN_PROXY` or the explicit root option `--proxy`.

| Environment | Root option | Default | Constraint |
|---|---|---:|---|
| `SHODAN_CONNECT_TIMEOUT` | `--connect-timeout` | 10 s | finite, positive |
| `SHODAN_READ_TIMEOUT` | `--read-timeout` | 30 s | finite, positive |
| `SHODAN_WRITE_TIMEOUT` | `--write-timeout` | 30 s | finite, positive |
| `SHODAN_POOL_TIMEOUT` | `--pool-timeout` | 10 s | finite, positive |
| `SHODAN_STREAM_TIMEOUT` | `--stream-timeout` | 60 s | finite, positive |
| `SHODAN_RETRIES` | `--retries` | 2 | integer from 0 to 5 |
| `SHODAN_PROXY` | `--proxy` | disabled | absolute HTTP(S) proxy URL |
| `SHODAN_SAFETY_MODE` | `--safety-mode` | `direct` | `direct` or `strict` |

Root options must appear before the command group:

```bash
shodan-skill --read-timeout 45 --retries 1 host info 8.8.8.8
shodan-skill --proxy https://proxy.example:8443 search count "port:443"
```

Prefer `SHODAN_PROXY` over a command argument when a proxy URL contains credentials, because process arguments may be visible in shell history or process listings. Proxy credentials and API keys are redacted from parser failures, diagnostics, results, and exception output.

## Command groups

```text
host       Host information and history
search     Host search, count, facets, filters, and tokens
scan       Read scan metadata or submit scans
alert      Alerts, triggers, ignored services, and attached notifiers
notifier   Notification provider and notifier management
query      Community saved-query directory
dns        Domain history, resolve, and reverse lookup
tools      HTTP headers and caller public IP
account    Account profile, API plan, usage limits, and credit balances
stream     Banners, ASN, countries, ports, CVEs, alerts, and custom feeds
trends     Historical search, filters, and facets
exploits   Exploit search and count
data       Enterprise datasets, files, and verified downloads
org        Enterprise organization information and membership
reference  Local links to current filters, schemas, and Datapedia
```

Use `shodan-skill account api-info` for API-plan details, usage limits, and remaining query or scan credits. Use `shodan-skill account profile` only for membership and profile metadata; its generic `credits` field is not the API query- or scan-credit balance.

Examples:

```bash
shodan-skill host info 8.8.8.8
shodan-skill search hosts "product:nginx" --facets country:5
shodan-skill search count "port:443"
shodan-skill dns domain example.com --history
shodan-skill exploits search apache --page 2 --omit-code
shodan-skill stream ports 22,443 --limit 10
```

Use `shodan-skill GROUP ACTION --help` for the complete parameter contract. Deprecated underscore command names remain compatibility aliases and emit a warning.

## Safety and account requirements

The CLI and Skill default to `direct` mode. An explicit command or user request executes after local validation without a second confirmation for credits, state changes, downloads, scans, or monitored networks. Operations with deterministic previews write them to stderr and continue immediately. Use root-level `--dry-run` to validate and preview without sending a request.

Set `SHODAN_SAFETY_MODE=strict` or pass root-level `--safety-mode strict` to restore the previous confirmation behavior. In strict mode, use `--confirm` or `--yes`; scans and monitored networks additionally require `--acknowledge-authorization`. Existing confirmation options remain accepted in direct mode for script compatibility. Abbreviations such as `--y`, `--conf`, and `--ack` remain rejected.

Search filters, extra search pages, DNS domain lookups, and scans may consume credits according to Shodan's rules. Internet scans, global/custom streams, Trends, datasets, and organization operations require the applicable Enterprise entitlement. The CLI maps authentication, authorization, credit, timeout, network, API, and integrity failures to nonzero exit codes. A configured API key does not cause unstated operations to run.

Credit-consuming GET requests are not retried automatically, preventing a transient failure from multiplying credit impact. No-credit GET requests retain bounded retry and `Retry-After` handling.

Dataset downloads stream to a `.part` file, support bounded HTTP Range resume, verify size and available SHA-1 metadata by default, and finalize without clobbering a destination that appears during the download. Existing partial and final files require explicit `--resume` or `--overwrite` behavior.

## Output and exit codes

Non-streaming stdout defaults to a stable JSON envelope:

```json
{
  "ok": true,
  "data": {},
  "meta": {
    "command": "host-info",
    "credits_used": null,
    "credit_impact": "none",
    "credits_estimated": null
  },
  "error": null
}
```

`credit_impact` is one of `none`, `conditional`, `query`, `scan`, or `unknown`. `credits_estimated` is populated only when the CLI can determine a conservative count before the request. The backward-compatible `credits_used` field remains `null` because Shodan responses do not provide authoritative per-request usage; it must not be interpreted as zero.

Streams emit one envelope per JSON Line by default. `--stream-format sse` requests the official SSE representation and emits each envelope as an SSE `data:` event. Finite-timeout streams disable server heartbeat messages so a quiet feed cannot mask the idle timeout. `--debug` requests Shodan discard diagnostics with `debug=1`; diagnostics and mutation previews go to stderr. Select `--output json`, `--output jsonl`, or `--output human` where applicable.

| Exit | Meaning |
|---:|---|
| 0 | Success |
| 2 | Usage or strict-mode safety gate |
| 3 | Authentication |
| 4 | Authorization or entitlement |
| 5 | Credits |
| 6 | Network |
| 7 | API, download, or integrity error |
| 8 | Timeout |
| 9 | Interrupted stream or operation |
| 10 | Unexpected internal error |

API keys, credential-like fields, bearer tokens, authorization headers, cookies, notifier secrets, webhook URLs, and signed-URL credentials are recursively redacted. The Shodan key is passed as query authentication internally but never displayed in a URL.

## Documentation drift and schemas

Check the live official documentation against the checked-in snapshot:

```bash
python scripts/refresh_official_snapshot.py --check
```

This read-only command needs network access but makes no Shodan API request. If the official pages intentionally changed, regenerate and review the inventory before updating the coverage manifest:

```bash
python scripts/refresh_official_snapshot.py --write
python scripts/verify_coverage.py --require-complete
```

A scheduled GitHub workflow performs the drift check weekly. `shodan-skill reference datapedia` also returns direct links to the Datapedia overview, banner JSON schema, and changelog without requiring a key.

## Agent platform bundles

Generate and verify every adapter from the root `SKILL.md`:

```bash
python scripts/build_bundles.py
python scripts/verify_skill.py
```

Install one generated bundle into a platform discovery layout:

```bash
python scripts/install_skill.py --platform codex
python scripts/install_skill.py --platform openclaw
python scripts/install_skill.py --platform claude-code
python scripts/install_skill.py --platform hermes
```

The installer prompts before replacing an existing installation. Pass `--yes` only when replacement is intended. Install the CLI package separately so agents can invoke `shodan-skill` without knowing the Skill directory.

## Tests, security, and releases

Mandatory offline checks:

```bash
python -m pytest
python -m pytest --cov=shodan_skill --cov-report=term-missing --cov-fail-under=90
python -m ruff check .
python -m ruff format --check .
python -m mypy src/shodan_skill
python scripts/verify_coverage.py --require-complete
python scripts/verify_skill.py
python scripts/verify_manual.py
python scripts/verify_release.py
python -m build
```

Build the bilingual documentation site after installing its pinned dependencies:

```bash
python -m pip install --requirement requirements-docs.txt
python -m mkdocs build --strict
```

The coverage verifier also runs `pytest --collect-only` and rejects a manifest entry whose operation-specific contract node is missing or reused. GitHub CI covers Python 3.10, 3.12, and 3.14 on Linux, Windows, and macOS. CodeQL, dependency updates, an official-doc drift monitor, release checksums, a CycloneDX SBOM, and GitHub build provenance are configured. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

CI runs the complete quality, coverage, bundle-drift, and packaging gate once on Linux, while a separate matrix runs compatibility tests across all supported Python and operating-system combinations. Pushing a version tag such as `v2.0.0` starts the release workflow; the workflow validates the tag and all release gates before it creates or updates the GitHub Release and attaches the verified artifacts.

Live verification is disabled by default and requires explicit user authorization plus independent environment and pytest gates:

- `SHODAN_LIVE_TESTS=1` and `--allow-live-shodan` for authorized read-only checks
- `--allow-shodan-credits` for credit-consuming checks
- `SHODAN_MUTATING_TESTS=1` and `--allow-shodan-mutations` for separately authorized mutations
- `SHODAN_ENTERPRISE_TESTS=1` for an entitled Enterprise account
- `SHODAN_TEST_TARGETS` containing only authorized scan or monitoring targets

No environment variable, configured key, or test flag by itself authorizes a live scan, mutation, stream, download, or credit-consuming request. Ordinary `python -m pytest` leaves all real-API tests explicitly skipped.

## License

MIT
