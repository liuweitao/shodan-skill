---
name: shodan-skill
description: Use the installed shodan-skill CLI for documented Shodan REST, Streaming, Trends, and Exploits operations, including host intelligence, search and facets, DNS, scans, alerts, notifiers, bulk datasets, organizations, API-plan and credit-balance checks, and real-time feeds. Trigger for Shodan lookups, exposure research, scan or monitoring requests, API coverage questions, and Shodan account or Enterprise workflows. Treat the user's explicit request as the instruction to execute it without a second confirmation; never infer an unstated operation from an API key.
---

# Shodan Skill

Use `shodan-skill` as the single implementation on every supported agent platform.

## Run the workflow

1. Confirm the command is installed with `shodan-skill --help`. If it is missing, direct the user to install this package before attempting an API operation.
2. Use `SHODAN_API_KEY` or the official Shodan CLI configuration for authentication. Never request that a key be pasted into a command, prompt, source file, or log.
3. Identify whether the request is read-only, credit-consuming, state-changing, destructive, or Enterprise-only. Consult [API coverage](references/api-coverage.yaml) for the exact method, path, access class, credit impact, and collected contract test. Use the [official API snapshot](references/official-api-snapshot.yaml) when checking whether the inventory matches the last retrieved documentation.
4. Translate the request to the grouped kebab-case CLI. Prefer `shodan-skill GROUP ACTION --help` when parameters are uncertain.
5. Route API-plan, usage-limit, quota, remaining-credit, credit-balance, query-credit, and scan-credit requests to `shodan-skill account api-info`. Use `shodan-skill account profile` only for membership and profile metadata. Never treat the profile response's generic `credits` field as the query- or scan-credit balance.
6. Treat an explicit user request as the instruction to execute that operation, including credits, mutations, downloads, scans, monitoring, streams, and Enterprise operations. Do not ask for a second confirmation or authorization acknowledgement.
7. Use the default `direct` safety mode. The CLI emits deterministic previews for applicable operations and continues immediately. Use `--dry-run` only when the user asks to preview without execution. Use `strict` mode only when the user explicitly requests it.
8. Validate every target and dynamic path segment locally, and do not add operations or expand targets beyond what the user requested. Treat Streaming and Enterprise entitlements as account requirements.
9. Parse stdout as the stable JSON envelope, JSON Lines for default streams, or SSE `data:` events when `--stream-format sse` is selected. Treat stderr as diagnostics and preserve nonzero exit codes. Never expose redacted values, signed URLs, authorization headers, cookies, or API keys.
10. Report skipped live verification honestly. Keep repository live-test gates separate from normal CLI execution; do not interpret a configured test environment as a request to run live tests.

## Choose the focused reference

- Read [search and host](references/search-and-host.md) for host intelligence, search, count, pagination, facets, filters, tokens, and saved queries.
- Read [DNS and tools](references/dns-and-tools.md) for DNS, account, ports, protocols, public IP, HTTP headers, and official data-field references.
- Read [scans and alerts](references/scan-and-alerts.md) for scans, alerts, triggers, notifiers, and their request forms.
- Read [streaming](references/streaming.md) for feeds, JSONL/SSE, limits, idle timeouts, and reconnects.
- Read [Trends and Exploits](references/trends-and-exploits.md) for the separate Trends and Exploits services.
- Read [Enterprise](references/enterprise.md) for datasets, verified downloads, organizations, and entitlement boundaries.
- Read [official data schemas](references/data-schemas.md) for banner, exploit, and Threatnet event shapes.
- Read the [official SDK baseline](references/sdk-baseline.md) and [SDK-only operations](references/sdk-only.md) only for compatibility or API-coverage questions.
- Read [safety](references/safety.md) before any credit-consuming, state-changing, destructive, scanning, monitoring, or download operation.

Use deprecated underscore aliases only to preserve an existing workflow. Generate new instructions and examples with the grouped interface.
