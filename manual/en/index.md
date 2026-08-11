# Shodan Skill user guide

Shodan Skill is an unofficial, safety-focused command-line client and Agent Skill for the publicly documented Shodan REST, Streaming, Trends, and Exploits APIs. A single Python implementation provides consistent validation, transport, retry, timeout, output, and redaction behavior across supported agent platforms.

This project is not affiliated with, endorsed by, or sponsored by Shodan. You need your own Shodan account, API key, credits, and service entitlements for the operations you run.

## Start here

- Follow the [quick start](getting-started/quickstart.md) to install the package and run a read-only request.
- Read [safety, credits, and access](concepts/safety.md) before scans, alerts, downloads, streams, or Enterprise operations.
- Use the [command reference](reference/commands.md) for a compact list of all command paths.
- Open [troubleshooting](troubleshooting.md) when authentication, entitlement, timeout, or network failures occur.

## What the project covers

Version 2.0.1 maps and contract-tests the 58 operations re-enumerated from Shodan's public developer documentation on 2026-07-27: 45 REST, 8 Streaming, 3 Trends, and 2 Exploits operations. The CLI also provides a verified dataset-download workflow and local reference commands.

The raw documented HTTP APIs are canonical. The repository's machine-readable coverage manifest maps each documented operation to one CLI command and one mocked HTTP contract test. The official Python SDK is a compatibility reference, not a limit on HTTP coverage.

## Documentation boundaries

This guide explains user workflows and project-specific behavior. For exact response fields, use the linked Shodan developer documentation and Datapedia schemas. For exact options supported by an installed version, run:

```bash
shodan-skill --help
shodan-skill GROUP ACTION --help
```

The root README remains the installation and project overview. `SKILL.md` and `references/` are runtime material for agents and machine verification; they are not a second user manual.
