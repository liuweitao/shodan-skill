# Agent platforms

The canonical architecture is:

```text
Natural-language request
  -> platform Skill
  -> installed shodan-skill CLI
  -> shared validation, safety, transport, output, and redaction
  -> Shodan services
```

Install the Python CLI first. Then install one generated Skill bundle into the platform discovery layout:

```bash
python scripts/install_skill.py --platform codex
python scripts/install_skill.py --platform openclaw
python scripts/install_skill.py --platform claude-code
python scripts/install_skill.py --platform hermes
```

The installer prompts before replacing an existing bundle. Use `--yes` only when replacement is intended. Platform bundles are generated from the root `SKILL.md` and focused references; do not edit a generated bundle by hand.

## Request behavior

An explicit natural-language operation request is handled like an explicit CLI command under the configured safety mode. The agent must validate the stated targets, preserve scope, and use the installed CLI. A configured key, available credits, or Enterprise entitlement does not authorize an unstated operation.

Examples:

```text
Show the current Shodan record for 8.8.8.8.
Count hosts matching port:443 without running a full host search.
Dry-run a Shodan scan request for the target I explicitly authorized.
Stream ten records for ports 22 and 443.
```

The Agent Skill uses progressive references for search, scans, streaming, Enterprise services, schemas, and safety. User-facing workflows belong in this manual; the platform bundle remains concise and operational.
