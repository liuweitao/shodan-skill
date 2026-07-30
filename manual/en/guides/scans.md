# Scans

Only scan targets you are authorized to assess. Validate the exact target list before execution and do not broaden a requested CIDR or address set.

## Reference and status commands

```bash
shodan-skill scan ports
shodan-skill scan protocols
shodan-skill scan list --page 1
shodan-skill scan status SCAN_ID
```

Ports and protocols return Shodan reference data. List and status read existing scan metadata.

## Submit an on-demand scan

Preview without a request:

```bash
shodan-skill --dry-run scan submit 192.0.2.10 --service 443:https
```

Execute the explicitly requested scan:

```bash
shodan-skill scan submit 192.0.2.10 --service 443:https
```

Targets accept validated IP addresses and CIDRs. Repeat `--service PORT:PROTOCOL` for custom services. `--force` requests the official SDK-compatible Enterprise re-scan behavior and is identified in the preview. On-demand scans can consume scan credits.

## Internet-wide scan

```bash
shodan-skill --dry-run scan internet 443 https
shodan-skill scan internet 443 https
```

Internet-wide scans require Enterprise access and have broad external impact. The deterministic preview identifies the operation, target scope, credit category, and reversibility before direct-mode execution.

In strict mode, append `--confirm --acknowledge-authorization` to the leaf command. In direct mode those compatibility options are not required.

Dynamic identifiers and path fragments are checked locally to prevent separators or traversal segments from altering the intended endpoint.

Official REST reference: <https://developer.shodan.io/api>
