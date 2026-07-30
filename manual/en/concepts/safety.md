# Safety, credits, and access

## Direct mode

The CLI and Agent Skill default to `direct`. An explicit command or natural-language operation request is the instruction to execute that operation after local validation. Credit use, mutations, downloads, scans, monitored networks, streams, and Enterprise operations do not receive a second confirmation prompt.

Operations with deterministic previews write them to stderr and continue. To stop after validation and preview without constructing a transport, place `--dry-run` before the command group:

```bash
shodan-skill --dry-run scan submit 192.0.2.10
```

Never expand a target list or initiate an operation that the user did not request. An API key or account entitlement makes an operation possible; it does not request the operation.

## Strict compatibility mode

Select strict mode explicitly:

```bash
shodan-skill --safety-mode strict scan submit 192.0.2.10 \
  --confirm --acknowledge-authorization
```

Strict mode enforces `--confirm` or `--yes`. Scans and monitored networks additionally require `--acknowledge-authorization`. These options must be written in full; abbreviations such as `--y`, `--conf`, and `--ack` are rejected. The options remain accepted in direct mode for script compatibility.

## Credit impact

- Filtered host searches and pages after the first may use query credits.
- DNS domain information uses one query credit per lookup.
- On-demand scans can use scan credits.
- `search count`, host details, metadata, account, and tools requests do not consume query credits according to the documented contract.
- Credit-consuming GET requests are not automatically retried.

The output metadata reports `credit_impact` and, only when a conservative value can be calculated before the request, `credits_estimated`. The compatibility field `credits_used` remains `null`; it must not be interpreted as zero.

## Entitlements and authorization

Internet-wide scans, most global or filtered streams, Trends, datasets, and organization operations require applicable Enterprise or service entitlement. Alert streams can be available to accounts with alerts. Authorization error `4` is expected when a valid account lacks the requested entitlement.

Only scan or monitor targets you are authorized to assess. Use test and documentation addresses such as `192.0.2.0/24` for examples, not as live scan instructions.
