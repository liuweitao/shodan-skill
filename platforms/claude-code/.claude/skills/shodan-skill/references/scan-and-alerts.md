# Scans, alerts, and notifiers

Read-only commands:

```text
shodan-skill scan list [--page N]
shodan-skill scan status <SCAN_ID>
shodan-skill alert list [--[no-]include-expired]
shodan-skill alert info <ALERT_ID> [--[no-]include-expired]
shodan-skill alert triggers
shodan-skill notifier list
shodan-skill notifier info <NOTIFIER_ID>
shodan-skill notifier providers
```

State-changing commands:

```text
shodan-skill scan submit <IP_OR_CIDR[,..]> [--service PORT:PROTOCOL] [--force]
shodan-skill scan internet <PORT> <PROTOCOL>
shodan-skill alert create <NAME> <NETWORK[,..]> [--expires SECONDS]
shodan-skill alert edit <ALERT_ID> <NETWORK[,..]>
shodan-skill alert delete <ALERT_ID>
shodan-skill alert trigger enable|disable <ALERT_ID> <TRIGGER[,TRIGGER...]>
shodan-skill alert trigger ignore|unignore <ALERT_ID> <TRIGGER> <IP:PORT>
shodan-skill alert notifier add|remove <ALERT_ID> <NOTIFIER_ID>
shodan-skill notifier create <PROVIDER> --arg NAME=VALUE --description TEXT
shodan-skill notifier edit <NOTIFIER_ID> --arg NAME=VALUE
shodan-skill notifier delete <NOTIFIER_ID>
```

Every mutation emits a deterministic JSON preview before sending HTTP. The preview includes the operation, identifiers, target count when calculable, credit impact, and reversibility. Default `direct` mode continues without confirmation or an authorization acknowledgement. Use `--dry-run` to stop after preview, or select `strict` mode to restore the compatibility gates.

On-demand scans can consume scan credits. Internet-wide scans require Enterprise access. Validate every target, custom service, alert/notifier ID, trigger, and ignored `IP:PORT` service before creating a transport. Reject separators and traversal segments in every dynamic URL path segment so the requested operation cannot be rewritten.

`--force` follows the official Python SDK's Enterprise re-scan option and is called out explicitly in the preview. `--include-expired` and `--no-include-expired` forward the official client alert-list/detail option without changing the default when omitted.

The REST API requires a nonblank notifier description in addition to the provider and provider arguments. Treat notifier arguments and alert responses as potentially secret; recursively redact routing keys, webhook URLs, tokens, and other credential-like values.

Official source: <https://developer.shodan.io/api>
