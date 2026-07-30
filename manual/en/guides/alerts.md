# Alerts and notifiers

Alerts monitor explicitly supplied networks. Creating or editing an alert does not authorize monitoring a network; confirm that you are permitted to monitor every target.

## Read alert state

```bash
shodan-skill alert list --include-expired
shodan-skill alert info ALERT_ID --no-include-expired
shodan-skill alert triggers
```

When the include-expired option is omitted, the service default is preserved.

## Manage alerts

```bash
shodan-skill alert create "Production" 192.0.2.0/24 --expires 0
shodan-skill alert edit ALERT_ID 192.0.2.0/24
shodan-skill alert delete ALERT_ID
shodan-skill alert trigger enable ALERT_ID new_service
shodan-skill alert trigger disable ALERT_ID new_service
shodan-skill alert trigger ignore ALERT_ID new_service 192.0.2.10:443
shodan-skill alert trigger unignore ALERT_ID new_service 192.0.2.10:443
```

Create, edit, delete, trigger, ignore, and notifier-attachment commands produce deterministic previews. Use root `--dry-run` to stop after validation.

## Manage notifiers

```bash
shodan-skill notifier list
shodan-skill notifier info NOTIFIER_ID
shodan-skill notifier providers
shodan-skill notifier create slack --arg webhook_url=https://example.invalid/synthetic --description "Synthetic example"
shodan-skill notifier edit NOTIFIER_ID --arg key=synthetic-value
shodan-skill notifier delete NOTIFIER_ID
shodan-skill alert notifier add ALERT_ID NOTIFIER_ID
shodan-skill alert notifier remove ALERT_ID NOTIFIER_ID
```

A notifier description is required when creating a notifier. Repeat `--arg NAME=VALUE` for provider parameters. Provider arguments often contain routing keys, webhook URLs, or tokens; keep them out of shell history where possible and never use real secrets in documentation or issue reports.

The CLI recursively redacts notifier secrets and alert responses, but the preview still identifies the requested object and operation. Deleting an alert or notifier and removing an attachment are destructive or state-changing actions.

Official REST reference: <https://developer.shodan.io/api>
