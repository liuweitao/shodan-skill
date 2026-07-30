# DNS, account, and tools

Use these commands:

```text
shodan-skill dns domain <DOMAIN> [--history] [--type A|AAAA|CNAME|NS|SOA|MX|TXT] [--page N]
shodan-skill dns resolve <DOMAIN[,DOMAIN...]>
shodan-skill dns reverse <IP[,IP...]>
shodan-skill tools httpheaders
shodan-skill tools myip
shodan-skill account profile
shodan-skill account api-info
```

Route requests for an API plan, usage limits, quotas, remaining credits, credit balances, query credits, or scan credits to `account api-info`. Use `account profile` only for membership and profile metadata such as the display name and creation time. The profile response can contain a generic `credits` field; do not interpret it as the remaining query- or scan-credit balance.

Domain information consumes one query credit per lookup, so the CLI displays a credit preview, executes directly by default, and does not automatically retry the credit-consuming request. Use `--dry-run` to preview without sending. Resolve, reverse, HTTP-header, public-IP, account-profile, and API-plan requests are read-only. `account profile` maps to `/account/profile`; `account api-info` maps separately to `/api-info`.

Validate domains, IPv4/IPv6 values, record types, and positive page numbers before making a request. Treat returned headers and account information as potentially sensitive and apply recursive redaction before output.

Use the official Datapedia [banner JSON Schema](https://datapedia.shodan.io/banner.schema.json) and [schema changelog](https://datapedia.shodan.io/changelog.html) for banner fields instead of a partial embedded dictionary. Load the root Skill's official-data-schemas reference when schema-selection guidance is needed.

Official API source: <https://developer.shodan.io/api>
