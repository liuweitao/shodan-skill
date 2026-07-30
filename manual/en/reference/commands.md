# Command reference

This is a compact path and option index, not a replacement for `shodan-skill GROUP ACTION --help`. Root options such as `--output`, `--dry-run`, timeouts, retries, proxy, and safety mode must appear before the group.

## Host and search

| Command | Main leaf arguments |
|---|---|
| `shodan-skill host info IP` | `--history`, `--minify` |
| `shodan-skill search hosts QUERY` | `--page`, `--facets`, `--[no-]minify`, `--fields`, `--limit` |
| `shodan-skill search count QUERY` | `--facets` |
| `shodan-skill search facets` | None |
| `shodan-skill search filters` | None |
| `shodan-skill search tokens QUERY` | None |

## Scan

| Command | Main leaf arguments |
|---|---|
| `shodan-skill scan submit IPS` | `--service`, `--force` |
| `shodan-skill scan internet PORT PROTOCOL` | Enterprise |
| `shodan-skill scan list` | `--page` |
| `shodan-skill scan status ID` | None |
| `shodan-skill scan ports` | None |
| `shodan-skill scan protocols` | None |

## Alerts

| Command | Main leaf arguments |
|---|---|
| `shodan-skill alert list` | `--[no-]include-expired` |
| `shodan-skill alert info ID` | `--[no-]include-expired` |
| `shodan-skill alert triggers` | None |
| `shodan-skill alert create NAME NETWORKS` | `--expires` |
| `shodan-skill alert edit ID NETWORKS` | None |
| `shodan-skill alert delete ID` | Destructive |
| `shodan-skill alert trigger enable ID TRIGGER` | None |
| `shodan-skill alert trigger disable ID TRIGGER` | None |
| `shodan-skill alert trigger ignore ID TRIGGER SERVICE` | None |
| `shodan-skill alert trigger unignore ID TRIGGER SERVICE` | None |
| `shodan-skill alert notifier add ID NOTIFIER_ID` | None |
| `shodan-skill alert notifier remove ID NOTIFIER_ID` | None |

## Notifiers

| Command | Main leaf arguments |
|---|---|
| `shodan-skill notifier list` | None |
| `shodan-skill notifier info ID` | None |
| `shodan-skill notifier providers` | None |
| `shodan-skill notifier create PROVIDER` | `--arg NAME=VALUE`, required `--description` |
| `shodan-skill notifier edit ID` | `--arg NAME=VALUE` |
| `shodan-skill notifier delete ID` | Destructive |

## Saved queries, DNS, account, and tools

| Command | Main leaf arguments |
|---|---|
| `shodan-skill query list` | `--page`, `--sort`, `--order` |
| `shodan-skill query search QUERY` | `--page` |
| `shodan-skill query tags` | `--limit` |
| `shodan-skill dns domain DOMAIN` | `--history`, `--type`, `--page` |
| `shodan-skill dns resolve HOSTNAMES` | Comma-separated |
| `shodan-skill dns reverse IPS` | Comma-separated |
| `shodan-skill account profile` | None |
| `shodan-skill account api-info` | None |
| `shodan-skill tools httpheaders` | None |
| `shodan-skill tools myip` | None |

## Streaming

Every stream supports `--limit`, `--stream-format`, `--debug`, `--reconnect`, and `--max-reconnects`.

| Command | Selector |
|---|---|
| `shodan-skill stream banners` | Global banners |
| `shodan-skill stream asn ASNS` | Comma-separated ASNs |
| `shodan-skill stream countries COUNTRIES` | Comma-separated country codes |
| `shodan-skill stream ports PORTS` | Comma-separated ports |
| `shodan-skill stream vulns VULNS` | Comma-separated CVEs |
| `shodan-skill stream alerts` | Account alert feed |
| `shodan-skill stream alert ID` | One alert feed |
| `shodan-skill stream custom QUERY` | Custom query |

## Trends and Exploits

| Command | Main leaf arguments |
|---|---|
| `shodan-skill trends search QUERY` | `--facets` |
| `shodan-skill trends filters` | None |
| `shodan-skill trends facets` | None |
| `shodan-skill exploits search QUERY` | `--page`, `--facets`, `--limit`, `--omit-code`, `--truncate-code` |
| `shodan-skill exploits count QUERY` | `--facets` |

## Enterprise data and organization

| Command | Main leaf arguments |
|---|---|
| `shodan-skill data list` | None |
| `shodan-skill data files DATASET` | None |
| `shodan-skill data download DATASET NAME` | `--output-file`, `--resume`, `--overwrite`, `--[no-]verify`, `--chunk-size` |
| `shodan-skill org info` | None |
| `shodan-skill org member add USER` | `--[no-]notify` |
| `shodan-skill org member remove USER` | Destructive |

## Local references

| Command | Result |
|---|---|
| `shodan-skill reference filters` | Current official filter reference link |
| `shodan-skill reference datapedia` | Datapedia overview, schema, and changelog links |

Mutation commands also accept strict-mode compatibility flags where applicable. Run leaf help for the exact contract supported by your installed version.
