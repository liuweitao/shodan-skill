# Search, hosts, and saved queries

Use these read-only commands with an authenticated Shodan account:

```text
shodan-skill host info <IP> [--history] [--minify]
shodan-skill search hosts <QUERY> [--page N] [--facets LIST] [--[no-]minify] [--fields LIST] [--limit N]
shodan-skill search count <QUERY> [--facets LIST]
shodan-skill search facets
shodan-skill search filters
shodan-skill search tokens <QUERY>
shodan-skill query list [--page N] [--sort votes|timestamp] [--order asc|desc]
shodan-skill query search <TERM> [--page N]
shodan-skill query tags [--limit N]
shodan-skill scan ports
shodan-skill scan protocols
```

`search hosts` can consume one query credit when the query contains a filter and additional credits for pages after the first. It displays a credit preview and executes directly by default; use `--dry-run` to preview without sending. The credit-consuming request is not automatically retried. `search count` does not consume query credits. `--limit` truncates the returned `matches` locally and does not change the documented API request. Host information, search metadata, saved-query directory methods, ports, and protocols are read-only.

Validate IPs locally, including IPv6. Require page and limit values of at least 1. Send `fields`, `facets`, `minify`, and history parameters without silently changing their API meaning. Consult the current dynamic filters and facets endpoints rather than a hand-maintained list.

Official source: <https://developer.shodan.io/api>
