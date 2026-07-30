# Discovery and DNS

## Host details and search

Read a host record, optionally including history or a minified response:

```bash
shodan-skill host info 8.8.8.8
shodan-skill host info 8.8.8.8 --history --minify
```

Search, count, or inspect current query metadata:

```bash
shodan-skill search hosts "product:nginx" --page 1 --facets country:5
shodan-skill search count "port:443" --facets country:5
shodan-skill search facets
shodan-skill search filters
shodan-skill search tokens "product:nginx"
```

`search hosts --limit N` truncates returned matches locally; it does not rewrite the documented API request. `--fields`, `--facets`, `--minify`, and pagination are forwarded without silent semantic changes. Consult the dynamic filters and facets endpoints instead of relying on a copied static list.

## Saved-query directory

```bash
shodan-skill query list --page 1 --sort timestamp --order desc
shodan-skill query search nginx --page 1
shodan-skill query tags --limit 10
```

These commands browse the community query directory. Treat a saved query as input to review, not as authority to scan or monitor a target.

## DNS

```bash
shodan-skill dns domain example.com --history --type A --page 1
shodan-skill dns resolve example.com,example.net
shodan-skill dns reverse 8.8.8.8,1.1.1.1
```

Domain information consumes one query credit per lookup. Resolve and reverse lookup are read-only. Domains, IPv4/IPv6 values, record types, and positive page values are validated locally.

## Account, tools, and local references

```bash
shodan-skill account profile
shodan-skill account api-info
shodan-skill tools httpheaders
shodan-skill tools myip
shodan-skill reference filters
shodan-skill reference datapedia
```

`account api-info` is the correct command for plan and remaining query or scan credits. A generic `credits` field in another response is not an authoritative balance. Returned headers, account details, and DNS information can be sensitive; retain the default redaction behavior.

Official REST reference: <https://developer.shodan.io/api>
