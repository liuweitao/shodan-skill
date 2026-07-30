# Trends and Exploits

These command groups use separate service hosts and must not be routed through ordinary host search endpoints.

## Trends

```bash
shodan-skill trends search "product:nginx" --facets country:10
shodan-skill trends filters
shodan-skill trends facets
```

Trends uses `https://trends.shodan.io` and requires the applicable Trends or Enterprise entitlement. The documented search contract exposes `query` and optional `facets`. The CLI does not invent undocumented time-range parameters.

Official reference: <https://developer.shodan.io/api/trends>

## Exploits

```bash
shodan-skill exploits search apache --page 2 --facets platform:5
shodan-skill exploits count apache --facets platform:5
```

Exploits uses `https://exploits.shodan.io/api`. `--limit N` truncates search matches locally and is not sent as an unsupported API parameter. Exploit code is preserved by default. Reduce it only when requested:

```bash
shodan-skill exploits search apache --omit-code
shodan-skill exploits search apache --truncate-code 2000
```

Official references:

- <https://developer.shodan.io/api/exploits/rest>
- <https://developer.shodan.io/api/exploit-specification>
