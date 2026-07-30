# Task recipes

These recipes use synthetic or public documentation examples. Review credit and authorization requirements before adapting them.

## Inspect a host and preserve machine-readable output

```bash
shodan-skill host info 8.8.8.8
```

The JSON envelope can be redirected safely because diagnostics remain on stderr. Host records can still contain sensitive observations; decide where the file may be stored.

## Estimate a search before retrieving matches

```bash
shodan-skill search count "product:nginx country:DE" --facets org:5
shodan-skill --dry-run search hosts "product:nginx country:DE" --facets org:5
shodan-skill search hosts "product:nginx country:DE" --facets org:5 --limit 20
```

Count does not consume query credits. Dry-run validates and previews the full search. The final local limit truncates returned matches but does not change API pagination semantics.

## Check remaining account credits

```bash
shodan-skill account api-info
```

Use this command for plan and remaining query or scan credits. `account profile` serves a different purpose.

## Preview a state-changing request

```bash
shodan-skill --dry-run alert create "Example" 192.0.2.0/24 --expires 3600
```

Dry-run validates targets and prints the deterministic mutation preview without constructing a transport.

## Bound a stream

```bash
shodan-skill --stream-timeout 90 stream countries US,DE \
  --limit 25 --reconnect --max-reconnects 2
```

Always choose an intentional limit and timeout for automation. Treat a premature end as a partial, failed operation.

## Resume an Enterprise download

```bash
shodan-skill data download raw-daily daily.json.gz \
  --output-file daily.json.gz --resume
```

Resume requires an existing `.part` file and a compatible server Range response. Integrity verification remains enabled unless `--no-verify` is explicitly selected.

## Send clean JSON to another tool

Use the default JSON output and keep stderr separate:

```bash
shodan-skill --output json search count "port:443"
```

Do not merge stderr into stdout before parsing, because previews and diagnostics intentionally use stderr.
