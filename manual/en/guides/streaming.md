# Streaming

Streaming requests use `https://stream.shodan.io`. Alert feeds require an account with alerts; global banners, ASN, country, port, vulnerability, and custom-query feeds require the applicable Streaming or Enterprise entitlement.

## Feed commands

```bash
shodan-skill stream banners --limit 10
shodan-skill stream asn AS123,AS456 --limit 10
shodan-skill stream countries US,DE --limit 10
shodan-skill stream ports 22,443 --limit 10
shodan-skill stream vulns CVE-2024-1234 --limit 10
shodan-skill stream alerts --limit 10
shodan-skill stream alert ALERT_ID --limit 10
shodan-skill stream custom "product:nginx" --limit 10
```

Selectors are validated before connecting. ASN input accepts `AS123` or `123` and sends the numeric path form. Custom queries preserve filter-name casing.

## Output formats

JSON Lines is the default. To request and emit SSE:

```bash
shodan-skill stream ports 22,443 --limit 10 --stream-format sse
```

Each non-debug record receives the stable output envelope. Server debug/discard events and reconnect diagnostics go to stderr and do not count toward the limit. `--debug` sends the documented `debug=1` request parameter.

## Limits, timeouts, and reconnects

The default limit is 10 so an unattended command terminates. A finite stream timeout and `heartbeat=false` prevent heartbeat lines from masking an idle feed. Enable bounded reconnects deliberately:

```bash
shodan-skill --stream-timeout 90 stream ports 22,443 \
  --limit 100 --reconnect --max-reconnects 3
```

The accepted reconnect maximum is 10. A disconnect, timeout, or clean EOF before the requested record limit is a network error. Ctrl+C exits with interrupted-operation code `9`.

Official Streaming reference: <https://developer.shodan.io/api/stream>
