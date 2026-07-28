# Streaming API

The Streaming API uses `https://stream.shodan.io` and requires an API key. Alert feeds are available to accounts with alerts; the global banners, ASN, countries, ports, vulnerabilities, and custom-query feeds require the applicable Streaming/Enterprise entitlement.

## Commands

```text
shodan-skill stream banners
shodan-skill stream asn AS123,AS456
shodan-skill stream countries US,DE
shodan-skill stream ports 22,443
shodan-skill stream vulns CVE-2024-1234
shodan-skill stream alerts
shodan-skill stream alert ALERT_ID
shodan-skill stream custom "product:nginx"
```

Every command emits one stable-envelope JSON object per line by default. `--stream-format sse` both requests the documented SSE representation and emits each stable envelope as an SSE `data:` event terminated by a blank line. `--limit` bounds emitted banner records and does not count server debug events. The default limit is 10 so an unattended invocation terminates.

Streams use finite connect and idle/read timeouts and send `heartbeat=false`, matching the official client's timeout behavior so heartbeat newlines cannot keep an otherwise idle stream alive indefinitely. `--reconnect --max-reconnects N` enables bounded exponential-backoff reconnects after a disconnect, timeout, or clean EOF; the maximum accepted value is 10. A stream that ends before `--limit` is reached returns a network error instead of reporting partial output as a complete success.

Pass `--debug` to request the documented `debug=1` discard events. Reconnect and server debug/discard events are written as redacted diagnostics to stderr and do not count toward `--limit`. Ctrl+C exits with the documented interrupted-stream code.

`stream custom` requires a non-empty, case-sensitive `query` parameter; preserve the user's filter-name casing exactly. Country codes, port numbers, ASNs, CVE identifiers, and alert IDs are validated locally before opening the connection.

ASN selectors accept either `AS123` or `123` as input, validate the 32-bit range, and send the numeric form required by the official Streaming path.

Official reference: <https://developer.shodan.io/api/stream>

The official Python client's timeout handling also sends `heartbeat=false`: <https://github.com/achillean/shodan-python/blob/master/shodan/stream.py>. For record shapes, load the root Skill's official-data-schemas reference; the Threatnet event specification is not a universal schema for every banner feed.
