# SDK-only and undocumented operations

The canonical coverage manifest tracks the publicly documented raw HTTP APIs. The official `shodan==1.31.0` Python client also contains the following surfaces that are absent from the current HTTP documentation and therefore excluded from the 58-operation completeness claim.

| SDK surface | Raw path or variant | Repository status | Live verification |
|---|---|---|---|
| `Shodan.services()` | `GET /shodan/services` | Excluded; no current public HTTP documentation | Not run; no live authorization |
| `Shodan.labs.honeyscore(ip)` | `GET /labs/honeyscore/{ip}` | Excluded; no current public HTTP documentation | Not run; no live authorization |
| `Stream.tags(tags, ...)` | `GET /shodan/tags/{tags}` | Excluded; no current public Streaming documentation | Not run; no Streaming entitlement or authorization |
| `ignore_alert_trigger_notification(..., vulns=...)` | Adds a vulnerability path segment after the documented ignored service | Excluded; documented CLI implements only the public service path | Not run; no mutation authorization |

Sources:

- Official client implementation: <https://github.com/achillean/shodan-python/blob/master/shodan/client.py>
- Official Streaming client: <https://github.com/achillean/shodan-python/blob/master/shodan/stream.py>
- Public REST documentation: <https://developer.shodan.io/api>
- Public Streaming documentation: <https://developer.shodan.io/api/stream>

Do not add these surfaces to `api-coverage.yaml` unless Shodan documents them in the public HTTP reference. If experimental compatibility commands are introduced later, label them SDK-only, keep them outside the official count, require separate mocked contracts, and never claim live support without an authorized result.
