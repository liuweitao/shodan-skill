# Configuration and timeouts

Root options must be placed before the command group:

```bash
shodan-skill --read-timeout 45 --retries 1 host info 8.8.8.8
```

## Runtime settings

| Environment variable | Root option | Default | Constraint |
|---|---|---:|---|
| `SHODAN_CONNECT_TIMEOUT` | `--connect-timeout` | 10 s | Finite and positive |
| `SHODAN_READ_TIMEOUT` | `--read-timeout` | 30 s | Finite and positive |
| `SHODAN_WRITE_TIMEOUT` | `--write-timeout` | 30 s | Finite and positive |
| `SHODAN_POOL_TIMEOUT` | `--pool-timeout` | 10 s | Finite and positive |
| `SHODAN_STREAM_TIMEOUT` | `--stream-timeout` | 60 s | Finite and positive |
| `SHODAN_RETRIES` | `--retries` | 2 | Integer from 0 to 5 |
| `SHODAN_PROXY` | `--proxy` | Disabled | Absolute HTTP(S) URL |
| `SHODAN_SAFETY_MODE` | `--safety-mode` | `direct` | `direct` or `strict` |

An explicit root option overrides the matching environment setting. Invalid values fail locally before a transport is created.

## Retry behavior

No-credit GET requests use bounded retries and respect `Retry-After`. Credit-consuming GET requests are not retried automatically because a retry could multiply credit impact. Mutations are not silently replayed. After a failure, review stderr and decide whether an explicit retry is safe.

## Proxy isolation

`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `.netrc` are ignored. Prefer `SHODAN_PROXY` over `--proxy` when the proxy URL contains credentials, because process arguments can be visible in history or process listings. Proxy credentials are redacted from output and errors.

## Stream timeout

The stream timeout is an idle/read boundary, not an unlimited session duration. Finite-timeout streams request `heartbeat=false` so server heartbeat lines cannot hide an otherwise idle feed. Use a deliberate `--limit` and bounded reconnect settings for unattended work.
