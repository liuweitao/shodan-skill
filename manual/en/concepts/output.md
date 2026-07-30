# Output, errors, and redaction

## Stable envelope

Non-streaming stdout defaults to a stable JSON envelope:

```json
{
  "ok": true,
  "data": {},
  "meta": {
    "command": "host-info",
    "credits_used": null,
    "credit_impact": "none",
    "credits_estimated": null
  },
  "error": null
}
```

Use `--output json`, `--output jsonl`, or `--output human` before the command group. Structured success results go to stdout. Diagnostics, mutation previews, reconnect events, and debug events go to stderr.

Streams emit one envelope per JSON Line. With `--stream-format sse`, each envelope is emitted as an SSE `data:` event followed by a blank line.

## Exit codes

| Exit | Meaning |
|---:|---|
| 0 | Success |
| 2 | Usage or strict-mode safety gate |
| 3 | Authentication |
| 4 | Authorization or entitlement |
| 5 | Credits |
| 6 | Network |
| 7 | API, download, or integrity error |
| 8 | Timeout |
| 9 | Interrupted stream or operation |
| 10 | Unexpected internal error |

Scripts should check the exit code before consuming a result. A stream that ends before its requested limit returns a network error rather than presenting partial output as a complete success.

## Recursive redaction

The CLI redacts API keys, credential-like fields, bearer tokens, authorization headers, cookies, notifier parameters, routing keys, webhook URLs, signed download URLs, and proxy credentials from structured output and errors. The Shodan API key is used as query authentication internally but is never displayed in a URL.

Redaction reduces accidental disclosure; it does not make arbitrary output safe to publish. Host data, account details, alerts, headers, and organization membership can still be sensitive even when credentials are removed.
