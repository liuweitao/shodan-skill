# Enterprise data and organizations

These workflows require an entitled Enterprise account. An authorization error from an unentitled account is expected and must not be reported as successful verification.

## Bulk datasets

```bash
shodan-skill data list
shodan-skill data files raw-daily
shodan-skill data download raw-daily daily.json.gz --output-file daily.json.gz
```

Download first retrieves file metadata, then streams the selected signed HTTPS URL to `OUTPUT.part`. The CLI checks the expected size and available SHA-1 metadata before finalization. Signed URLs are redacted.

- `--resume` continues an existing partial file using a bounded HTTP Range request.
- `--overwrite` replaces an existing partial or final file.
- `--resume` and `--overwrite` cannot be combined.
- `--no-verify` explicitly disables the metadata SHA-1 check.
- `--chunk-size` controls validated local streaming chunks.

Without resume or overwrite, existing files are preserved and the command stops. Finalization fails closed if another process creates the destination during the download. Preview the destination behavior with root `--dry-run`.

## Organization membership

```bash
shodan-skill org info
shodan-skill org member add user@example.com --notify
shodan-skill org member remove user@example.com
```

Membership changes produce a deterministic preview. `--notify` or `--no-notify` is forwarded only when explicitly selected; omission preserves the service default. Removal is destructive.

Enterprise Internet scanning is documented separately in the [scan guide](scans.md).

Official REST reference: <https://developer.shodan.io/api>
