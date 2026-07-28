# Enterprise operations

These commands require an entitled Shodan Enterprise account. Receiving an authorization error from an unentitled account is expected and is not reported as successful verification.

## Bulk datasets

```text
shodan-skill data list
shodan-skill data files raw-daily
shodan-skill data download raw-daily daily.json.gz --output-file daily.json.gz
```

Dataset downloads first retrieve the official file metadata, then stream the selected signed HTTPS URL to `OUTPUT.part`. A successful size check and, when metadata provides it, SHA-1 integrity check occurs before finalization. Without `--overwrite`, finalization fails closed if another process creates the destination during the download. Signed download URLs are redacted from all structured output.

Use `--resume` to continue an existing `.part` file with an HTTP Range request. Without `--resume` or `--overwrite`, an existing partial file is preserved and the command stops. Use `--overwrite` to discard an existing partial or replace an existing final destination; it cannot be combined with `--resume`. `--no-verify` explicitly disables the metadata SHA-1 check. Downloads execute directly by default after destination validation.

The preview marks both resume and overwrite modes as non-reversible because they modify pre-existing local data.

## Organization

```text
shodan-skill org info
shodan-skill org member add user@example.com [--notify|--no-notify]
shodan-skill org member remove user@example.com
```

Membership changes display a deterministic preview and execute directly by default. The optional add-member notification flag is forwarded only when explicitly selected; when omitted, the preview labels the mode as `service-default` instead of implying that email is disabled. Default tests mock every request and never modify a live organization.

The Enterprise Internet scan is exposed separately as `shodan-skill scan internet PORT PROTOCOL` and executes directly in the default mode after local validation.

Official reference: <https://developer.shodan.io/api>
