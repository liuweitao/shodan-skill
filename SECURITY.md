# Security policy

## Supported versions

Security fixes are provided for the latest release line. Older versions should be upgraded before reporting a problem that is already fixed in the current release.

| Version | Supported |
|---|---|
| 2.0.x | Yes |
| 1.x and earlier | No |

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability, leaked credential, unsafe scan path, confirmation bypass, redaction failure, or signed-URL exposure.

Use the repository's [private vulnerability reporting](https://github.com/liuweitao/shodan-skill/security/advisories/new). Include:

- affected version and platform;
- the smallest safe reproduction that does not contact an unauthorized target;
- expected and observed behavior;
- whether credentials, credits, account state, or local files may be affected;
- suggested remediation, if known.

Do not include a real Shodan API key, bearer token, cookie, notifier credential, signed download URL, private target, or exploit payload. Replace sensitive values with unmistakably synthetic placeholders.

The maintainers should acknowledge a complete report within seven days and coordinate disclosure after a fix is available. No promise of a bounty is made.

## Safe research boundary

Reproduce findings with mocked HTTP transports whenever possible. A configured API key does not authorize live scanning, monitoring, credit consumption, account mutation, streaming, Enterprise access, or testing targets owned by another party.
