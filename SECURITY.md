# Security policy

## Supported versions

Security fixes are provided for the latest release line. Older versions should be upgraded before reporting a problem that is already fixed in the current release.

| Version | Supported |
|---|---|
| 2.0.x | Yes |
| 1.x and earlier | No |

## Runtime and dependency security

Use a maintained Python release with current security patches. Python 3.10 remains a compatibility target,
but reached end of life in October 2026 and no longer receives upstream security fixes. Compatibility tests
are not a security support guarantee for that interpreter.

### October 2026 review

Reviewed on 2026-10-27 against the Node.js security release, PSF advisory database, and Python packaging
advisories linked below. This is a source and dependency assessment, not evidence that an installation
has been compromised or that every deployed environment has been updated.

| Component / advisory | Project exposure | Remediation |
|---|---|---|
| certifi / [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2) | httpx uses certifi for TLS verification. Earlier dependency constraints allowed CA bundles containing the compromised emSign chain. An on-path attacker with a compromised intermediate key could intercept HTTPS, including API credentials. | Require `certifi>=2026.10.19`; upgrade existing installations and rebuild images. Version 2026.10.18 removed the affected roots; 2026.10.19 is recommended for compatibility with unaffected roots. |
| PyPI publishing / [GHSA-5xjx-3w67-w9x9](https://github.com/pypa/gh-action-pypi-publish/security/advisories/GHSA-5xjx-3w67-w9x9) | The previous pinned action was v1.14.2, included in the advisory's affected range. The exposure is in release publishing and attestations. | Upgrade the pinned action to v1.14.3. |
| CPython ssl / [CVE-2026-115557](https://github.com/psf/advisory-database/blob/main/advisories/python/PSF-2026-46.json) | The CLI makes TLS client connections. The new interpreter denylist provides additional protection against compromised certificates, including system CA users. | Use Python 3.11.18+, 3.12.16+, 3.13.18+, 3.14.10+, or 3.15.2+ within the corresponding release line. CI checks for the latest available patch instead of preferring an older cached interpreter. |
| Node.js / [October 21 security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) | The Python CLI has no Node.js runtime dependency. JavaScript GitHub Actions run on the runner's bundled Node.js. The original PR run used runner v2.338.0, whose build specifies Node.js 24.21.0, below the patched version. | Node.js fixes are in 22.23.4, 24.22.1, and 26.12.1. Runner v2.338.2 bundles Node.js 24.22.1. GitHub manages hosted runner rollout; upgrading an action or using setup-node does not update the runner's bundled interpreter. Confirm the runner version in each run's setup log. |

The Node.js release covers DNS NUL truncation (CVE-2026-105482), TLS hostname checks
(CVE-2026-105483, CVE-2026-106069, CVE-2026-106072), Brotli decoding (CVE-2026-111497),
HTTP keep-alive responses (CVE-2026-105481), snapshot entropy caches (CVE-2026-106074),
ZIP validation (CVE-2026-106070), and permission checks (CVE-2026-106071, CVE-2026-106073).
These do not execute in the Python CLI; CI exposure depends on the bundled engine and the action's
inputs and code paths. An affected engine version alone does not establish exploitability for each CVE.

Other recent CPython advisories have different reachability:

- The CLI does not extract tar archives, so the tar filter bypass in
  [CVE-2026-114583](https://github.com/psf/advisory-database/blob/main/advisories/python/PSF-2026-45.json)
  has no direct CLI path. Packaging tools can process archives and should also be updated.
- [CVE-2026-19553](https://github.com/psf/advisory-database/blob/main/advisories/python/PSF-2026-44.json)
  requires a missing TLS server hostname with `wrap_bio`. The synchronous httpx/httpcore transport
  supplies the hostname for direct TLS and TLS-in-TLS proxy connections; there is no direct vulnerable
  configuration here.
- [CVE-2026-19445](https://github.com/psf/advisory-database/blob/main/advisories/python/PSF-2026-43.json)
  affects TLS servers with an SNI context callback. This project is a TLS client.
- [CVE-2026-12345](https://github.com/psf/advisory-database/blob/main/advisories/python/PSF-2026-42.json)
  concerns `TemporaryDirectory` cleanup. The installer uses `mkdtemp` and `shutil.rmtree`, not
  `TemporaryDirectory`; keep the interpreter updated and prevent other users from modifying the install tree.
- The documentation drift tool parses remote HTML using `html.parser`, so
  [CVE-2026-15308](https://github.com/psf/advisory-database/blob/main/advisories/python/PSF-2026-33.json)
  is relevant to that maintenance tool on an unpatched interpreter, rather than the CLI. Its response-size
  limit does not replace the interpreter fix.

For existing virtual environments, upgrading the project source alone is insufficient. Follow the
[Python incident guidance](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
to bootstrap a trusted pip version, then upgrade the environment:

```bash
python -m pip install --upgrade "pip>=26.2.2" "certifi>=2026.10.19"
python -m pip install --upgrade shodan-skill
python -m pip check
```

The first command assumes pip has already been bootstrapped using the hash-verified wheel linked in the
incident guidance, or another trusted distribution channel. Use uv 0.13.4+ if installing with uv. Check
every existing environment and container separately. System CA stores, proxies, vendored certificate
bundles, and agent hosts using Node.js require their own updates. No installed agent-host version is
recorded in this repository, so their vulnerability status cannot be inferred from the platform adapters.

The repository's Dependabot alert API reported alerts disabled during this review. Weekly Dependabot
update configuration does not by itself establish that vulnerability alerts are enabled or absent.

Validation used Python 3.14.10, httpx 0.28.1, httpcore 1.0.9, certifi 2026.10.23, and pip 26.2.2.
The offline suite passed 430 tests with 11 live tests skipped and 94.75% coverage. pip-audit 2.10.1
reported no known vulnerabilities in 87 resolved packages covering runtime, development, release, and
documentation dependencies. This result applies to that resolution on the review date; older existing
environments and other versions allowed by dependency ranges need separate audits.

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
