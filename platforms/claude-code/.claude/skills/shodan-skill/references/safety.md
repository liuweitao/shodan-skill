# Safety and live operations

Normal CLI and Skill execution defaults to `direct` mode. An explicit CLI command or user request is the instruction to execute that operation; no second confirmation or authorization acknowledgement is required. Do not initiate an unstated operation merely because `SHODAN_API_KEY` is configured.

Before any request:

1. Validate targets and parameters locally.
2. Display the deterministic operation preview when the operation defines one.
3. Continue directly in the default `direct` mode.
4. Use root-level `--dry-run` to stop after validation and preview without constructing a transport.
5. Do not add operations or expand targets beyond the explicit request.

Set `SHODAN_SAFETY_MODE=strict` or pass root-level `--safety-mode strict` to restore confirmation gates. In strict mode, use `--confirm` or `--yes`, plus `--acknowledge-authorization` for scans and monitored networks. These compatibility options must be written exactly; abbreviated long forms such as `--y`, `--conf`, or `--ack` are rejected.

Use these independent live-test gates:

- `SHODAN_LIVE_TESTS=1` and `--allow-live-shodan` for explicitly authorized read-only checks.
- `--allow-shodan-credits` for credit-consuming checks.
- `SHODAN_MUTATING_TESTS=1` and `--allow-shodan-mutations` for separately authorized state changes.
- `SHODAN_ENTERPRISE_TESTS=1` for entitled Enterprise checks.
- `SHODAN_TEST_TARGETS` only for targets the user is authorized to scan or monitor.

These gates are cumulative where categories overlap. No environment variable, pytest option, configured key, or account entitlement authorizes a live operation by itself.

Repository live tests remain fail-closed and independent from normal direct-mode CLI execution. Validate every dynamic URL path segment before constructing a transport so an identifier cannot alter the requested endpoint. Redact API keys, authorization headers, bearer tokens, cookies, provider arguments (including routing keys and webhook URLs), signed URLs, and credential-like values from all outputs and errors.

The HTTP transport ignores ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `.netrc` settings. Use only an explicitly reviewed `SHODAN_PROXY` or root-level `--proxy` value; a proxy can observe Shodan query authentication. Prefer the environment variable when the proxy URL contains credentials, and keep every timeout finite.

Do not automatically retry credit-consuming GET requests. A user may retry explicitly after reviewing the failure; no-credit GET requests may use the bounded transport retry policy.
