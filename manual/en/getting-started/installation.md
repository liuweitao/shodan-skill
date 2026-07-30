# Installation and authentication

## Requirements

- Python 3.10 or newer
- A Shodan account and API key
- Credits or service entitlements required by the requested operation

Install from a local checkout:

```bash
python -m pip install .
shodan-skill --help
shodan-skill --version
```

The installed command does not depend on the location of the Skill directory. Install the CLI package separately from any agent-platform bundle.

## API-key discovery

The CLI checks these sources in order:

1. `SHODAN_API_KEY`
2. `~/.shodan/api_key`
3. `~/.config/shodan/api_key`

The legacy `~/.shodan/api_key` path takes precedence when both files exist. Keep the file readable only by the intended user. Never put a real key in a prompt, repository, fixture, screenshot, URL, or command argument that may be logged.

## Verify authentication

```bash
shodan-skill account api-info
shodan-skill account profile
```

Exit code `3` means authentication failed. Exit code `4` normally means the key is valid but the account lacks permission or entitlement. Exit code `5` reports a credit failure.

## Upgrade or remove

Use the same package source you originally trusted. For a local checkout, pull and review the changes before reinstalling. Remove the package with:

```bash
python -m pip uninstall shodan-skill
```

Agent bundles are separate copies in each platform's discovery directory. Removing the Python package does not remove those bundles, and removing a bundle does not uninstall the CLI.

## Proxy caution

The transport intentionally ignores ambient proxy variables and `.netrc`. If a reviewed proxy is required, configure `SHODAN_PROXY` or the root `--proxy` option. A proxy can observe Shodan query authentication, so do not route requests through an untrusted proxy.
