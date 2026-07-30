# Quick start

## 1. Install

Python 3.10 or newer is required. From a checked-out repository:

```bash
python -m pip install .
shodan-skill --version
```

For development, install the editable package and test tools:

```bash
python -m pip install -e ".[dev]"
```

## 2. Configure an API key

Use an environment variable so the key does not enter source files or command history:

```bash
export SHODAN_API_KEY="your-key"
```

PowerShell:

```powershell
$env:SHODAN_API_KEY = "your-key"
```

The CLI can also read `~/.shodan/api_key` or `~/.config/shodan/api_key`. See [installation and authentication](installation.md) for precedence and handling guidance.

## 3. Check the account and run a read-only request

```bash
shodan-skill account api-info
shodan-skill host info 8.8.8.8
```

`account api-info` reports plan and remaining query or scan credit information. It is distinct from `account profile`, which returns membership and profile details.

## 4. Search with a dry run first

Root options must appear before the command group:

```bash
shodan-skill --dry-run search hosts "product:nginx" --facets country:5
shodan-skill search hosts "product:nginx" --facets country:5
```

The first command validates the request and displays a credit preview without creating a transport. The second executes it. Filtered searches and pages after the first can consume query credits.

## 5. Read the result

Non-streaming stdout uses a stable JSON envelope by default. Diagnostics and previews use stderr, so scripts can parse stdout independently. Use `--output human` for interactive inspection or `--output jsonl` when line-oriented output is more convenient.

Next, review [safety and access](../concepts/safety.md) and the [task recipes](../recipes.md).
