#!/usr/bin/env python3
"""Generate every platform adapter from the canonical root Skill."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_FILES = (
    "api-coverage.yaml",
    "official-api-snapshot.yaml",
    "search-and-host.md",
    "scan-and-alerts.md",
    "dns-and-tools.md",
    "streaming.md",
    "trends-and-exploits.md",
    "enterprise.md",
    "data-schemas.md",
    "sdk-baseline.md",
    "sdk-only.md",
    "safety.md",
)
VERSION_PATTERN = re.compile(r'^__version__\s*=\s*"([^"]+)"$', re.MULTILINE)


def _openclaw_skill(canonical: str) -> str:
    marker = "\n---\n"
    frontmatter, body = canonical[4:].split(marker, 1)
    metadata = 'metadata:\n  openclaw:\n    emoji: "🔎"\n    requires:\n      bins:\n        - "shodan-skill"\n'
    installation = (
        "\n## OpenClaw installation\n\n"
        "Install the `shodan-skill` Python package first, then place this generated directory at "
        "`~/.openclaw/skills/shodan-skill`. Confirm discovery with `shodan-skill --help` before an API request.\n"
    )
    return f"---\n{frontmatter}\n{metadata}---\n{body.rstrip()}\n{installation}"


def _package_version() -> str:
    match = VERSION_PATTERN.search((ROOT / "src" / "shodan_skill" / "__init__.py").read_text(encoding="utf-8"))
    if match is None:
        raise ValueError("Unable to determine the shodan-skill package version.")
    return match.group(1)


def _replace_directory(destination: Path, output_root: Path) -> None:
    resolved_root = output_root.resolve()
    resolved = destination.resolve()
    if resolved_root not in resolved.parents:
        raise ValueError(f"Refusing to replace path outside output root: {resolved}")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)


def _write_bundle(destination: Path, canonical: str, *, openclaw: bool = False) -> None:
    destination.joinpath("SKILL.md").write_text(
        _openclaw_skill(canonical) if openclaw else canonical,
        encoding="utf-8",
    )
    references = destination / "references"
    references.mkdir()
    for name in REFERENCE_FILES:
        shutil.copy2(ROOT / "references" / name, references / name)


def build_bundles(output_root: Path) -> dict[str, str]:
    canonical = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    version = _package_version()
    destinations = {
        "openclaw": output_root / "openclaw" / "shodan-skill",
        "codex": output_root / "codex" / "shodan-skill",
        "claude-code": output_root / "claude-code" / ".claude" / "skills" / "shodan-skill",
        "hermes": output_root / "hermes" / "shodan-skill",
    }
    for destination in destinations.values():
        _replace_directory(destination, output_root)
    _write_bundle(destinations["openclaw"], canonical, openclaw=True)
    _write_bundle(destinations["codex"], canonical)
    _write_bundle(destinations["claude-code"], canonical)
    _write_bundle(destinations["hermes"], canonical)

    shutil.copytree(ROOT / "agents", destinations["codex"] / "agents")
    destinations["openclaw"].joinpath("openclaw.yaml").write_text(
        f'name: "shodan-skill"\nversion: "{version}"\ncommand: "shodan-skill"\n',
        encoding="utf-8",
    )
    destinations["hermes"].joinpath("hermes.yaml").write_text(
        f'name: "shodan-skill"\nversion: "{version}"\nentrypoint: "shodan-skill"\n'
        'requires:\n  commands:\n    - "shodan-skill"\n  environment:\n    - "SHODAN_API_KEY"\n',
        encoding="utf-8",
    )
    return {name: str(path) for name, path in destinations.items()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, default=ROOT / "platforms")
    args = parser.parse_args()
    print(json.dumps(build_bundles(args.output_root), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
