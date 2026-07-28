#!/usr/bin/env python3
"""Validate the canonical Skill, generated adapters, and selection fixtures."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PLACEHOLDERS = ("{baseDir}", "${CLAUDE_SKILL_DIR}", "${SKILL_DIR}")
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
SHODAN_TERM = re.compile(r"\bshodan\b", re.IGNORECASE)
SELECTION_SCOPE_TERM = re.compile(
    (
        r"\b(?:account|alert|api|dataset|dns|enterprise|exploit|exposure|exposed|feed|host|monitor|notifier"
        r"|organization|port|resolve|scan|search|service|stream|streaming|trend)\w*\b"
        r"|查询|检索|扫描|暴露|服务|实时流|域名|解析|告警|通知|数据集|组织|账户"
    ),
    re.IGNORECASE,
)


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


def _frontmatter(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
    if not match:
        raise ValueError(f"Invalid Skill frontmatter: {path}")
    value = yaml.safe_load(match.group(1))
    if not isinstance(value, dict):
        raise ValueError(f"Skill frontmatter must be a mapping: {path}")
    return value


def _validate_references(skill: Path) -> None:
    text = skill.read_text(encoding="utf-8")
    for reference in re.findall(r"\]\((references/[^)]+)\)", text):
        if len(Path(reference).parts) != 2 or not skill.parent.joinpath(reference).is_file():
            raise ValueError(f"Broken or deeply nested Skill reference: {reference}")


def _validate_fixtures(root: Path, description: str) -> None:
    fixtures = yaml.safe_load((root / "scripts" / "fixtures" / "skill-selection.yaml").read_text(encoding="utf-8"))
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("Selection fixtures must be a non-empty list.")
    if not SHODAN_TERM.search(description) or not SELECTION_SCOPE_TERM.search(description):
        raise ValueError("Skill description does not declare a recognizable Shodan operation scope.")
    prompts: set[str] = set()
    positive_count = 0
    negative_count = 0
    has_non_english_positive = False
    for index, fixture in enumerate(fixtures):
        if not isinstance(fixture, dict) or set(fixture) != {"prompt", "should_trigger"}:
            raise ValueError(f"Selection fixture {index} must contain only prompt and should_trigger.")
        prompt = fixture["prompt"]
        should_trigger = fixture["should_trigger"]
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError(f"Selection fixture {index} prompt must be a non-empty string.")
        if not isinstance(should_trigger, bool):
            raise ValueError(f"Selection fixture {index} should_trigger must be a boolean.")
        if prompt in prompts:
            raise ValueError(f"Duplicate selection fixture prompt: {prompt}")
        prompts.add(prompt)
        in_scope = bool(SHODAN_TERM.search(prompt) and SELECTION_SCOPE_TERM.search(prompt))
        if should_trigger and not in_scope:
            raise ValueError(f"Positive selection fixture is outside the declared Shodan scope: {prompt}")
        if not should_trigger and in_scope:
            raise ValueError(f"Negative selection fixture overlaps the declared Shodan scope: {prompt}")
        if should_trigger:
            positive_count += 1
            has_non_english_positive = has_non_english_positive or any(ord(character) > 127 for character in prompt)
        else:
            negative_count += 1
    if positive_count < 3 or negative_count < 3:
        raise ValueError("Selection fixtures require at least three positive and three negative prompts.")
    if not has_non_english_positive:
        raise ValueError("Selection fixtures require at least one non-English positive prompt.")


def _package_version(root: Path) -> str:
    match = VERSION_PATTERN.search((root / "src" / "shodan_skill" / "__init__.py").read_text(encoding="utf-8"))
    if match is None:
        raise ValueError("Unable to determine the shodan-skill package version.")
    return match.group(1)


def _native_smoke_status(command: str) -> str:
    executable = shutil.which(command)
    if not executable:
        return f"{command}: unavailable"
    try:
        result = subprocess.run(  # noqa: S603 - executable is resolved from the fixed platform command list
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except PermissionError:
        return f"{command}: unavailable (permission denied)"
    except (OSError, subprocess.TimeoutExpired):
        return f"{command}: version-smoke-failed"
    return f"{command}: {'version-smoke-passed' if result.returncode == 0 else 'version-smoke-failed'}"


def verify(root: Path = ROOT) -> list[str]:
    canonical = root / "SKILL.md"
    canonical_text = canonical.read_text(encoding="utf-8")
    frontmatter = _frontmatter(canonical)
    if set(frontmatter) != {"name", "description"}:
        raise ValueError("Canonical SKILL.md frontmatter must contain only name and description.")
    _validate_references(canonical)
    _validate_fixtures(root, str(frontmatter["description"]))
    version = _package_version(root)

    bundles = {
        "openclaw": root / "platforms" / "openclaw" / "shodan-skill",
        "codex": root / "platforms" / "codex" / "shodan-skill",
        "claude-code": root / "platforms" / "claude-code" / ".claude" / "skills" / "shodan-skill",
        "hermes": root / "platforms" / "hermes" / "shodan-skill",
    }
    for name, bundle in bundles.items():
        extras = {
            "openclaw": {"openclaw.yaml"},
            "codex": {"agents/openai.yaml"},
            "claude-code": set(),
            "hermes": {"hermes.yaml"},
        }[name]
        expected_files = {
            "SKILL.md",
            *(f"references/{reference}" for reference in REFERENCE_FILES),
            *extras,
        }
        actual_files = {
            path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file() or path.is_symlink()
        }
        if actual_files != expected_files:
            raise ValueError(f"{name} bundle file inventory differs from the generated layout.")
        skill = bundle / "SKILL.md"
        _frontmatter(skill)
        _validate_references(skill)
        text = skill.read_text(encoding="utf-8")
        expected_skill = _openclaw_skill(canonical_text) if name == "openclaw" else canonical_text
        if text != expected_skill:
            raise ValueError(f"{name} bundle differs from the canonical source.")
        if any(placeholder in text for placeholder in FORBIDDEN_PLACEHOLDERS):
            raise ValueError(f"{name} bundle contains a platform placeholder.")
        references = bundle / "references"
        if {path.name for path in references.iterdir() if path.is_file()} != set(REFERENCE_FILES):
            raise ValueError(f"{name} bundle reference inventory differs from the canonical source.")
        for reference in REFERENCE_FILES:
            if references.joinpath(reference).read_bytes() != root.joinpath("references", reference).read_bytes():
                raise ValueError(f"{name} bundle reference differs from the canonical source: {reference}")
        if any(path.is_symlink() for path in bundle.rglob("*")):
            raise ValueError(f"{name} bundle contains a symbolic link.")
    if (bundles["codex"] / "agents" / "openai.yaml").read_bytes() != (root / "agents" / "openai.yaml").read_bytes():
        raise ValueError("Codex agent metadata differs from the canonical source.")
    openai = yaml.safe_load((bundles["codex"] / "agents" / "openai.yaml").read_text(encoding="utf-8"))
    if "$shodan-skill" not in openai["interface"]["default_prompt"]:
        raise ValueError("Codex default prompt must invoke $shodan-skill.")
    openclaw = yaml.safe_load((bundles["openclaw"] / "openclaw.yaml").read_text(encoding="utf-8"))
    if openclaw != {"name": "shodan-skill", "version": version, "command": "shodan-skill"}:
        raise ValueError("OpenClaw metadata differs from the package metadata.")
    hermes = yaml.safe_load((bundles["hermes"] / "hermes.yaml").read_text(encoding="utf-8"))
    if hermes != {
        "name": "shodan-skill",
        "version": version,
        "entrypoint": "shodan-skill",
        "requires": {"commands": ["shodan-skill"], "environment": ["SHODAN_API_KEY"]},
    }:
        raise ValueError("Hermes metadata differs from the package metadata.")

    return [_native_smoke_status(command) for command in ("openclaw", "codex", "claude", "hermes")]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args(argv)
    try:
        statuses = verify()
    except (KeyError, OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        print(f"Skill validation failed: {exc}", file=sys.stderr)
        return 2
    for status in statuses:
        print(status)
    failures = [status for status in statuses if status.endswith("version-smoke-failed")]
    if failures:
        print(f"Native platform smoke test failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    print("Skill and platform bundles valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
