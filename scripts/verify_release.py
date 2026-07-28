#!/usr/bin/env python3
"""Verify package version consistency and an optional Git release tag."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r'^__version__\s*=\s*"([^"]+)"$', re.MULTILINE)
PROJECT_VERSION_PATTERN = re.compile(r"""^version\s*=\s*["']([^"']+)["'](?:\s*#.*)?$""")
RELEASE_VERSION_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")


def pyproject_version(path: Path) -> str:
    """Read project.version without requiring tomllib on supported Python 3.10."""
    in_project = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_project = line == "[project]"
            continue
        if not in_project:
            continue
        match = PROJECT_VERSION_PATTERN.fullmatch(line)
        if match is not None:
            return match.group(1)
    raise ValueError("Unable to find project.version in pyproject.toml.")


def package_versions(root: Path = ROOT) -> tuple[str, str]:
    project_version = pyproject_version(root / "pyproject.toml")
    package_text = (root / "src" / "shodan_skill" / "__init__.py").read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(package_text)
    if match is None:
        raise ValueError("Unable to find shodan_skill.__version__.")
    return project_version, match.group(1)


def verify_release(*, root: Path = ROOT, tag: str | None = None) -> list[str]:
    errors: list[str] = []
    project_version, package_version = package_versions(root)
    if project_version != package_version:
        errors.append(f"pyproject version {project_version} does not match package version {package_version}")
    if not RELEASE_VERSION_PATTERN.fullmatch(project_version):
        errors.append(f"package version is not release-shaped: {project_version}")
    if tag is not None and tag.removeprefix("v") != project_version:
        errors.append(f"release tag {tag} does not match package version {project_version}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag")
    args = parser.parse_args(argv)
    try:
        errors = verify_release(tag=args.tag)
    except (OSError, ValueError) as exc:
        print(f"release verification error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Release metadata valid: {package_versions()[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
