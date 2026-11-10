#!/usr/bin/env python3
"""Validate that a release SBOM describes the product and its HTTP dependencies."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def verify_sbom(document: Mapping[str, Any], *, version: str) -> None:
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise ValueError("expected a CycloneDX 1.6 SBOM")
    components = {
        component["name"].lower().replace("_", "-"): component for component in document.get("components", [])
    }
    if not {"shodan-skill", "httpx", "certifi"} <= components.keys():
        raise ValueError("SBOM must contain shodan-skill, httpx and certifi")
    if components["shodan-skill"].get("version") != version:
        raise ValueError("SBOM product version does not match the release")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    # Read the canonical version without importing an editable source installation.
    from verify_release import package_versions

    verify_sbom(json.loads(args.path.read_text(encoding="utf-8")), version=package_versions(root)[0])
    print("Release SBOM contains the expected product version and HTTP dependencies.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
