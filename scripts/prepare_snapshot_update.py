#!/usr/bin/env python3
"""Prepare a validated documentation candidate and date metadata for a review-only PR."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.build_bundles import build_bundles  # noqa: E402
from scripts.refresh_official_snapshot import snapshot_differences  # noqa: E402
from scripts.verify_coverage import load_official_snapshot  # noqa: E402


def prepare_update(candidate: Path, *, root: Path = ROOT) -> bool:
    snapshot = root / "references/official-api-snapshot.yaml"
    manifest = root / "references/api-coverage.yaml"
    current = load_official_snapshot(candidate)
    expected = load_official_snapshot(snapshot)
    if not snapshot_differences(expected, current):
        return False
    # Preserve manifest comments, aliases, implementation claims, and contract-test gates.
    text, count = re.subn(
        r"^official_retrieved:.*$",
        f"official_retrieved: {current['retrieved_at']}",
        manifest.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if count != 1:
        raise ValueError("expected exactly one official_retrieved field in the coverage manifest")
    snapshot.write_text(candidate.read_text(encoding="utf-8"), encoding="utf-8")
    manifest.write_text(text, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    if prepare_update(args.candidate):
        build_bundles(ROOT / "platforms")
        print("Prepared snapshot, retrieval metadata and platform copies for human review.")
    else:
        print("No upstream content changes; no files changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
