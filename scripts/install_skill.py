#!/usr/bin/env python3
"""Install one generated Shodan Skill bundle without silent overwrites."""

from __future__ import annotations

import argparse
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = {
    "openclaw": (ROOT / "platforms" / "openclaw" / "shodan-skill", Path(".openclaw/skills/shodan-skill")),
    "codex": (ROOT / "platforms" / "codex" / "shodan-skill", Path(".codex/skills/shodan-skill")),
    "claude-code": (
        ROOT / "platforms" / "claude-code" / ".claude" / "skills" / "shodan-skill",
        Path(".claude/skills/shodan-skill"),
    ),
    "hermes": (ROOT / "platforms" / "hermes" / "shodan-skill", Path(".hermes/skills/shodan-skill")),
}


def _reject_symlink_components(root: Path, destination: Path) -> None:
    try:
        relative = destination.relative_to(root)
    except ValueError as exc:
        raise ValueError("Installation destination escaped the selected home directory.") from exc
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"Refusing to install through a symbolic path: {current}")
        try:
            resolved_current = current.resolve()
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"Unable to resolve installation path safely: {current}") from exc
        if resolved_current != root and root not in resolved_current.parents:
            raise ValueError(f"Refusing to install through a redirected path: {current}")


def install(platform: str, home: Path, *, confirmed: bool = False) -> Path:
    source, relative = PLATFORMS[platform]
    if source.is_symlink() or any(path.is_symlink() for path in source.rglob("*")):
        raise ValueError("Generated bundles containing symbolic links cannot be installed.")
    if not source.is_dir():
        raise FileNotFoundError("Generated bundle is missing; run scripts/build_bundles.py first.")
    resolved_home = home.resolve()
    destination = resolved_home / relative
    _reject_symlink_components(resolved_home, destination)
    replacement_authorized = destination.exists()
    if replacement_authorized:
        if not destination.is_dir():
            raise ValueError(f"Installation destination is not a directory: {destination}")
        if not confirmed:
            try:
                answer = input(f"Replace existing installation at {destination}? [y/N] ").strip().lower()
            except EOFError as exc:
                raise FileExistsError("Existing installation was not replaced; pass --yes to confirm.") from exc
            if answer not in {"y", "yes"}:
                raise FileExistsError("Existing installation was not replaced.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(resolved_home, destination)

    stage_root = Path(tempfile.mkdtemp(prefix=".shodan-skill-install-", dir=destination.parent))
    staged = stage_root / "new"
    backup = stage_root / "previous"
    try:
        shutil.copytree(source, staged)
        _reject_symlink_components(resolved_home, destination)
        had_previous = destination.exists()
        if had_previous and not replacement_authorized:
            raise FileExistsError("Installation destination appeared during installation; it was not replaced.")
        if had_previous:
            destination.replace(backup)
        try:
            staged.replace(destination)
        except OSError as replacement_error:
            if had_previous and backup.exists() and not destination.exists():
                try:
                    backup.replace(destination)
                except OSError as rollback_error:
                    raise OSError(
                        f"Installation replacement failed; the previous installation remains at {backup}"
                    ) from rollback_error
            raise replacement_error
    except Exception:
        if not backup.exists():
            with suppress(OSError):
                shutil.rmtree(stage_root)
        raise
    shutil.rmtree(stage_root)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--platform", choices=tuple(PLATFORMS), required=True)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--yes", action="store_true", help="Confirm replacement of an existing installation")
    args = parser.parse_args()
    try:
        print(install(args.platform, args.home, confirmed=args.yes))
    except (FileExistsError, FileNotFoundError, OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
