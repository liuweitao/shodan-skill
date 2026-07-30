#!/usr/bin/env python3
"""Verify the bilingual user manual without requiring MkDocs dependencies."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
MANUAL = ROOT / "manual"
LOCALES = ("en", "zh")
MOJIBAKE_MARKERS = ("銆", "涓€", "锛", "鏂囨", "浠撳簱", "鈥")
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
NAV_PAGE = re.compile(r"(?m)^\s+- [^:]+:\s+([a-z0-9_./-]+\.md)\s*$")
CLI_COMMAND = re.compile(r"(?m)^    cli:\s+(.+?)\s*$")


def _pages(locale: str, root: Path) -> dict[Path, Path]:
    locale_root = root / "manual" / locale
    return {path.relative_to(locale_root): path for path in locale_root.rglob("*.md")}


def _check_link(page: Path, raw_target: str, root: Path) -> str | None:
    target = raw_target.strip().strip("<>")
    if not target or target.startswith("#") or re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE):
        return None
    target_path = unquote(target.split("#", 1)[0])
    if not target_path:
        return None
    resolved = (page.parent / target_path).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return f"{page.relative_to(root)}: link escapes the repository: {raw_target}"
    if not resolved.exists():
        return f"{page.relative_to(root)}: missing link target: {raw_target}"
    return None


def verify(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    localized = {locale: _pages(locale, root) for locale in LOCALES}
    expected = set(localized["en"])

    if not expected:
        errors.append("manual/en contains no Markdown pages")
    for locale in LOCALES:
        actual = set(localized[locale])
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing:
            errors.append(f"manual/{locale} is missing: {', '.join(map(str, missing))}")
        if extra:
            errors.append(f"manual/{locale} has unmatched pages: {', '.join(map(str, extra))}")

    config = (root / "mkdocs.yml").read_text(encoding="utf-8")
    nav_pages = set(map(Path, NAV_PAGE.findall(config)))
    if nav_pages != expected:
        missing_nav = sorted(expected - nav_pages)
        stale_nav = sorted(nav_pages - expected)
        if missing_nav:
            errors.append(f"mkdocs navigation is missing: {', '.join(map(str, missing_nav))}")
        if stale_nav:
            errors.append(f"mkdocs navigation has stale pages: {', '.join(map(str, stale_nav))}")

    for locale, pages in localized.items():
        for relative, page in pages.items():
            text = page.read_text(encoding="utf-8")
            if not text.startswith("# "):
                errors.append(f"manual/{locale}/{relative}: page must start with one H1")
            if "\ufffd" in text:
                errors.append(f"manual/{locale}/{relative}: contains a Unicode replacement character")
            if locale == "zh" and any(marker in text for marker in MOJIBAKE_MARKERS):
                errors.append(f"manual/{locale}/{relative}: contains a common mojibake marker")
            for target in MARKDOWN_LINK.findall(text):
                error = _check_link(page, target, root)
                if error:
                    errors.append(error)

    command_text = (root / "references" / "api-coverage.yaml").read_text(encoding="utf-8")
    commands = set(CLI_COMMAND.findall(command_text))
    commands.update({"data download", "reference filters", "reference datapedia"})
    for locale in LOCALES:
        manual_text = "\n".join(path.read_text(encoding="utf-8") for path in localized[locale].values())
        missing_commands = sorted(command for command in commands if f"shodan-skill {command}" not in manual_text)
        if missing_commands:
            errors.append(f"manual/{locale} does not mention commands: {', '.join(missing_commands)}")

    docs_url = "https://liuweitao.github.io/shodan-skill/"
    for filename in ("README.md", "README_CN.md"):
        text = (root / filename).read_text(encoding="utf-8")
        if docs_url not in text:
            errors.append(f"{filename} does not link to the published manual")

    text_files = [root / "README_CN.md"]
    if (root / "AGENTS.md").is_file():
        text_files.append(root / "AGENTS.md")
    for path in text_files:
        text = path.read_text(encoding="utf-8")
        if "\ufffd" in text or any(marker in text for marker in MOJIBAKE_MARKERS):
            errors.append(f"{path.name} contains common mojibake markers")

    return errors


def main() -> int:
    errors = verify()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    page_count = len(_pages("en", ROOT))
    print(f"Bilingual manual valid: {page_count} matched pages per language")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
