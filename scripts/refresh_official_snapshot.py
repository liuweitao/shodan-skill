#!/usr/bin/env python3
"""Refresh or check the checked-in snapshot of documented Shodan HTTP operations."""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from collections.abc import Mapping
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SNAPSHOT = ROOT / "references" / "official-api-snapshot.yaml"
DOCUMENT_SOURCES = {
    "rest": "https://developer.shodan.io/api",
    "streaming": "https://developer.shodan.io/api/stream",
    "trends": "https://developer.shodan.io/api/trends",
    "exploits": "https://developer.shodan.io/api/exploits/rest",
}
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
USER_AGENT = "shodan-skill-doc-snapshot/1 (+https://github.com/liuweitao/shodan-skill)"


class _DocumentationParser(HTMLParser):
    """Collect visible text and heading text without third-party HTML dependencies."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self._heading_tag: str | None = None
        self._heading_parts: list[str] = []
        self.visible_parts: list[str] = []
        self.headings: list[str] = []

    def handle_starttag(self, tag: str, _attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        if lowered in {"script", "style", "noscript", "svg"}:
            self._ignored_depth += 1
        elif self._ignored_depth == 0 and lowered in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._heading_tag = lowered
            self._heading_parts = []

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in {"script", "style", "noscript", "svg"} and self._ignored_depth:
            self._ignored_depth -= 1
            return
        if self._ignored_depth == 0 and self._heading_tag == lowered:
            heading = _normalize_text(" ".join(self._heading_parts))
            if heading:
                self.headings.append(heading)
            self._heading_tag = None
            self._heading_parts = []

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        normalized = _normalize_text(data)
        if not normalized:
            return
        self.visible_parts.append(normalized)
        if self._heading_tag is not None:
            self._heading_parts.append(normalized)


def _normalize_text(value: str) -> str:
    return " ".join(value.split())


def parse_document(html: str) -> tuple[list[tuple[str, str]], str]:
    """Return documented method/path pairs and a stable visible-text digest."""
    parser = _DocumentationParser()
    parser.feed(html)
    parser.close()
    operations: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for heading in parser.headings:
        compact = heading.replace("\u00a0", " ")
        method = next((candidate for candidate in HTTP_METHODS if compact.startswith(candidate)), None)
        if method is None:
            continue
        remainder = compact[len(method) :].lstrip()
        if not remainder.startswith("/"):
            continue
        path = remainder.split("?", 1)[0].split("#", 1)[0].split()[0].rstrip("/")
        if not path:
            path = "/"
        operation = (method, path)
        if operation not in seen:
            seen.add(operation)
            operations.append(operation)
    visible_text = _normalize_text(" ".join(parser.visible_parts))
    digest = hashlib.sha256(visible_text.encode("utf-8")).hexdigest()
    return operations, digest


def _fetch_document_once(url: str, *, timeout: float = 30.0) -> str:
    request = Request(
        url,
        headers={
            "Accept": "text/html",
            "Accept-Encoding": "identity",
            "User-Agent": USER_AGENT,
        },
    )
    with urlopen(request, timeout=timeout) as response:
        final = urlsplit(response.geturl())
        expected = urlsplit(url)
        if final.scheme != "https" or final.hostname != expected.hostname:
            raise ValueError(f"official documentation redirected outside {expected.hostname}")
        declared_length = response.headers.get("Content-Length")
        if declared_length is not None and int(declared_length) > MAX_DOCUMENT_BYTES:
            raise ValueError(f"official documentation exceeds {MAX_DOCUMENT_BYTES} bytes")
        body = response.read(MAX_DOCUMENT_BYTES + 1)
        if len(body) > MAX_DOCUMENT_BYTES:
            raise ValueError(f"official documentation exceeds {MAX_DOCUMENT_BYTES} bytes")
        charset = response.headers.get_content_charset() or "utf-8"
    return body.decode(charset)


def _fetch_document(url: str, *, timeout: float = 30.0) -> str:
    """Retry transient upstream/network errors without accepting partial snapshots."""
    for attempt in range(3):
        try:
            return _fetch_document_once(url, timeout=timeout)
        except HTTPError as exc:
            if exc.code not in {408, 429, 500, 502, 503, 504} or attempt == 2:
                raise
            exc.close()
        except (URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep(2**attempt)
    raise AssertionError("retry loop exhausted")


def build_snapshot(
    documents: Mapping[str, str],
    *,
    retrieved_at: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic snapshot from already-fetched official HTML documents."""
    if set(documents) != set(DOCUMENT_SOURCES):
        raise ValueError("documents must contain every configured Shodan API family exactly once")
    operations: list[dict[str, str]] = []
    sources: dict[str, dict[str, object]] = {}
    for family, url in DOCUMENT_SOURCES.items():
        parsed, digest = parse_document(documents[family])
        if not parsed:
            raise ValueError(f"no documented HTTP operations found for {family}")
        sources[family] = {
            "url": url,
            "document_sha256": digest,
            "operation_count": len(parsed),
        }
        operations.extend({"api": family, "method": method, "path": path} for method, path in parsed)
    return {
        "schema_version": 1,
        "retrieved_at": retrieved_at or date.today().isoformat(),
        "generated_by": "scripts/refresh_official_snapshot.py",
        "sources": sources,
        "operations": operations,
    }


def fetch_snapshot(*, timeout: float = 30.0) -> dict[str, Any]:
    documents = {family: _fetch_document(url, timeout=timeout) for family, url in DOCUMENT_SOURCES.items()}
    return build_snapshot(documents)


def load_snapshot(path: Path = DEFAULT_SNAPSHOT) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError("official snapshot root must be a mapping")
    return data


def snapshot_differences(expected: Mapping[str, Any], current: Mapping[str, Any]) -> list[str]:
    """Describe endpoint or normalized-document changes while ignoring retrieval time."""
    differences: list[str] = []
    expected_operations = expected.get("operations")
    current_operations = current.get("operations")
    if expected_operations != current_operations:
        differences.append("documented HTTP operation inventory changed")
    expected_sources = expected.get("sources")
    current_sources = current.get("sources")
    if isinstance(expected_sources, Mapping) and isinstance(current_sources, Mapping):
        for family in DOCUMENT_SOURCES:
            old_source = expected_sources.get(family)
            new_source = current_sources.get(family)
            if not isinstance(old_source, Mapping) or not isinstance(new_source, Mapping):
                differences.append(f"{family} source metadata is missing or malformed")
                continue
            if old_source.get("url") != new_source.get("url"):
                differences.append(f"{family} documentation URL changed")
            if old_source.get("document_sha256") != new_source.get("document_sha256"):
                differences.append(f"{family} normalized documentation text changed")
    else:
        differences.append("source metadata is missing or malformed")
    return differences


def snapshot_report(expected: Mapping[str, Any], current: Mapping[str, Any]) -> str:
    """Explain inventory changes separately from text changes that need human review."""
    differences = snapshot_differences(expected, current)
    lines = ["# Official Shodan documentation review", ""]
    if not differences:
        return "\n".join([*lines, "No documentation or operation changes detected.", ""])
    lines.extend(["Review upstream documentation before accepting this candidate snapshot.", ""])
    lines.extend(f"- {difference}" for difference in differences)
    old = {(operation["api"], operation["method"], operation["path"]) for operation in expected.get("operations", [])}
    new = {(operation["api"], operation["method"], operation["path"]) for operation in current.get("operations", [])}
    lines.extend(["", "## Operation inventory", ""])
    if old == new:
        lines.append(f"All {len(new)} method/path pairs are unchanged. Text changes can still affect API behavior.")
    for label, operations in (("Added", new - old), ("Removed", old - new)):
        lines.extend(f"- {label}: `{family} {method} {path}`" for family, method, path in sorted(operations))
    lines.extend(["", "## Sources", ""])
    for family, url in DOCUMENT_SOURCES.items():
        lines.append(f"- {family}: {url}")
    lines.extend(
        [
            "",
            "The hashes record normalized visible text, not a semantic diff. Review parameters, credits, permissions,",
            "and response contracts in each changed source; a stable operation inventory does not prove compatibility.",
            "Sync `references/api-coverage.yaml` official_retrieved with the accepted snapshot retrieval date,",
            "then run `python scripts/build_bundles.py` to update every platform copy.",
            "Never auto-accept a snapshot solely to make the scheduled check green.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_report(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_snapshot(path: Path, snapshot: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(dict(snapshot), allow_unicode=True, sort_keys=False, width=120),
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Fetch docs and fail if the checked-in snapshot is stale")
    mode.add_argument("--write", action="store_true", help="Fetch docs and replace the checked-in snapshot")
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--report", type=Path, help="Write a Markdown review report")
    parser.add_argument("--candidate-snapshot", type=Path, help="Save fetched evidence without accepting it")
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.timeout > 120:
        parser.error("--timeout must be greater than zero and at most 120 seconds")
    if args.candidate_snapshot and args.candidate_snapshot.resolve() == args.snapshot.resolve():
        parser.error("--candidate-snapshot must differ from --snapshot; use --write to accept changes")
    if args.report and args.report.resolve() in {
        args.snapshot.resolve(),
        args.candidate_snapshot.resolve() if args.candidate_snapshot else None,
    }:
        parser.error("--report must differ from the snapshot paths")
    try:
        current = fetch_snapshot(timeout=args.timeout)
        expected = load_snapshot(args.snapshot) if args.snapshot.exists() or args.check else {}
        differences = snapshot_differences(expected, current)
        if args.candidate_snapshot:
            _write_snapshot(args.candidate_snapshot, current)
        if args.report:
            _write_report(args.report, snapshot_report(expected, current))
        if args.write:
            if differences:
                _write_snapshot(args.snapshot, current)
                print(f"Wrote official API snapshot: {args.snapshot}")
            else:
                print("Official Shodan documentation snapshot is current; no files changed.")
            return 0
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        if args.report:
            try:
                _write_report(args.report, "# Official documentation fetch failed\n\n" + str(exc) + "\n")
            except OSError as report_error:
                print(f"could not write failure report: {report_error}", file=sys.stderr)
        print(f"official snapshot error: {exc}", file=sys.stderr)
        return 2
    if differences:
        for difference in differences:
            print(f"DRIFT: {difference}", file=sys.stderr)
        print(
            "Run 'python scripts/refresh_official_snapshot.py --write' and review every documentation change.",
            file=sys.stderr,
        )
        return 1
    print("Official Shodan documentation snapshot is current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
