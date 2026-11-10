from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from scripts.refresh_official_snapshot import (
    DOCUMENT_SOURCES,
    build_snapshot,
    load_snapshot,
    parse_document,
    snapshot_differences,
)


def test_document_parser_extracts_heading_operations_and_strips_query_parameters() -> None:
    html = """
    <html><body>
      <h6><span>GET</span><span>/shodan/custom?query={query}</span></h6>
      <h6>POST /shodan/scan</h6>
      <h6>GET /shodan/custom?query={query}</h6>
      <pre>GET /example/from-code-must-not-count</pre>
      <script>GET /example/from-script-must-not-count</script>
    </body></html>
    """

    operations, digest = parse_document(html)

    assert operations == [
        ("GET", "/shodan/custom"),
        ("POST", "/shodan/scan"),
    ]
    assert len(digest) == 64
    assert digest == parse_document(html.replace("\n", "   "))[1]


def test_snapshot_builder_records_source_hashes_and_detects_text_or_endpoint_drift() -> None:
    documents = {family: f"<h6>GET /{family}</h6><p>parameter text</p>" for family in DOCUMENT_SOURCES}
    snapshot = build_snapshot(documents, retrieved_at="2026-07-27")

    assert snapshot["retrieved_at"] == "2026-07-27"
    assert len(snapshot["operations"]) == 4
    assert all(source["operation_count"] == 1 for source in snapshot["sources"].values())
    assert snapshot_differences(snapshot, deepcopy(snapshot)) == []

    changed_text = build_snapshot(
        {**documents, "rest": "<h6>GET /rest</h6><p>changed parameter text</p>"},
        retrieved_at="2026-07-28",
    )
    assert snapshot_differences(snapshot, changed_text) == ["rest normalized documentation text changed"]

    changed_endpoint = build_snapshot(
        {**documents, "rest": "<h6>GET /rest/new</h6><p>parameter text</p>"},
        retrieved_at="2026-07-28",
    )
    differences = snapshot_differences(snapshot, changed_endpoint)
    assert "documented HTTP operation inventory changed" in differences
    assert "rest normalized documentation text changed" in differences


def test_checked_in_snapshot_has_exact_official_sources_and_58_operations() -> None:
    snapshot = load_snapshot(Path("references/official-api-snapshot.yaml"))

    assert set(snapshot["sources"]) == set(DOCUMENT_SOURCES)
    assert len(snapshot["operations"]) == 58
    assert {family: snapshot["sources"][family]["operation_count"] for family in DOCUMENT_SOURCES} == {
        "rest": 45,
        "streaming": 8,
        "trends": 3,
        "exploits": 2,
    }


def test_fetch_retries_transient_errors_and_stops_after_three_attempts(monkeypatch) -> None:
    from urllib.error import URLError

    import pytest

    import scripts.refresh_official_snapshot as refresh

    calls = []
    sleeps = []

    def fetch(url, *, timeout):
        calls.append((url, timeout))
        if len(calls) < 3:
            raise URLError("temporary network failure")
        return "<h6>GET /rest</h6>"

    monkeypatch.setattr(refresh, "_fetch_document_once", fetch)
    monkeypatch.setattr(refresh.time, "sleep", sleeps.append)
    assert refresh._fetch_document("https://developer.shodan.io/api", timeout=5).startswith("<h6>")
    assert len(calls) == 3 and sleeps == [1, 2]

    calls.clear()

    def unavailable(url, *, timeout):
        calls.append(url)
        raise URLError("still unavailable")

    monkeypatch.setattr(refresh, "_fetch_document_once", unavailable)
    with pytest.raises(URLError):
        refresh._fetch_document("https://developer.shodan.io/api")
    assert len(calls) == 3


def test_fetch_does_not_retry_permanent_http_failures(monkeypatch) -> None:
    from urllib.error import HTTPError

    import pytest

    import scripts.refresh_official_snapshot as refresh

    def missing(url, *, timeout):
        raise HTTPError(url, 404, "Not Found", None, None)

    def unexpected_sleep(seconds):
        pytest.fail("permanent HTTP errors must not retry")

    monkeypatch.setattr(refresh, "_fetch_document_once", missing)
    monkeypatch.setattr(refresh.time, "sleep", unexpected_sleep)
    with pytest.raises(HTTPError):
        refresh._fetch_document("https://developer.shodan.io/api")


def test_snapshot_report_distinguishes_inventory_and_text_changes() -> None:
    from scripts.refresh_official_snapshot import snapshot_report

    documents = {family: f"<h6>GET /{family}</h6><p>old text</p>" for family in DOCUMENT_SOURCES}
    old = build_snapshot(documents)
    changed = build_snapshot({**documents, "rest": "<h6>GET /rest/new</h6>"})
    report = snapshot_report(old, changed)
    assert "Added: `rest GET /rest/new`" in report
    assert "Removed: `rest GET /rest`" in report
    changed = build_snapshot({**documents, "rest": "<h6>GET /rest</h6><p>new text</p>"})
    report = snapshot_report(old, changed)
    assert "All 4 method/path pairs are unchanged" in report
    assert "Text changes can still affect API behavior" in report


def test_check_writes_candidate_and_report_without_accepting_drift(tmp_path, monkeypatch) -> None:
    import yaml

    import scripts.refresh_official_snapshot as refresh

    documents = {family: f"<h6>GET /{family}</h6>" for family in DOCUMENT_SOURCES}
    old = build_snapshot(documents, retrieved_at="2026-01-01")
    current = build_snapshot({**documents, "rest": "<h6>GET /rest/new</h6>"})
    path, candidate, report = (tmp_path / name for name in ("accepted.yaml", "candidate.yaml", "report.md"))
    path.write_text(yaml.safe_dump(old))
    accepted = path.read_bytes()
    monkeypatch.setattr(refresh, "fetch_snapshot", lambda **kwargs: current)
    assert (
        refresh.main(
            ["--check", "--snapshot", str(path), "--candidate-snapshot", str(candidate), "--report", str(report)]
        )
        == 1
    )
    assert path.read_bytes() == accepted
    assert refresh.load_snapshot(candidate) == current
    assert "Added:" in report.read_text()


def test_write_skips_date_only_changes_and_fetch_failure_preserves_snapshot(tmp_path, monkeypatch) -> None:
    from urllib.error import URLError

    import yaml

    import scripts.refresh_official_snapshot as refresh

    documents = {family: f"<h6>GET /{family}</h6>" for family in DOCUMENT_SOURCES}
    old = build_snapshot(documents, retrieved_at="2026-01-01")
    current = build_snapshot(documents, retrieved_at="2026-01-02")
    path = tmp_path / "snapshot.yaml"
    path.write_text(yaml.safe_dump(old))
    accepted = path.read_bytes()
    monkeypatch.setattr(refresh, "fetch_snapshot", lambda **kwargs: current)
    assert refresh.main(["--write", "--snapshot", str(path)]) == 0
    assert path.read_bytes() == accepted

    def unavailable(**kwargs):
        raise URLError("upstream unavailable")

    monkeypatch.setattr(refresh, "fetch_snapshot", unavailable)
    report = tmp_path / "report.md"
    assert refresh.main(["--write", "--snapshot", str(path), "--report", str(report)]) == 2
    assert path.read_bytes() == accepted
    assert "fetch failed" in report.read_text()


def test_check_rejects_paths_that_would_overwrite_accepted_evidence(tmp_path) -> None:
    import pytest

    from scripts.refresh_official_snapshot import main

    path = str(tmp_path / "snapshot.yaml")
    with pytest.raises(SystemExit):
        main(["--check", "--snapshot", path, "--candidate-snapshot", path])
    with pytest.raises(SystemExit):
        main(["--check", "--snapshot", path, "--report", path])
