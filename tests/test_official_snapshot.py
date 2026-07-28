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
