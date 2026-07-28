from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from scripts.verify_coverage import DEFAULT_MANIFEST, load_manifest
from shodan_skill.cli import run
from shodan_skill.config import Settings
from shodan_skill.transport import USER_AGENT, HttpTransport

READ_ONLY_OPERATION_IDS = {
    "shodan-host-info",
    "shodan-host-count",
    "shodan-host-search",
    "shodan-search-facets",
    "shodan-search-filters",
    "shodan-search-tokens",
    "shodan-ports",
    "shodan-protocols",
    "shodan-query-list",
    "shodan-query-search",
    "shodan-query-tags",
    "shodan-account-profile",
    "shodan-dns-domain",
    "shodan-dns-resolve",
    "shodan-dns-reverse",
    "shodan-tools-httpheaders",
    "shodan-tools-myip",
    "shodan-api-info",
}


@pytest.mark.parametrize(
    ("args", "method", "path", "query"),
    [
        (
            ["host", "info", "2001:db8::1", "--history", "--minify"],
            "GET",
            "/shodan/host/2001:db8::1",
            {"history": "true", "minify": "true"},
        ),
        (
            ["search", "count", "product:nginx", "--facets", "country:5"],
            "GET",
            "/shodan/host/count",
            {"query": "product:nginx", "facets": "country:5"},
        ),
        (
            [
                "search",
                "hosts",
                "product:nginx",
                "--page",
                "2",
                "--facets",
                "country",
                "--no-minify",
                "--fields",
                "tags,http.title",
                "--yes",
            ],
            "GET",
            "/shodan/host/search",
            {
                "query": "product:nginx",
                "page": "2",
                "facets": "country",
                "minify": "false",
                "fields": "tags,http.title",
            },
        ),
        (["search", "facets"], "GET", "/shodan/host/search/facets", {}),
        (["search", "filters"], "GET", "/shodan/host/search/filters", {}),
        (["search", "tokens", "Raspbian port:22"], "GET", "/shodan/host/search/tokens", {"query": "Raspbian port:22"}),
        (["scan", "ports"], "GET", "/shodan/ports", {}),
        (["scan", "protocols"], "GET", "/shodan/protocols", {}),
        (
            ["query", "list", "--page", "2", "--sort", "votes", "--order", "asc"],
            "GET",
            "/shodan/query",
            {"page": "2", "sort": "votes", "order": "asc"},
        ),
        (["query", "search", "camera", "--page", "3"], "GET", "/shodan/query/search", {"query": "camera", "page": "3"}),
        (["query", "tags", "--limit", "7"], "GET", "/shodan/query/tags", {"size": "7"}),
        (["account", "profile"], "GET", "/account/profile", {}),
        (["account", "api-info"], "GET", "/api-info", {}),
        (
            ["dns", "domain", "example.com", "--history", "--type", "A", "--page", "2", "--yes"],
            "GET",
            "/dns/domain/example.com",
            {"history": "true", "type": "A", "page": "2"},
        ),
        (
            ["dns", "resolve", "example.com,www.example.com"],
            "GET",
            "/dns/resolve",
            {"hostnames": "example.com,www.example.com"},
        ),
        (["dns", "reverse", "192.0.2.1,2001:db8::1"], "GET", "/dns/reverse", {"ips": "192.0.2.1,2001:db8::1"}),
        (["tools", "httpheaders"], "GET", "/tools/httpheaders", {}),
        (["tools", "myip"], "GET", "/tools/myip", {}),
    ],
    ids=[
        "shodan-host-info",
        "shodan-host-count",
        "shodan-host-search",
        "shodan-search-facets",
        "shodan-search-filters",
        "shodan-search-tokens",
        "shodan-ports",
        "shodan-protocols",
        "shodan-query-list",
        "shodan-query-search",
        "shodan-query-tags",
        "shodan-account-profile",
        "shodan-api-info",
        "shodan-dns-domain",
        "shodan-dns-resolve",
        "shodan-dns-reverse",
        "shodan-tools-httpheaders",
        "shodan-tools-myip",
    ],
)
def test_readonly_http_contracts(
    tmp_path: Path,
    args: list[str],
    method: str,
    path: str,
    query: dict[str, str],
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"matches": [], "received": True})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        args,
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "contract-test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 0, stderr.getvalue()
    assert len(seen) == 1
    request = seen[0]
    assert request.method == method
    assert request.url.path == path
    assert request.headers["user-agent"] == USER_AGENT
    assert dict(request.url.params) == {"key": "contract-test-key", **query}
    payload = json.loads(stdout.getvalue())
    assert set(payload) == {"ok", "data", "meta", "error"}
    assert payload["ok"] is True
    assert payload["data"] == {"matches": [], "received": True}
    expected_impact = (
        "conditional" if args[:2] == ["search", "hosts"] else "query" if args[:2] == ["dns", "domain"] else "none"
    )
    assert payload["meta"]["credit_impact"] == expected_impact
    assert payload["meta"]["credits_estimated"] == (1 if args[:2] == ["dns", "domain"] else None)
    assert payload["meta"]["credits_used"] is None
    assert payload["error"] is None
    assert "contract-test-key" not in stdout.getvalue()


@pytest.mark.parametrize(
    "args",
    [
        ["search", "hosts", "product:nginx", "--yes"],
        ["dns", "domain", "example.com", "--yes"],
    ],
)
def test_credit_consuming_get_requests_are_not_automatically_retried(tmp_path: Path, args: list[str]) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"error": "temporarily unavailable"})

    def factory(settings: Settings) -> HttpTransport:
        settings = Settings(
            api_key=settings.api_key,
            connect_timeout=settings.connect_timeout,
            read_timeout=settings.read_timeout,
            write_timeout=settings.write_timeout,
            pool_timeout=settings.pool_timeout,
            stream_timeout=settings.stream_timeout,
            retries=5,
        )
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    code = run(
        args,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )

    assert code == 7
    assert calls == 1


@pytest.mark.parametrize(
    "args",
    [
        ["host", "info", "fe80::1%scope?query=rewritten"],
        ["scan", "status", "../api-info"],
        ["alert", "info", "alert-id/../../api-info"],
        ["notifier", "info", "notifier-id/../provider"],
    ],
)
def test_readonly_identifiers_cannot_rewrite_endpoint_before_transport(tmp_path: Path, args: list[str]) -> None:
    code = run(
        args,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=lambda _settings: pytest.fail("unsafe identifier created a transport"),
    )
    assert code == 2


@pytest.mark.parametrize(
    "args",
    [
        ["host", "info", "999.1.1.1"],
        ["search", "hosts", "nginx", "--page", "0"],
        ["query", "list", "--page", "0"],
        ["query", "search", "camera", "--page", "0"],
        ["dns", "domain", "bad domain"],
        ["dns", "domain", "example.com", "--page", "0"],
        ["dns", "resolve", "example.com,bad domain"],
        ["dns", "reverse", "192.0.2.1,invalid"],
        ["dns", "reverse", "fe80::1%scope"],
    ],
)
def test_readonly_boundaries_fail_before_http(tmp_path: Path, args: list[str]) -> None:
    class NoHttp:
        def __init__(self, _settings: Settings) -> None:
            pass

        def __enter__(self) -> NoHttp:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def request(self, *_args: Any, **_kwargs: Any) -> Any:
            pytest.fail("invalid input reached HTTP transport")

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        args,
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=NoHttp,
    )
    assert code == 2
    assert stdout.getvalue() == ""
    assert json.loads(stderr.getvalue())["error"]["code"] == "usage"


def test_read_only_manifest_entries_are_complete_and_contract_tested() -> None:
    operations = {operation["id"]: operation for operation in load_manifest(DEFAULT_MANIFEST)["operations"]}
    assert operations.keys() >= READ_ONLY_OPERATION_IDS
    for operation_id in READ_ONLY_OPERATION_IDS:
        assert operations[operation_id]["implementation"] == "complete"
        assert operations[operation_id]["contract_test"] == "complete"
