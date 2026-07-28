from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from scripts.verify_coverage import DEFAULT_MANIFEST, load_manifest
from shodan_skill.cli import run
from shodan_skill.config import Settings
from shodan_skill.errors import NetworkError
from shodan_skill.transport import USER_AGENT, HttpTransport

SECONDARY_SERVICE_OPERATION_IDS = {
    "shodan-stream-banners",
    "shodan-stream-asn",
    "shodan-stream-countries",
    "shodan-stream-ports",
    "shodan-stream-vulns",
    "shodan-stream-alerts",
    "shodan-stream-alert",
    "shodan-stream-custom",
    "shodan-trends-search",
    "shodan-trends-filters",
    "shodan-trends-facets",
    "shodan-exploits-search",
    "shodan-exploits-count",
}


@pytest.mark.parametrize(
    ("args", "host", "path", "query"),
    [
        (
            ["trends", "search", "product:nginx", "--facets", "country:10"],
            "trends.shodan.io",
            "/api/v1/search",
            {"query": "product:nginx", "facets": "country:10"},
        ),
        (["trends", "filters"], "trends.shodan.io", "/api/v1/search/filters", {}),
        (["trends", "facets"], "trends.shodan.io", "/api/v1/search/facets", {}),
        (
            ["exploits", "search", "apache", "--page", "2", "--facets", "platform:5"],
            "exploits.shodan.io",
            "/api/search",
            {"query": "apache", "page": "2", "facets": "platform:5"},
        ),
        (
            ["exploits", "count", "apache", "--facets", "platform:5"],
            "exploits.shodan.io",
            "/api/count",
            {"query": "apache", "facets": "platform:5"},
        ),
    ],
    ids=[
        "shodan-trends-search",
        "shodan-trends-filters",
        "shodan-trends-facets",
        "shodan-exploits-search",
        "shodan-exploits-count",
    ],
)
def test_secondary_http_contracts(
    tmp_path: Path,
    args: list[str],
    host: str,
    path: str,
    query: dict[str, str],
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"matches": [{"id": "x", "code": "abcdef"}]})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stdout, stderr = io.StringIO(), io.StringIO()
    assert (
        run(
            args,
            stdout=stdout,
            stderr=stderr,
            environ={"SHODAN_API_KEY": "test-key"},
            home=tmp_path,
            transport_factory=factory,
        )
        == 0
    )
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "GET"
    assert request.url.host == host
    assert request.url.path == path
    assert request.headers["user-agent"] == USER_AGENT
    assert dict(request.url.params) == {"key": "test-key", **query}
    payload = json.loads(stdout.getvalue())
    assert set(payload) == {"ok", "data", "meta", "error"}
    assert payload["ok"] is True
    assert payload["meta"]["credit_impact"] == "none"
    assert payload["meta"]["credits_estimated"] is None
    assert payload["meta"]["credits_used"] is None
    assert payload["error"] is None


@pytest.mark.parametrize(
    ("args", "path", "query"),
    [
        (["stream", "banners", "--limit", "1", "--debug"], "/shodan/banners", {"debug": "1"}),
        (["stream", "asn", "AS123,456", "--limit", "1"], "/shodan/asn/123,456", {}),
        (["stream", "countries", "us,DE", "--limit", "1"], "/shodan/countries/US,DE", {}),
        (["stream", "ports", "22,443", "--limit", "1"], "/shodan/ports/22,443", {}),
        (["stream", "vulns", "cve-2024-1234", "--limit", "1"], "/shodan/vulns/CVE-2024-1234", {}),
        (["stream", "alerts", "--limit", "1"], "/shodan/alert", {}),
        (["stream", "alert", "alert-1", "--limit", "1"], "/shodan/alert/alert-1", {}),
        (["stream", "custom", "Product:nginx", "--limit", "1"], "/shodan/custom", {"query": "Product:nginx"}),
    ],
    ids=[
        "shodan-stream-banners",
        "shodan-stream-asn",
        "shodan-stream-countries",
        "shodan-stream-ports",
        "shodan-stream-vulns",
        "shodan-stream-alerts",
        "shodan-stream-alert",
        "shodan-stream-custom",
    ],
)
def test_stream_http_contracts(
    tmp_path: Path,
    args: list[str],
    path: str,
    query: dict[str, str],
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b'{"ip_str":"192.0.2.1"}\n')

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stdout, stderr = io.StringIO(), io.StringIO()
    assert (
        run(
            args,
            stdout=stdout,
            stderr=stderr,
            environ={"SHODAN_API_KEY": "test-key"},
            home=tmp_path,
            transport_factory=factory,
        )
        == 0
    )
    assert len(seen) == 1
    request = seen[0]
    assert request.url.host == "stream.shodan.io"
    assert request.url.path == path
    assert request.headers["user-agent"] == USER_AGENT
    assert dict(request.url.params) == {
        "key": "test-key",
        "t": "json",
        "heartbeat": "false",
        **query,
    }
    payload = json.loads(stdout.getvalue())
    assert set(payload) == {"ok", "data", "meta", "error"}
    assert payload["ok"] is True
    assert payload["data"]["ip_str"] == "192.0.2.1"
    assert payload["error"] is None


def test_stream_sse_contract_and_output(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b'data: {"ip_str":"192.0.2.1"}\n\n')

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stdout, stderr = io.StringIO(), io.StringIO()
    assert (
        run(
            ["stream", "banners", "--limit", "1", "--stream-format", "sse"],
            stdout=stdout,
            stderr=stderr,
            environ={"SHODAN_API_KEY": "test-key"},
            home=tmp_path,
            transport_factory=factory,
        )
        == 0
    )
    assert stderr.getvalue() == ""
    assert seen[0].url.params["t"] == "sse"
    assert seen[0].url.params["heartbeat"] == "false"
    assert stdout.getvalue().startswith("data: {")
    assert stdout.getvalue().endswith("\n\n")
    assert json.loads(stdout.getvalue()[6:].strip())["data"]["ip_str"] == "192.0.2.1"


@pytest.mark.parametrize(
    "args",
    [
        ["stream", "ports", "0"],
        ["stream", "countries", "USA"],
        ["stream", "asn", "invalid"],
        ["stream", "asn", "AS4294967296"],
        ["stream", "vulns", "CVE-bad"],
        ["stream", "custom", ""],
        ["stream", "banners", "--max-reconnects", "11"],
        ["exploits", "search", "apache", "--truncate-code", "0"],
    ],
)
def test_secondary_boundaries_fail_before_http(tmp_path: Path, args: list[str]) -> None:
    class NoHttp:
        def __init__(self, _settings: Settings) -> None:
            self.sleeper = lambda _delay: None

        def __enter__(self) -> NoHttp:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def request(self, *_args: Any, **_kwargs: Any) -> Any:
            pytest.fail("invalid input reached request")

        def iter_jsonl(self, *_args: Any, **_kwargs: Any) -> Iterator[Any]:
            pytest.fail("invalid input reached stream")

    stdout, stderr = io.StringIO(), io.StringIO()
    assert (
        run(
            args,
            stdout=stdout,
            stderr=stderr,
            environ={"SHODAN_API_KEY": "test-key"},
            home=tmp_path,
            transport_factory=NoHttp,
        )
        == 2
    )


def test_exploit_code_default_omit_truncate_and_limit(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"matches": [{"code": "abcdef"}, {"code": "second"}]})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    def invoke(extra: list[str]) -> dict[str, Any]:
        stdout = io.StringIO()
        assert (
            run(
                ["exploits", "search", "x", *extra],
                stdout=stdout,
                stderr=io.StringIO(),
                environ={"SHODAN_API_KEY": "test-key"},
                home=tmp_path,
                transport_factory=factory,
            )
            == 0
        )
        return json.loads(stdout.getvalue())["data"]

    assert invoke([])["matches"][0]["code"] == "abcdef"
    assert "code" not in invoke(["--omit-code"])["matches"][0]
    assert invoke(["--truncate-code", "3"])["matches"][0]["code"] == "abc"
    assert len(invoke(["--limit", "1"])["matches"]) == 1


def test_stream_debug_limit_and_bounded_reconnect(tmp_path: Path) -> None:
    class FakeTransport:
        def __init__(self, _settings: Settings) -> None:
            self.calls = 0
            self.delays: list[float] = []
            self.sleeper = self.delays.append

        def __enter__(self) -> FakeTransport:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def iter_jsonl(self, *_args: Any, **_kwargs: Any) -> Iterator[Any]:
            self.calls += 1
            if self.calls == 1:
                yield {"event": "debug", "discarded": 3}
                raise NetworkError("disconnected")
            yield {"banner": 1}
            yield {"banner": 2}

        def iter_sse(self, *_args: Any, **_kwargs: Any) -> Iterator[Any]:
            return self.iter_jsonl()

    instance: FakeTransport | None = None

    def factory(settings: Settings) -> FakeTransport:
        nonlocal instance
        instance = FakeTransport(settings)
        return instance

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        ["stream", "banners", "--limit", "2", "--debug", "--reconnect", "--max-reconnects", "1"],
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 0
    assert instance is not None and instance.calls == 2 and instance.delays == [0.25]
    assert len(stdout.getvalue().splitlines()) == 2
    diagnostics = [json.loads(line)["data"] for line in stderr.getvalue().splitlines()]
    assert diagnostics == [
        {"event": "debug", "discarded": 3},
        {"event": "reconnect", "attempt": 1, "reason": "network"},
    ]


@pytest.mark.parametrize(
    ("status", "reason"),
    [(500, "network"), (502, "network"), (503, "network"), (524, "timeout")],
)
def test_stream_reconnects_after_transient_gateway_failure(tmp_path: Path, status: int, reason: str) -> None:
    calls = 0
    delays: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(status, json={"error": "temporarily unavailable"})
        return httpx.Response(200, content=b'{"banner":1}\n')

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(
            settings,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleeper=delays.append,
        )

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        ["stream", "banners", "--limit", "1", "--reconnect", "--max-reconnects", "1"],
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )

    assert code == 0
    assert calls == 2
    assert delays == [0.25]
    assert json.loads(stdout.getvalue())["data"] == {"banner": 1}
    assert json.loads(stderr.getvalue())["data"] == {
        "event": "reconnect",
        "attempt": 1,
        "reason": reason,
    }


def test_stream_eof_before_limit_is_not_reported_as_success(tmp_path: Path) -> None:
    class ShortStream:
        def __init__(self, _settings: Settings) -> None:
            self.sleeper = lambda _delay: None

        def __enter__(self) -> ShortStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def iter_jsonl(self, *_args: Any, **_kwargs: Any) -> Iterator[Any]:
            yield {"banner": 1}

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        ["stream", "banners", "--limit", "2"],
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=ShortStream,
    )
    assert code == 6
    assert len(stdout.getvalue().splitlines()) == 1
    assert json.loads(stderr.getvalue())["error"]["code"] == "network"


def test_stream_keyboard_interrupt_has_interrupted_exit_code(tmp_path: Path) -> None:
    class InterruptedTransport:
        def __init__(self, _settings: Settings) -> None:
            self.sleeper = lambda _delay: None

        def __enter__(self) -> InterruptedTransport:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def iter_jsonl(self, *_args: Any, **_kwargs: Any) -> Iterator[Any]:
            raise KeyboardInterrupt
            yield

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        ["stream", "banners"],
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=InterruptedTransport,
    )
    assert code == 9
    assert stdout.getvalue() == ""
    assert json.loads(stderr.getvalue())["error"]["code"] == "interrupted"


def test_stream_alert_rejects_path_rewriting_identifier_before_http(tmp_path: Path) -> None:
    class NoHttp:
        def __init__(self, _settings: Settings) -> None:
            pytest.fail("invalid stream identifier created a transport")

    code = run(
        ["stream", "alert", "alert-id/../../banners"],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=NoHttp,
    )
    assert code == 2


def test_secondary_service_manifest_entries_are_complete_and_contract_tested() -> None:
    operations = {operation["id"]: operation for operation in load_manifest(DEFAULT_MANIFEST)["operations"]}
    for operation_id in SECONDARY_SERVICE_OPERATION_IDS:
        assert operations[operation_id]["implementation"] == "complete"
        assert operations[operation_id]["contract_test"] == "complete"
