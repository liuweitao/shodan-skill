from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timezone
from email.utils import format_datetime
from hashlib import sha1
from pathlib import Path

import httpx
import pytest

import shodan_skill.transport as transport_module
from shodan_skill.config import Settings
from shodan_skill.errors import (
    ApiError,
    AuthenticationError,
    AuthorizationError,
    CreditsError,
    NetworkError,
    TimeoutError,
)
from shodan_skill.transport import USER_AGENT, HttpTransport


class ChunkStream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    def __iter__(self) -> Iterator[bytes]:
        yield from self.chunks


def make_transport(handler: httpx.MockTransport, **settings: object) -> HttpTransport:
    values = {"api_key": "test-key", **settings}
    return HttpTransport(Settings(**values), client=httpx.Client(transport=handler), sleeper=lambda _delay: None)


def test_owned_client_ignores_environment_proxies_and_requires_explicit_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def close(self) -> None:
            return None

    monkeypatch.setattr(transport_module.httpx, "Client", FakeClient)
    transport = HttpTransport(
        Settings(
            api_key="test-key",
            proxy="https://user:password@proxy.example:8443",
        )
    )
    transport.close()

    assert captured["trust_env"] is False
    assert captured["proxy"] == "https://user:password@proxy.example:8443"
    assert captured["headers"] == {"User-Agent": USER_AGENT}


def test_request_contract_and_secret_safe_parameters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/shodan/alert"
        assert request.url.params["key"] == "test-key"
        assert request.url.params["page"] == "2"
        assert request.headers["user-agent"] == USER_AGENT
        assert json.loads(request.content) == {"name": "test"}
        return httpx.Response(200, json={"id": "alert"})

    transport = make_transport(httpx.MockTransport(handler))
    result = transport.request(
        "rest",
        "POST",
        "/shodan/alert",
        params={"page": 2, "unused": None},
        json_body={"name": "test"},
    )
    assert result == {"id": "alert"}


def test_authenticated_boolean_query_parameters_use_lowercase_json_spelling() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    make_transport(httpx.MockTransport(handler)).request(
        "rest",
        "GET",
        "/api-info",
        params={"enabled": True, "disabled": False},
    )

    assert seen[0].url.params["enabled"] == "true"
    assert seen[0].url.params["disabled"] == "false"


def test_form_body_is_supported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.content == b"ips=192.0.2.1"
        return httpx.Response(200, json={"ok": True})

    assert make_transport(httpx.MockTransport(handler)).request(
        "rest", "POST", "/shodan/scan", form_body={"ips": "192.0.2.1"}
    ) == {"ok": True}


def test_successful_no_content_response_is_not_treated_as_malformed_json() -> None:
    handler = httpx.MockTransport(lambda _request: httpx.Response(204))
    assert make_transport(handler).request("rest", "DELETE", "/shodan/alert/example") is None


def test_retry_after_and_bounded_retry() -> None:
    calls = 0
    delays: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, headers={"Retry-After": "1.5"}, json={"error": "busy"})
        return httpx.Response(200, json={"ok": True})

    transport = HttpTransport(
        Settings(api_key="test-key", retries=2),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleeper=delays.append,
    )
    assert transport.request("rest", "GET", "/api-info") == {"ok": True}
    assert calls == 2
    assert delays == [1.5]


def test_non_get_requests_are_not_retried() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"error": "busy"})

    with pytest.raises(ApiError):
        make_transport(httpx.MockTransport(handler), retries=5).request("rest", "POST", "/shodan/scan")
    assert calls == 1


def test_retry_can_be_disabled_for_credit_consuming_get_requests() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"error": "busy"})

    with pytest.raises(ApiError):
        make_transport(httpx.MockTransport(handler), retries=5).request(
            "rest",
            "GET",
            "/shodan/host/search",
            params={"query": "product:nginx"},
            retry=False,
        )
    assert calls == 1


@pytest.mark.parametrize(
    ("status", "message", "exception"),
    [
        (401, "Invalid API key", AuthenticationError),
        (403, "Access denied", AuthorizationError),
        (402, "No scan credits", CreditsError),
        (402, "Payment required", CreditsError),
        (408, "Request timeout", TimeoutError),
        (504, "Gateway timeout", TimeoutError),
        (524, "Upstream timeout", TimeoutError),
        (500, "Server error", ApiError),
    ],
)
def test_status_mapping(status: int, message: str, exception: type[Exception]) -> None:
    handler = httpx.MockTransport(lambda _request: httpx.Response(status, json={"error": message}))
    with pytest.raises(exception):
        make_transport(handler, retries=0).request("rest", "GET", "/api-info")


def test_timeout_network_and_malformed_response_mapping() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("late", request=request)

    with pytest.raises(TimeoutError):
        make_transport(httpx.MockTransport(timeout), retries=0).request("rest", "GET", "/api-info")

    def network(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    with pytest.raises(NetworkError):
        make_transport(httpx.MockTransport(network), retries=0).request("rest", "GET", "/api-info")
    malformed = httpx.MockTransport(lambda _request: httpx.Response(200, text="not-json"))
    with pytest.raises(ApiError, match="malformed JSON"):
        make_transport(malformed).request("rest", "GET", "/api-info")
    nonfinite = httpx.MockTransport(lambda _request: httpx.Response(200, text='{"value": NaN}'))
    with pytest.raises(ApiError, match="non-finite"):
        make_transport(nonfinite).request("rest", "GET", "/api-info")


def test_success_status_with_api_error_payload_is_not_reported_as_success() -> None:
    handler = httpx.MockTransport(lambda _request: httpx.Response(200, json={"error": "Invalid query"}))
    with pytest.raises(ApiError, match="Invalid query"):
        make_transport(handler).request("rest", "GET", "/shodan/host/search")


def test_structured_api_error_payload_is_not_reported_as_success() -> None:
    handler = httpx.MockTransport(lambda _request: httpx.Response(200, json={"error": {"message": "Invalid query"}}))
    with pytest.raises(ApiError, match="Shodan returned an API error"):
        make_transport(handler).request("rest", "GET", "/shodan/host/search")


def test_jsonl_and_sse_stream_parsing_across_fragmented_chunks() -> None:
    jsonl = httpx.MockTransport(
        lambda _request: httpx.Response(200, stream=ChunkStream([b'{"a":', b'1}\n{"b":2', b"}\n"]))
    )
    assert list(make_transport(jsonl).iter_jsonl("streaming", "/shodan/banners")) == [{"a": 1}, {"b": 2}]
    sse = httpx.MockTransport(
        lambda _request: httpx.Response(200, stream=ChunkStream([b'data: {"a":', b"1}\r\n\r\n", b'data: {"b":2}\n\n']))
    )
    assert list(make_transport(sse).iter_sse("streaming", "/shodan/banners")) == [{"a": 1}, {"b": 2}]

    carriage_returns = httpx.MockTransport(
        lambda _request: httpx.Response(200, stream=ChunkStream([b'data: {"cr":true}\r\r']))
    )
    assert list(make_transport(carriage_returns).iter_sse("streaming", "/shodan/banners")) == [{"cr": True}]
    split_crlf = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            stream=ChunkStream([b'data: {"split":\r', b"\ndata: true}\r\n\r\n"]),
        )
    )
    assert list(make_transport(split_crlf).iter_sse("streaming", "/shodan/banners")) == [{"split": True}]


def test_malformed_stream_item_is_typed_error() -> None:
    handler = httpx.MockTransport(lambda _request: httpx.Response(200, stream=ChunkStream([b"bad\n"])))
    with pytest.raises(ApiError, match="malformed JSON"):
        list(make_transport(handler).iter_jsonl("streaming", "/shodan/banners"))


def test_owned_client_context_manager_closes() -> None:
    transport = HttpTransport(Settings(api_key="test-key", retries=0))
    client = transport.client
    with transport as entered:
        assert entered is transport
    assert client.is_closed


def test_timeout_and_network_failures_retry_before_succeeding() -> None:
    for exception_type in (httpx.ReadTimeout, httpx.ConnectError):
        calls = 0

        def handler(
            request: httpx.Request,
            error_type: type[httpx.RequestError] = exception_type,
        ) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise error_type("temporary", request=request)
            return httpx.Response(200, json={"ok": True})

        assert make_transport(httpx.MockTransport(handler), retries=1).request("rest", "GET", "/api-info") == {
            "ok": True
        }
        assert calls == 2


def test_stream_timeout_and_network_are_typed() -> None:
    for exception_type, expected in ((httpx.ReadTimeout, TimeoutError), (httpx.ConnectError, NetworkError)):

        def handler(
            request: httpx.Request,
            error_type: type[httpx.RequestError] = exception_type,
        ) -> httpx.Response:
            raise error_type("stream failure", request=request)

        with pytest.raises(expected):
            list(make_transport(httpx.MockTransport(handler)).iter_bytes("streaming", "/shodan/banners"))


def test_streaming_http_errors_are_typed_without_reading_failures() -> None:
    handler = httpx.MockTransport(
        lambda _request: httpx.Response(401, stream=ChunkStream([b'{"error":"Invalid API key"}']))
    )
    with pytest.raises(AuthenticationError, match="Invalid API key"):
        list(make_transport(handler).iter_bytes("streaming", "/shodan/banners"))


def test_download_http_errors_are_typed_without_reading_failures(tmp_path: Path) -> None:
    handler = httpx.MockTransport(
        lambda _request: httpx.Response(403, stream=ChunkStream([b'{"error":"Enterprise required"}']))
    )
    with pytest.raises(AuthorizationError, match="Enterprise required"):
        make_transport(handler).download_file(
            "https://downloads.example.invalid/archive",
            tmp_path / "archive.bin",
        )


def test_backoff_bounds_and_non_json_error_fallback() -> None:
    assert HttpTransport._backoff(0, "invalid") == 0.25
    assert HttpTransport._backoff(0, "NaN") == 0.25
    assert HttpTransport._backoff(10, None) == 4.0
    assert HttpTransport._backoff(0, "99") == 30.0
    retry_at = format_datetime(datetime.fromtimestamp(1015, tz=timezone.utc), usegmt=True)
    assert HttpTransport._backoff(0, retry_at, now=1000) == 15.0
    handler = httpx.MockTransport(lambda _request: httpx.Response(500, text="html"))
    with pytest.raises(ApiError, match="request failed"):
        make_transport(handler, retries=0).request("rest", "GET", "/api-info")


def test_backoff_handles_platform_timestamp_range_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenTimestamp:
        tzinfo = timezone.utc

        @staticmethod
        def timestamp() -> float:
            raise OSError("timestamp is outside the platform range")

    monkeypatch.setattr(transport_module, "parsedate_to_datetime", lambda _value: BrokenTimestamp())
    assert HttpTransport._backoff(1, "valid-looking-date") == 0.5


def test_sse_ignores_events_without_data() -> None:
    handler = httpx.MockTransport(
        lambda _request: httpx.Response(200, stream=ChunkStream([b": keepalive\n\n", b"event: debug\n\n"]))
    )
    assert list(make_transport(handler).iter_sse("streaming", "/shodan/banners")) == []


def test_stream_parsers_handle_split_utf8_and_unterminated_sse_event() -> None:
    encoded = '{"text":"雪"}\n'.encode()
    jsonl = httpx.MockTransport(
        lambda _request: httpx.Response(200, stream=ChunkStream([encoded[:10], encoded[10:11], encoded[11:]]))
    )
    assert list(make_transport(jsonl).iter_jsonl("streaming", "/shodan/banners")) == [{"text": "雪"}]
    sse = httpx.MockTransport(lambda _request: httpx.Response(200, stream=ChunkStream([b'data: {"final":', b"true}"])))
    assert list(make_transport(sse).iter_sse("streaming", "/shodan/banners")) == [{"final": True}]


@pytest.mark.parametrize(
    ("method", "payload"),
    [
        ("iter_jsonl", b'{"text":"\xff"}\n'),
        ("iter_sse", b'data: {"text":"\xff"}\n\n'),
    ],
)
def test_stream_parsers_map_invalid_utf8_to_api_error(method: str, payload: bytes) -> None:
    handler = httpx.MockTransport(lambda _request: httpx.Response(200, stream=ChunkStream([payload])))
    iterator = getattr(make_transport(handler), method)("streaming", "/shodan/banners")
    with pytest.raises(ApiError, match="UTF-8"):
        list(iterator)


@pytest.mark.parametrize(
    ("method", "payload"),
    [
        ("iter_jsonl", b'{"value":NaN}\n'),
        ("iter_sse", b'data: {"value":Infinity}\n\n'),
    ],
)
def test_stream_parsers_reject_nonfinite_json_numbers(method: str, payload: bytes) -> None:
    handler = httpx.MockTransport(lambda _request: httpx.Response(200, stream=ChunkStream([payload])))
    iterator = getattr(make_transport(handler), method)("streaming", "/shodan/banners")
    with pytest.raises(ApiError, match="non-finite"):
        list(iterator)


@pytest.mark.parametrize(
    ("method", "payload"),
    [
        ("iter_jsonl", b'{"oversized":true}\n'),
        ("iter_sse", b'data: {"oversized":true}\n\n'),
    ],
)
def test_stream_parsers_bound_individual_frame_memory(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    payload: bytes,
) -> None:
    monkeypatch.setattr(transport_module, "MAX_STREAM_FRAME_CHARS", 8)
    handler = httpx.MockTransport(lambda _request: httpx.Response(200, stream=ChunkStream([payload])))
    iterator = getattr(make_transport(handler), method)("streaming", "/shodan/banners")
    with pytest.raises(ApiError, match="maximum frame size"):
        list(iterator)


@pytest.mark.parametrize("content_range", [None, "bytes 0-2/6", "bytes 3-5/7", "invalid"])
def test_resume_rejects_untrusted_content_range_without_corrupting_partial(
    tmp_path: Path,
    content_range: str | None,
) -> None:
    output = tmp_path / "archive.bin"
    partial = output.with_name(f"{output.name}.part")
    partial.write_bytes(b"abc")

    def handler(_request: httpx.Request) -> httpx.Response:
        headers = {} if content_range is None else {"Content-Range": content_range}
        return httpx.Response(206, headers=headers, content=b"def")

    with pytest.raises(ApiError, match="range"):
        make_transport(httpx.MockTransport(handler)).download_file(
            "https://downloads.example.invalid/archive",
            output,
            expected_size=6,
            resume=True,
        )
    assert partial.read_bytes() == b"abc"
    assert not output.exists()


def test_download_url_rejects_embedded_credentials_before_http(tmp_path: Path) -> None:
    def forbidden(_request: httpx.Request) -> httpx.Response:
        pytest.fail("unsafe signed URL reached HTTP")

    with pytest.raises(ApiError, match="invalid dataset download URL"):
        make_transport(httpx.MockTransport(forbidden)).download_file(
            "https://user:password@downloads.example.invalid/archive",
            tmp_path / "archive.bin",
        )

    with pytest.raises(ApiError, match="chunk size"):
        make_transport(httpx.MockTransport(forbidden)).download_file(
            "https://downloads.example.invalid/archive",
            tmp_path / "archive.bin",
            chunk_size=16 * 1024 * 1024 + 1,
        )


def test_download_preserves_existing_partial_without_resume_or_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "archive.bin"
    partial = output.with_name(f"{output.name}.part")
    partial.write_bytes(b"preserve")

    def forbidden(_request: httpx.Request) -> httpx.Response:
        pytest.fail("existing partial should fail before HTTP")

    with pytest.raises(ApiError, match="partial"):
        make_transport(httpx.MockTransport(forbidden)).download_file(
            "https://downloads.example.invalid/archive",
            output,
            expected_size=8,
        )

    assert partial.read_bytes() == b"preserve"
    assert not output.exists()


def test_resume_finalizes_an_already_complete_verified_partial_without_http(tmp_path: Path) -> None:
    content = b"already complete"
    checksum = sha1(content, usedforsecurity=False).hexdigest()
    output = tmp_path / "archive.bin"
    partial = output.with_name(f"{output.name}.part")
    partial.write_bytes(content)

    def forbidden(_request: httpx.Request) -> httpx.Response:
        pytest.fail("a complete partial download should not make another signed-URL request")

    result = make_transport(httpx.MockTransport(forbidden)).download_file(
        "https://downloads.example.invalid/archive",
        output,
        expected_size=len(content),
        expected_sha1=checksum,
        resume=True,
    )

    assert result == {"path": str(output), "bytes": len(content), "sha1": checksum}
    assert output.read_bytes() == content
    assert not partial.exists()


def test_resume_rejects_partial_larger_than_expected_without_http(tmp_path: Path) -> None:
    output = tmp_path / "archive.bin"
    partial = output.with_name(f"{output.name}.part")
    partial.write_bytes(b"oversized")

    def forbidden(_request: httpx.Request) -> httpx.Response:
        pytest.fail("an oversized partial download should not make another signed-URL request")

    with pytest.raises(ApiError, match="size mismatch"):
        make_transport(httpx.MockTransport(forbidden)).download_file(
            "https://downloads.example.invalid/archive",
            output,
            expected_size=3,
            resume=True,
        )
    assert partial.read_bytes() == b"oversized"
    assert not output.exists()


def test_download_finalization_does_not_clobber_a_destination_created_midflight(tmp_path: Path) -> None:
    output = tmp_path / "archive.bin"

    def handler(_request: httpx.Request) -> httpx.Response:
        output.write_bytes(b"other process")
        return httpx.Response(200, content=b"download")

    with pytest.raises(ApiError, match="already exists"):
        make_transport(httpx.MockTransport(handler)).download_file(
            "https://downloads.example.invalid/archive",
            output,
            expected_size=len(b"download"),
        )

    assert output.read_bytes() == b"other process"
    assert output.with_name(f"{output.name}.part").read_bytes() == b"download"


def test_download_overwrite_replaces_existing_destination_only_when_explicit(tmp_path: Path) -> None:
    output = tmp_path / "archive.bin"
    output.write_bytes(b"old")
    handler = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"new"))

    result = make_transport(handler).download_file(
        "https://downloads.example.invalid/archive",
        output,
        expected_size=3,
        overwrite=True,
    )

    assert result["bytes"] == 3
    assert output.read_bytes() == b"new"


def test_download_safe_finalization_failure_preserves_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "archive.bin"
    handler = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"download"))

    def fail_link(*_args: object, **_kwargs: object) -> None:
        raise OSError("no link")

    monkeypatch.setattr(transport_module.os, "link", fail_link)

    with pytest.raises(ApiError, match="without overwriting"):
        make_transport(handler).download_file(
            "https://downloads.example.invalid/archive",
            output,
            expected_size=len(b"download"),
        )

    assert not output.exists()
    assert output.with_name(f"{output.name}.part").read_bytes() == b"download"


def test_download_stops_before_writing_beyond_expected_size(tmp_path: Path) -> None:
    output = tmp_path / "archive.bin"
    handler = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"unexpectedly large"))

    with pytest.raises(ApiError, match="exceeded"):
        make_transport(handler).download_file(
            "https://downloads.example.invalid/archive",
            output,
            expected_size=3,
        )

    assert not output.exists()
    assert output.with_name(f"{output.name}.part").read_bytes() == b""
