from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from shodan_skill.cli import LEGACY_PREFIXES, normalize_legacy, run
from shodan_skill.config import Settings
from shodan_skill.errors import ApiError


class FakeTransport:
    instances: ClassVar[list[FakeTransport]] = []

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.calls: list[tuple[Any, ...]] = []
        self.__class__.instances.append(self)

    def __enter__(self) -> FakeTransport:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def request(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((*args, kwargs))
        if kwargs.get("params", {}).get("query") == "fail":
            raise ApiError(f"failure with {self.settings.api_key}")
        return {"matches": [{"id": 1}, {"id": 2}], "api_key": self.settings.api_key}

    def iter_jsonl(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((*args, kwargs))
        return iter([{"id": 1}, {"id": 2}, {"id": 3}])

    def iter_sse(self, *args: Any, **kwargs: Any) -> Any:
        return self.iter_jsonl(*args, **kwargs)


@pytest.fixture(autouse=True)
def clear_instances() -> None:
    FakeTransport.instances.clear()


def invoke(args: list[str], tmp_path: Path, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        args,
        stdout=stdout,
        stderr=stderr,
        environ=env if env is not None else {"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=FakeTransport,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_grouped_host_command_validates_and_calls_transport(tmp_path: Path) -> None:
    code, stdout, stderr = invoke(["host", "info", "192.0.2.1", "--history"], tmp_path)
    assert code == 0
    assert stderr == ""
    payload = json.loads(stdout)
    assert payload["meta"]["command"] == "host-info"
    assert payload["data"]["api_key"] == "[REDACTED]"
    call = FakeTransport.instances[0].calls[0]
    assert call[:3] == ("rest", "GET", "/shodan/host/192.0.2.1")


def test_legacy_aliases_normalize_and_warn(tmp_path: Path) -> None:
    for alias, prefix in LEGACY_PREFIXES.items():
        normalized, detected = normalize_legacy([alias, "value"])
        assert tuple(normalized[:2]) == prefix
        assert detected == alias
    code, _stdout, stderr = invoke(["query_search", "camera"], tmp_path)
    assert code == 0
    assert "deprecated" in stderr


def test_legacy_alert_aliases_preserve_the_official_client_default() -> None:
    assert normalize_legacy(["alert_list"])[0] == ["alert", "list", "--include-expired"]
    assert normalize_legacy(["alert_info", "alert-id"])[0] == [
        "alert",
        "info",
        "alert-id",
        "--include-expired",
    ]
    assert normalize_legacy(["alert_list", "--no-include-expired"])[0] == [
        "alert",
        "list",
        "--no-include-expired",
    ]


def test_legacy_stream_variants_normalize() -> None:
    assert normalize_legacy(["stream", "--ports", "22,443", "--limit", "1"])[0] == [
        "stream",
        "ports",
        "22,443",
        "--limit",
        "1",
    ]
    assert normalize_legacy(["stream", "--alert", "id"])[0] == ["stream", "alert", "id"]
    assert normalize_legacy(["stream", "--limit", "1"])[0] == ["stream", "banners", "--limit", "1"]


@pytest.mark.parametrize("group", ["host", "search", "scan", "trends", "stream"])
def test_group_help_is_not_rewritten_as_a_legacy_command(group: str) -> None:
    assert normalize_legacy([group, "--help"]) == ([group, "--help"], None)


def test_account_help_routes_credit_balances_to_api_info(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        run(["account", "--help"])

    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out
    normalized_help = " ".join(help_text.split())
    assert "api-info" in normalized_help
    assert "API plan, usage limits, and remaining query/scan credits" in normalized_help
    assert "profile" in normalized_help
    assert "not query or scan credit balances" in normalized_help


@pytest.mark.parametrize("option", ["--ports", "--alert"])
def test_legacy_stream_missing_selector_is_a_usage_error(tmp_path: Path, option: str) -> None:
    code, stdout, stderr = invoke(["stream", option], tmp_path)
    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["error"]["code"] == "usage"


def test_local_references_do_not_load_credentials_or_transport(tmp_path: Path) -> None:
    code, stdout, stderr = invoke(["reference", "datapedia"], tmp_path, env={})
    assert code == 0
    assert stderr == ""
    assert "datapedia.shodan.io" in stdout
    reference = json.loads(stdout)["data"]
    assert reference == {
        "overview": "https://datapedia.shodan.io/",
        "banner_schema": "https://datapedia.shodan.io/banner.schema.json",
        "changelog": "https://datapedia.shodan.io/changelog.html",
    }
    assert FakeTransport.instances == []


def test_runtime_options_override_environment_without_implicit_proxy_use(tmp_path: Path) -> None:
    code, stdout, stderr = invoke(
        [
            "--connect-timeout",
            "1.5",
            "--read-timeout",
            "2.5",
            "--write-timeout",
            "3.5",
            "--pool-timeout",
            "4.5",
            "--stream-timeout",
            "5.5",
            "--retries",
            "4",
            "--proxy",
            "https://proxy.example:8443",
            "host",
            "info",
            "192.0.2.1",
        ],
        tmp_path,
        env={
            "SHODAN_API_KEY": "test-key",
            "SHODAN_CONNECT_TIMEOUT": "20",
            "SHODAN_PROXY": "http://environment-proxy.example",
        },
    )

    assert code == 0, stderr
    assert json.loads(stdout)["ok"] is True
    settings = FakeTransport.instances[0].settings
    assert (
        settings.connect_timeout,
        settings.read_timeout,
        settings.write_timeout,
        settings.pool_timeout,
        settings.stream_timeout,
        settings.retries,
        settings.proxy,
    ) == (1.5, 2.5, 3.5, 4.5, 5.5, 4, "https://proxy.example:8443")


def test_proxy_credentials_are_redacted_when_argument_parsing_fails(tmp_path: Path) -> None:
    proxy = "https://user:proxy-password@proxy.example:8443"
    code, stdout, stderr = invoke(["--proxy", proxy, "--unknown"], tmp_path)

    assert (code, stdout) == (2, "")
    assert proxy not in stderr
    assert "proxy-password" not in stderr


def test_environment_proxy_credentials_are_redacted_from_runtime_errors(tmp_path: Path) -> None:
    proxy = "https://user:p%40ssword@proxy.example:8443"
    stdout, stderr = io.StringIO(), io.StringIO()

    def fail(settings: Settings) -> FakeTransport:
        raise ApiError(
            "proxy connection failed",
            details={"proxy": settings.proxy, "decoded_password": "p@ssword"},
        )

    code = run(
        ["host", "info", "192.0.2.1"],
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key", "SHODAN_PROXY": proxy},
        home=tmp_path,
        transport_factory=fail,
    )

    assert (code, stdout.getvalue()) == (7, "")
    assert proxy not in stderr.getvalue()
    assert "p%40ssword" not in stderr.getvalue()
    assert "p@ssword" not in stderr.getvalue()
    assert "[REDACTED]" in stderr.getvalue()


def test_missing_auth_invalid_input_and_api_error_are_nonzero(tmp_path: Path) -> None:
    code, stdout, stderr = invoke(["host", "info", "192.0.2.1"], tmp_path, env={})
    assert (code, stdout) == (3, "")
    assert json.loads(stderr)["error"]["code"] == "authentication"
    code, _, stderr = invoke(["host", "info", "not-an-ip"], tmp_path)
    assert code == 2
    assert json.loads(stderr)["error"]["code"] == "usage"
    code, _, stderr = invoke(
        ["search", "hosts", "fail", "--yes"],
        tmp_path,
        env={"SHODAN_API_KEY": "sensitive-key"},
    )
    assert code == 7
    assert "sensitive-key" not in stderr
    assert "[REDACTED]" in stderr


def test_notifier_secret_is_redacted_even_when_argument_parsing_fails(tmp_path: Path) -> None:
    secret = "supersecret-value"
    code, stdout, stderr = invoke(
        [
            "notifier",
            "create",
            "webhook",
            "--arg",
            f"url={secret}",
            "--description",
            "test",
            "--yes",
            "--unknown",
            f"url={secret}",
        ],
        tmp_path,
    )

    assert code == 2
    assert stdout == ""
    assert secret not in stderr
    assert "[REDACTED]" in stderr


def test_equals_style_notifier_secret_is_redacted_when_argument_parsing_fails(tmp_path: Path) -> None:
    secret = "equals-style-secret"
    code, stdout, stderr = invoke(
        [
            "notifier",
            "edit",
            "notifier-id",
            f"--arg=url={secret}",
            "--yes",
            "--unknown",
            f"url={secret}",
        ],
        tmp_path,
    )

    assert code == 2
    assert stdout == ""
    assert secret not in stderr
    assert "[REDACTED]" in stderr


def test_misspelled_notifier_option_cannot_leak_its_webhook_url(tmp_path: Path) -> None:
    secret = "https://hooks.example.invalid/private-opaque"
    code, stdout, stderr = invoke(
        [
            "notifier",
            "edit",
            "notifier-id",
            f"--argg=url={secret}",
            "--yes",
        ],
        tmp_path,
    )

    assert code == 2
    assert stdout == ""
    assert secret not in stderr
    assert "[REDACTED]" in stderr


def test_unsupported_credential_option_cannot_leak_its_separate_value(tmp_path: Path) -> None:
    secret = "short-private-value"
    code, stdout, stderr = invoke(
        [
            "host",
            "info",
            "192.0.2.1",
            "--api-key",
            secret,
        ],
        tmp_path,
    )

    assert code == 2
    assert stdout == ""
    assert secret not in stderr
    assert "[REDACTED]" in stderr


def test_unexpected_exception_maps_to_internal_without_leaking_details(tmp_path: Path) -> None:
    def exploding_factory(_settings: Settings) -> FakeTransport:
        raise RuntimeError("sensitive-key must never be displayed")

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        ["host", "info", "192.0.2.1"],
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "sensitive-key"},
        home=tmp_path,
        transport_factory=exploding_factory,
    )

    assert code == 10
    assert stdout.getvalue() == ""
    payload = json.loads(stderr.getvalue())
    assert payload["error"] == {
        "code": "internal",
        "message": "Unexpected internal error.",
        "details": {"type": "RuntimeError"},
    }
    assert "sensitive-key" not in stderr.getvalue()


def test_unexpected_value_error_is_not_misclassified_as_user_input(tmp_path: Path) -> None:
    def exploding_factory(_settings: Settings) -> FakeTransport:
        raise ValueError("library invariant failed")

    stderr = io.StringIO()
    code = run(
        ["host", "info", "192.0.2.1"],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=exploding_factory,
    )

    assert code == 10
    assert json.loads(stderr.getvalue())["error"]["details"] == {"type": "ValueError"}


def test_invalid_runtime_settings_remain_a_usage_error(tmp_path: Path) -> None:
    code, stdout, stderr = invoke(
        ["host", "info", "192.0.2.1"],
        tmp_path,
        env={"SHODAN_API_KEY": "test-key", "SHODAN_RETRIES": "invalid"},
    )
    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["error"]["code"] == "usage"


@pytest.mark.parametrize(
    "args",
    [
        ["search", "hosts", "   "],
        ["search", "count", ""],
        ["search", "tokens", "\t"],
        ["query", "search", "  "],
        ["trends", "search", "\n"],
        ["exploits", "search", ""],
        ["exploits", "count", " "],
        ["stream", "custom", "  "],
    ],
)
def test_blank_queries_fail_before_credentials_or_transport(tmp_path: Path, args: list[str]) -> None:
    code, stdout, stderr = invoke(args, tmp_path, env={})
    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["error"]["code"] == "usage"
    assert FakeTransport.instances == []


def test_search_and_exploit_limits_are_client_side(tmp_path: Path) -> None:
    code, stdout, _ = invoke(["search", "hosts", "nginx", "--limit", "1", "--yes"], tmp_path)
    assert code == 0
    assert len(json.loads(stdout)["data"]["matches"]) == 1
    code, stdout, _ = invoke(["exploits", "search", "cve", "--limit", "1"], tmp_path)
    assert code == 0
    assert len(json.loads(stdout)["data"]["matches"]) == 1


def test_stream_limit_and_sse_selection(tmp_path: Path) -> None:
    code, stdout, _ = invoke(["stream", "banners", "--limit", "2", "--stream-format", "sse"], tmp_path)
    assert code == 0
    events = [event for event in stdout.split("\n\n") if event]
    assert len(events) == 2
    assert all(event.startswith("data: ") for event in events)
    assert all(json.loads(event[6:])["ok"] for event in events)


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "submit", "192.0.2.1", "--yes", "--acknowledge-authorization"],
        ["alert", "info", "alert-id"],
        ["alert", "create", "test", "192.0.2.0/24", "--yes", "--acknowledge-authorization"],
        ["dns", "domain", "example.com", "--yes"],
        ["account", "api-info"],
        ["tools", "myip"],
        ["query", "search", "camera"],
        ["query", "tags"],
        ["notifier", "list"],
    ],
)
def test_additional_group_routes_return_success(tmp_path: Path, args: list[str]) -> None:
    code, stdout, _ = invoke(args, tmp_path)
    assert code == 0
    assert json.loads(stdout)["ok"] is True


def test_human_output_and_limit_validation(tmp_path: Path) -> None:
    code, stdout, _ = invoke(["--output", "human", "search", "count", "nginx"], tmp_path)
    assert code == 0
    assert '"matches"' in stdout
    code, _, stderr = invoke(["search", "hosts", "nginx", "--page", "0"], tmp_path)
    assert code == 2
    assert "at least 1" in stderr


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["scan", "ports"], ("rest", "GET", "/shodan/ports")),
        (["alert", "list"], ("rest", "GET", "/shodan/alert/info")),
        (["dns", "resolve", "example.com"], ("rest", "GET", "/dns/resolve")),
        (["account", "profile"], ("rest", "GET", "/account/profile")),
        (["trends", "search", "nginx"], ("trends", "GET", "/api/v1/search")),
    ],
)
def test_representative_group_routes(tmp_path: Path, args: list[str], expected: tuple[str, str, str]) -> None:
    code, _, _ = invoke(args, tmp_path)
    assert code == 0
    assert FakeTransport.instances[0].calls[0][:3] == expected


@pytest.mark.parametrize(
    "args",
    [
        ["search", "hosts", "product:nginx"],
        ["dns", "domain", "example.com"],
    ],
)
def test_credit_consuming_read_operations_execute_directly_by_default(
    tmp_path: Path,
    args: list[str],
) -> None:
    code, stdout, stderr = invoke(args, tmp_path)
    assert code == 0
    assert json.loads(stdout)["ok"] is True
    assert json.loads(stderr)["data"]["preview"]["credit_impact"]
    assert len(FakeTransport.instances) == 1
    assert len(FakeTransport.instances[0].calls) == 1


@pytest.mark.parametrize(
    "args",
    [
        ["search", "hosts", "product:nginx"],
        ["dns", "domain", "example.com"],
    ],
)
def test_strict_mode_preserves_confirmation_gate(tmp_path: Path, args: list[str]) -> None:
    code, stdout, stderr = invoke(
        args,
        tmp_path,
        env={"SHODAN_API_KEY": "test-key", "SHODAN_SAFETY_MODE": "strict"},
    )
    assert code == 2
    assert stdout == ""
    error = json.loads(stderr)["error"]
    assert error["code"] == "usage"
    assert error["details"]["credit_impact"]
    assert FakeTransport.instances == []


def test_dry_run_never_requires_strict_mode_confirmation(tmp_path: Path) -> None:
    code, stdout, stderr = invoke(
        ["--dry-run", "scan", "submit", "192.0.2.1"],
        tmp_path,
        env={"SHODAN_SAFETY_MODE": "strict"},
    )
    assert code == 0
    assert stdout == ""
    assert json.loads(stderr)["data"]["preview"]["operation"] == "scan-submit"
    assert FakeTransport.instances == []


@pytest.mark.parametrize(
    "args",
    [
        ["alert", "delete", "alert-id", "--y"],
        ["alert", "delete", "alert-id", "--conf"],
        ["scan", "submit", "192.0.2.1", "--yes", "--ack"],
    ],
)
def test_safety_flags_require_exact_option_names(tmp_path: Path, args: list[str]) -> None:
    code, stdout, stderr = invoke(args, tmp_path)

    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["error"]["code"] == "usage"
    assert FakeTransport.instances == []


def test_search_preview_does_not_present_client_side_limit_as_target_count(tmp_path: Path) -> None:
    code, stdout, stderr = invoke(
        ["--dry-run", "search", "hosts", "product:nginx", "--page", "2", "--limit", "1"],
        tmp_path,
        env={},
    )

    assert code == 0
    assert stdout == ""
    preview = json.loads(stderr)["data"]["preview"]
    assert preview["target_count"] is None
    assert preview["identifiers"] == ["product:nginx", "page=2", "client-limit=1"]
    assert FakeTransport.instances == []
