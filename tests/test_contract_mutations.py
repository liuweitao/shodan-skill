from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from scripts.verify_coverage import DEFAULT_MANIFEST, load_manifest
from shodan_skill.cli import run
from shodan_skill.config import Settings
from shodan_skill.transport import USER_AGENT, HttpTransport

MUTATION_CONTRACT_IDS = {
    "shodan-scan-submit",
    "shodan-scan-internet",
    "shodan-scans-list",
    "shodan-scan-status",
    "shodan-alert-detail",
    "shodan-alert-list",
    "shodan-alert-triggers",
    "shodan-alert-create",
    "shodan-alert-delete",
    "shodan-alert-edit",
    "shodan-alert-trigger-enable",
    "shodan-alert-trigger-disable",
    "shodan-alert-trigger-ignore",
    "shodan-alert-trigger-unignore",
    "shodan-alert-notifier-add",
    "shodan-alert-notifier-remove",
    "shodan-notifier-list",
    "shodan-notifier-detail",
    "shodan-notifier-providers",
    "shodan-notifier-create",
    "shodan-notifier-edit",
    "shodan-notifier-delete",
}


@pytest.mark.parametrize(
    ("args", "method", "path"),
    [
        (["scan", "submit", "192.0.2.1", "--yes", "--acknowledge-authorization"], "POST", "/shodan/scan"),
        (["scan", "internet", "443", "https", "--yes", "--acknowledge-authorization"], "POST", "/shodan/scan/internet"),
        (["scan", "list", "--page", "2"], "GET", "/shodan/scans"),
        (["scan", "status", "scan-id"], "GET", "/shodan/scan/scan-id"),
        (["alert", "info", "alert-id"], "GET", "/shodan/alert/alert-id/info"),
        (["alert", "list"], "GET", "/shodan/alert/info"),
        (["alert", "triggers"], "GET", "/shodan/alert/triggers"),
        (
            [
                "alert",
                "create",
                "production",
                "192.0.2.0/24",
                "--expires",
                "30",
                "--yes",
                "--acknowledge-authorization",
            ],
            "POST",
            "/shodan/alert",
        ),
        (["alert", "delete", "alert-id", "--yes"], "DELETE", "/shodan/alert/alert-id"),
        (
            ["alert", "edit", "alert-id", "192.0.2.0/25", "--yes", "--acknowledge-authorization"],
            "POST",
            "/shodan/alert/alert-id",
        ),
        (
            ["alert", "trigger", "enable", "alert-id", "new_service,vulnerable", "--yes"],
            "PUT",
            "/shodan/alert/alert-id/trigger/new_service,vulnerable",
        ),
        (
            ["alert", "trigger", "disable", "alert-id", "new_service", "--yes"],
            "DELETE",
            "/shodan/alert/alert-id/trigger/new_service",
        ),
        (
            ["alert", "trigger", "ignore", "alert-id", "new_service", "192.0.2.1:80", "--yes"],
            "PUT",
            "/shodan/alert/alert-id/trigger/new_service/ignore/192.0.2.1:80",
        ),
        (
            ["alert", "trigger", "unignore", "alert-id", "new_service", "192.0.2.1:80", "--yes"],
            "DELETE",
            "/shodan/alert/alert-id/trigger/new_service/ignore/192.0.2.1:80",
        ),
        (
            ["alert", "notifier", "add", "alert-id", "notifier-id", "--yes"],
            "PUT",
            "/shodan/alert/alert-id/notifier/notifier-id",
        ),
        (
            ["alert", "notifier", "remove", "alert-id", "notifier-id", "--yes"],
            "DELETE",
            "/shodan/alert/alert-id/notifier/notifier-id",
        ),
        (["notifier", "list"], "GET", "/notifier"),
        (["notifier", "info", "notifier-id"], "GET", "/notifier/notifier-id"),
        (["notifier", "providers"], "GET", "/notifier/provider"),
        (
            [
                "notifier",
                "create",
                "webhook",
                "--arg",
                "url=https://example.invalid/hook",
                "--description",
                "test",
                "--yes",
            ],
            "POST",
            "/notifier",
        ),
        (
            ["notifier", "edit", "notifier-id", "--arg", "url=https://example.invalid/new", "--yes"],
            "PUT",
            "/notifier/notifier-id",
        ),
        (["notifier", "delete", "notifier-id", "--yes"], "DELETE", "/notifier/notifier-id"),
    ],
    ids=[
        "shodan-scan-submit",
        "shodan-scan-internet",
        "shodan-scans-list",
        "shodan-scan-status",
        "shodan-alert-detail",
        "shodan-alert-list",
        "shodan-alert-triggers",
        "shodan-alert-create",
        "shodan-alert-delete",
        "shodan-alert-edit",
        "shodan-alert-trigger-enable",
        "shodan-alert-trigger-disable",
        "shodan-alert-trigger-ignore",
        "shodan-alert-trigger-unignore",
        "shodan-alert-notifier-add",
        "shodan-alert-notifier-remove",
        "shodan-notifier-list",
        "shodan-notifier-detail",
        "shodan-notifier-providers",
        "shodan-notifier-create",
        "shodan-notifier-edit",
        "shodan-notifier-delete",
    ],
)
def test_mutation_http_contracts(tmp_path: Path, args: list[str], method: str, path: str) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"success": True, "args": {"password": "should-redact"}})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        args,
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "contract-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 0, stderr.getvalue()
    assert len(seen) == 1
    assert seen[0].method == method
    assert seen[0].url.path == path
    assert seen[0].headers["user-agent"] == USER_AGENT
    expected_query = {"key": "contract-key"}
    if args[:2] == ["scan", "list"]:
        expected_query["page"] = "2"
    assert dict(seen[0].url.params) == expected_query
    payload = json.loads(stdout.getvalue())
    assert set(payload) == {"ok", "data", "meta", "error"}
    assert payload["ok"] is True
    expected_impact = (
        "scan" if args[:2] == ["scan", "submit"] else "unknown" if args[:2] == ["scan", "internet"] else "none"
    )
    assert payload["meta"]["credit_impact"] == expected_impact
    assert payload["meta"]["credits_estimated"] == (1 if args[:2] == ["scan", "submit"] else None)
    assert payload["meta"]["credits_used"] is None
    assert payload["error"] is None
    assert "should-redact" not in stdout.getvalue()
    assert "[REDACTED]" in stdout.getvalue()
    if method != "GET":
        assert '"preview"' in stderr.getvalue()


@pytest.mark.parametrize(
    "args",
    [
        ["alert", "edit", "alert-id", "192.0.2.0/24", "--yes", "--acknowledge-authorization"],
        ["notifier", "edit", "notifier-id", "--arg", "to=test@example.com", "--yes"],
    ],
)
def test_overwriting_mutation_previews_are_not_claimed_reversible(tmp_path: Path, args: list[str]) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stderr = io.StringIO()
    assert (
        run(
            args,
            stdout=io.StringIO(),
            stderr=stderr,
            environ={"SHODAN_API_KEY": "test-key"},
            home=tmp_path,
            transport_factory=factory,
        )
        == 0
    )
    preview = json.loads(stderr.getvalue())["data"]["preview"]
    assert preview["reversible"] is False


def test_scan_preview_counts_unique_canonical_targets_before_authentication(tmp_path: Path) -> None:
    stderr = io.StringIO()
    code = run(
        [
            "--dry-run",
            "scan",
            "submit",
            "192.0.2.1/24,192.0.2.1,2001:db8::1/126,2001:db8::2",
            "--acknowledge-authorization",
        ],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={},
        home=tmp_path,
        transport_factory=lambda _settings: pytest.fail("unconfirmed scan created a transport"),
    )

    assert code == 0
    preview = json.loads(stderr.getvalue())["data"]["preview"]
    assert preview["target_count"] == 260
    assert preview["identifiers"] == ["192.0.2.0/24", "2001:db8::/126"]


def test_scan_preview_includes_every_custom_service_before_confirmation(tmp_path: Path) -> None:
    stderr = io.StringIO()
    code = run(
        [
            "--dry-run",
            "scan",
            "submit",
            "192.0.2.1",
            "--service",
            "443:https",
            "--service",
            "53:dns-udp",
            "--acknowledge-authorization",
        ],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={},
        home=tmp_path,
        transport_factory=lambda _settings: pytest.fail("unconfirmed scan created a transport"),
    )

    assert code == 0
    preview = json.loads(stderr.getvalue())["data"]["preview"]
    assert preview["identifiers"] == [
        "192.0.2.1",
        "service=443:https",
        "service=53:dns-udp",
    ]


def test_scan_and_mutation_request_bodies(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"success": True})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    common = {
        "stdout": io.StringIO(),
        "stderr": io.StringIO(),
        "environ": {"SHODAN_API_KEY": "test-key"},
        "home": tmp_path,
        "transport_factory": factory,
    }
    assert (
        run(
            ["scan", "submit", "192.0.2.1", "--service", "443:https", "--yes", "--acknowledge-authorization"],
            **common,
        )
        == 0
    )
    scan_form = parse_qs(requests[-1].content.decode())
    assert requests[-1].headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert json.loads(scan_form["ips"][0]) == {"192.0.2.1": [[443, "https"]]}
    assert (
        run(
            [
                "scan",
                "submit",
                "192.0.2.1/24,192.0.2.1,198.51.100.1/32",
                "--yes",
                "--acknowledge-authorization",
            ],
            **common,
        )
        == 0
    )
    scan_form = parse_qs(requests[-1].content.decode())
    assert requests[-1].headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert scan_form["ips"] == ["192.0.2.0/24,198.51.100.1"]
    assert run(["scan", "internet", "443", "https", "--yes", "--acknowledge-authorization"], **common) == 0
    assert requests[-1].headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert parse_qs(requests[-1].content.decode()) == {"port": ["443"], "protocol": ["https"]}
    assert (
        run(
            [
                "alert",
                "create",
                "test",
                "192.0.2.0/24,198.51.100.1",
                "--expires",
                "60",
                "--yes",
                "--acknowledge-authorization",
            ],
            **common,
        )
        == 0
    )
    assert requests[-1].headers["content-type"] == "application/json"
    assert json.loads(requests[-1].content) == {
        "name": "test",
        "filters": {"ip": ["192.0.2.0/24", "198.51.100.1"]},
        "expires": 60,
    }
    assert (
        run(
            [
                "alert",
                "edit",
                "alert-id",
                "192.0.2.0/25,198.51.100.1",
                "--yes",
                "--acknowledge-authorization",
            ],
            **common,
        )
        == 0
    )
    assert requests[-1].headers["content-type"] == "application/json"
    assert json.loads(requests[-1].content) == {"filters": {"ip": ["192.0.2.0/25", "198.51.100.1"]}}
    assert (
        run(
            [
                "notifier",
                "create",
                "webhook",
                "--arg",
                "url=https://example.invalid",
                "--arg",
                "token=value",
                "--description",
                "test",
                "--yes",
            ],
            **common,
        )
        == 0
    )
    assert requests[-1].headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert parse_qs(requests[-1].content.decode()) == {
        "provider": ["webhook"],
        "url": ["https://example.invalid"],
        "token": ["value"],
        "description": ["test"],
    }
    assert (
        run(
            [
                "notifier",
                "edit",
                "notifier-id",
                "--arg",
                "url=https://example.invalid/new",
                "--yes",
            ],
            **common,
        )
        == 0
    )
    assert requests[-1].headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert parse_qs(requests[-1].content.decode()) == {"url": ["https://example.invalid/new"]}


def test_documented_optional_scan_and_alert_parameters(tmp_path: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"success": True})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    common = {
        "stdout": io.StringIO(),
        "stderr": io.StringIO(),
        "environ": {"SHODAN_API_KEY": "test-key"},
        "home": tmp_path,
        "transport_factory": factory,
    }
    assert (
        run(
            [
                "scan",
                "submit",
                "192.0.2.1",
                "--force",
                "--yes",
                "--acknowledge-authorization",
            ],
            **common,
        )
        == 0
    )
    assert parse_qs(requests[-1].content.decode()) == {"ips": ["192.0.2.1"], "force": ["true"]}
    assert run(["alert", "list", "--include-expired"], **common) == 0
    assert requests[-1].url.params["include_expired"] == "true"
    assert run(["alert", "info", "alert-id", "--no-include-expired"], **common) == 0
    assert requests[-1].url.params["include_expired"] == "false"


DIRECT_MUTATIONS = [
    ["scan", "submit", "192.0.2.1", "--acknowledge-authorization"],
    ["scan", "internet", "443", "https", "--acknowledge-authorization"],
    ["alert", "create", "test", "192.0.2.0/24", "--acknowledge-authorization"],
    ["alert", "delete", "alert-id"],
    ["alert", "edit", "alert-id", "192.0.2.0/24", "--acknowledge-authorization"],
    ["alert", "trigger", "enable", "alert-id", "new_service"],
    ["alert", "trigger", "disable", "alert-id", "new_service"],
    ["alert", "trigger", "ignore", "alert-id", "new_service", "192.0.2.1:80"],
    ["alert", "trigger", "unignore", "alert-id", "new_service", "192.0.2.1:80"],
    ["alert", "notifier", "add", "alert-id", "notifier-id"],
    ["alert", "notifier", "remove", "alert-id", "notifier-id"],
    ["notifier", "create", "email", "--arg", "to=test@example.com", "--description", "test"],
    ["notifier", "edit", "notifier-id", "--arg", "to=test@example.com"],
    ["notifier", "delete", "notifier-id"],
]


@pytest.mark.parametrize("args", DIRECT_MUTATIONS)
def test_mutations_execute_directly_without_confirmation(tmp_path: Path, args: list[str]) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"success": True})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        args,
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 0, stderr.getvalue()
    assert len(requests) == 1
    assert json.loads(stderr.getvalue())["data"]["preview"]["operation"]


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "submit", "192.0.2.1", "--yes"],
        ["scan", "internet", "443", "https", "--yes"],
        ["alert", "create", "test", "192.0.2.0/24", "--yes"],
        ["alert", "edit", "alert-id", "192.0.2.0/24", "--yes"],
    ],
)
def test_strict_mode_requires_scan_authorization_acknowledgement(tmp_path: Path, args: list[str]) -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        args,
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_SAFETY_MODE": "strict"},
        home=tmp_path,
        transport_factory=lambda _settings: None,
    )
    assert code == 2
    assert "Authorization acknowledgement" in stderr.getvalue()


@pytest.mark.parametrize(
    ("args", "status", "message", "exit_code"),
    [
        (["scan", "submit", "192.0.2.1", "--yes", "--acknowledge-authorization"], 402, "No scan credits", 5),
        (
            ["scan", "internet", "443", "https", "--yes", "--acknowledge-authorization"],
            403,
            "Enterprise plan required",
            4,
        ),
        (["alert", "info", "missing"], 404, "Alert not found", 7),
        (["notifier", "info", "invalid"], 404, "Invalid notifier", 7),
        (["alert", "create", "duplicate", "192.0.2.0/24", "--yes", "--acknowledge-authorization"], 409, "Conflict", 7),
    ],
)
def test_mutation_error_mapping(
    tmp_path: Path,
    args: list[str],
    status: int,
    message: str,
    exit_code: int,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": message})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(
            settings,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            sleeper=lambda _delay: None,
        )

    code = run(
        args,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == exit_code


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "submit", "invalid", "--yes", "--acknowledge-authorization"],
        ["scan", "submit", "fe80::1%scope?query=rewritten", "--yes", "--acknowledge-authorization"],
        ["scan", "submit", "192.0.2.1", "--service", "bad", "--yes", "--acknowledge-authorization"],
        ["scan", "submit", "192.0.2.1", "--service", "443: https", "--yes", "--acknowledge-authorization"],
        ["scan", "internet", "443", " ", "--yes", "--acknowledge-authorization"],
        ["alert", "create", "", "192.0.2.0/24", "--yes", "--acknowledge-authorization"],
        ["alert", "create", "test", "192.0.2.0/24", "--expires", "-1", "--yes", "--acknowledge-authorization"],
        ["alert", "create", "test", "invalid", "--yes", "--acknowledge-authorization"],
        ["notifier", "create", "", "--arg", "to=test@example.com", "--description", "test", "--yes"],
        ["notifier", "create", "email", "--arg", "bad", "--description", "test", "--yes"],
        [
            "notifier",
            "create",
            "webhook",
            "--arg",
            "provider=email",
            "--description",
            "test",
            "--yes",
        ],
    ],
)
def test_invalid_mutation_inputs_fail_before_transport(tmp_path: Path, args: list[str]) -> None:
    created = False

    def factory(_settings: Settings) -> Any:
        nonlocal created
        created = True
        return None

    code = run(
        args,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 2
    assert created is False


@pytest.mark.parametrize(
    "args",
    [
        ["alert", "delete", "alert-id/trigger/new_service", "--yes"],
        ["alert", "edit", "alert-id/../other", "192.0.2.0/24", "--yes", "--acknowledge-authorization"],
        ["alert", "trigger", "enable", "alert-id/../other", "new_service", "--yes"],
        ["alert", "trigger", "disable", "alert-id", "new/service", "--yes"],
        ["alert", "trigger", "enable", "alert-id", "new_service,,vulnerable", "--yes"],
        ["alert", "trigger", "enable", "alert-id", "new_service,../other", "--yes"],
        ["alert", "trigger", "ignore", "alert-id", "new_service,vulnerable", "192.0.2.1:80", "--yes"],
        ["alert", "trigger", "ignore", "alert-id", "new_service", "192.0.2.1:80/extra", "--yes"],
        ["alert", "trigger", "ignore", "alert-id", "new_service", "[fe80::1%scope?x=y]:80", "--yes"],
        ["alert", "notifier", "add", "alert-id", "notifier/id", "--yes"],
        ["notifier", "edit", "notifier/id", "--arg", "to=test@example.com", "--yes"],
        ["notifier", "delete", "../notifier-id", "--yes"],
        ["notifier", "delete", "..", "--yes"],
    ],
)
def test_mutation_path_segments_cannot_rewrite_confirmed_endpoint(tmp_path: Path, args: list[str]) -> None:
    created = False

    def factory(_settings: Settings) -> Any:
        nonlocal created
        created = True
        pytest.fail("unsafe mutation identifier created a transport")

    code = run(
        args,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 2
    assert created is False


def test_notifier_create_requires_description_before_transport(tmp_path: Path) -> None:
    created = False

    def factory(_settings: Settings) -> Any:
        nonlocal created
        created = True
        pytest.fail("missing notifier description created a transport")

    stderr = io.StringIO()
    code = run(
        ["notifier", "create", "email", "--arg", "to=test@example.com", "--yes"],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 2
    assert created is False
    assert "description" in stderr.getvalue()


def test_notifier_create_rejects_blank_description_before_transport(tmp_path: Path) -> None:
    code = run(
        [
            "notifier",
            "create",
            "email",
            "--arg",
            "to=test@example.com",
            "--description",
            " ",
            "--yes",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=lambda _settings: pytest.fail("blank description created a transport"),
    )
    assert code == 2


def test_notifier_api_error_cannot_echo_submitted_secret(tmp_path: Path) -> None:
    secret_url = "https://hooks.example.invalid/services/private-value"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": f"Invalid url={secret_url}"})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stderr = io.StringIO()
    code = run(
        [
            "notifier",
            "create",
            "webhook",
            "--arg",
            f"url={secret_url}",
            "--description",
            "test",
            "--yes",
        ],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 7
    assert secret_url not in stderr.getvalue()
    assert "[REDACTED]" in stderr.getvalue()


def test_mutation_manifest_entries_are_complete_and_contract_tested() -> None:
    operations = {operation["id"]: operation for operation in load_manifest(DEFAULT_MANIFEST)["operations"]}
    assert operations.keys() >= MUTATION_CONTRACT_IDS
    for operation_id in MUTATION_CONTRACT_IDS:
        assert operations[operation_id]["implementation"] == "complete"
        assert operations[operation_id]["contract_test"] == "complete"
