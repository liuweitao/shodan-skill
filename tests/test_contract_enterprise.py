from __future__ import annotations

import hashlib
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
from shodan_skill.transport import USER_AGENT, HttpTransport

ENTERPRISE_OPERATION_IDS = {
    "shodan-data-list",
    "shodan-data-files",
    "shodan-org-info",
    "shodan-org-member-add",
    "shodan-org-member-remove",
}


class FailingDownloadStream(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        yield b"partial"
        raise httpx.ReadError("disconnected")


@pytest.mark.parametrize(
    ("args", "method", "path"),
    [
        (["data", "list"], "GET", "/shodan/data"),
        (["data", "files", "raw-daily"], "GET", "/shodan/data/raw-daily"),
        (["org", "info"], "GET", "/org"),
        (["org", "member", "add", "user@example.com", "--yes"], "PUT", "/org/member/user@example.com"),
        (["org", "member", "remove", "user@example.com", "--yes"], "DELETE", "/org/member/user@example.com"),
    ],
    ids=[
        "shodan-data-list",
        "shodan-data-files",
        "shodan-org-info",
        "shodan-org-member-add",
        "shodan-org-member-remove",
    ],
)
def test_enterprise_http_contracts(
    tmp_path: Path,
    args: list[str],
    method: str,
    path: str,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=[] if request.url.path.startswith("/shodan/data") else {"success": True})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        args,
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "enterprise-test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 0, stderr.getvalue()
    assert len(seen) == 1
    assert seen[0].method == method
    assert seen[0].url.path == path
    assert seen[0].headers["user-agent"] == USER_AGENT
    assert dict(seen[0].url.params) == {"key": "enterprise-test-key"}
    payload = json.loads(stdout.getvalue())
    assert set(payload) == {"ok", "data", "meta", "error"}
    assert payload["ok"] is True
    assert payload["meta"]["credit_impact"] == "none"
    assert payload["meta"]["credits_estimated"] is None
    assert payload["meta"]["credits_used"] is None
    assert payload["error"] is None
    if method != "GET":
        assert '"preview"' in stderr.getvalue()


@pytest.mark.parametrize(("option", "expected"), [("--notify", "true"), ("--no-notify", "false")])
def test_org_member_add_supports_documented_notification_option(
    tmp_path: Path,
    option: str,
    expected: str,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"success": True})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    assert (
        run(
            ["org", "member", "add", "user@example.com", option, "--yes"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
            environ={"SHODAN_API_KEY": "test-key"},
            home=tmp_path,
            transport_factory=factory,
        )
        == 0
    )
    assert requests[0].url.params["notify"] == expected


def test_org_member_add_preview_discloses_the_notification_mode(tmp_path: Path) -> None:
    for option, expected in (
        ([], "email-notification=service-default"),
        (["--notify"], "email-notification=true"),
        (["--no-notify"], "email-notification=false"),
    ):
        stderr = io.StringIO()
        code = run(
            ["--dry-run", "org", "member", "add", "user@example.com", *option],
            stdout=io.StringIO(),
            stderr=stderr,
            environ={},
            home=tmp_path,
            transport_factory=lambda _settings: pytest.fail("unconfirmed membership change created a transport"),
        )

        assert code == 0
        assert json.loads(stderr.getvalue())["data"]["preview"]["identifiers"] == [
            "user@example.com",
            expected,
        ]


def test_dataset_download_verifies_signed_url_and_checksum(tmp_path: Path) -> None:
    content = b"dataset-content"
    checksum = hashlib.sha1(content, usedforsecurity=False).hexdigest()
    output = tmp_path / "dataset.json.gz"
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "api.shodan.io":
            return httpx.Response(
                200,
                json=[
                    {
                        "name": "daily.json.gz",
                        "url": "https://downloads.example.invalid/daily?signature=signed-secret",
                        "size": len(content),
                        "sha1": checksum,
                    }
                ],
            )
        return httpx.Response(200, content=content)

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        ["data", "download", "raw-daily", "daily.json.gz", "--output-file", str(output), "--yes"],
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "enterprise-test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 0, stderr.getvalue()
    assert output.read_bytes() == content
    assert not output.with_name(f"{output.name}.part").exists()
    assert seen[0].url.path == "/shodan/data/raw-daily"
    assert seen[1].headers.get("range") is None
    assert "key" not in seen[1].url.params
    payload = json.loads(stdout.getvalue())["data"]
    assert payload == {"path": str(output), "bytes": len(content), "sha1": checksum}
    assert "signed-secret" not in stdout.getvalue() + stderr.getvalue()


def test_dataset_download_resumes_partial_file(tmp_path: Path) -> None:
    content = b"abcdef"
    checksum = hashlib.sha1(content, usedforsecurity=False).hexdigest()
    output = tmp_path / "resumed.bin"
    output.with_name(f"{output.name}.part").write_bytes(b"abc")
    ranges: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.shodan.io":
            return httpx.Response(
                200,
                json=[
                    {
                        "name": "archive.bin",
                        "url": "https://downloads.example.invalid/archive",
                        "size": len(content),
                        "sha1": checksum,
                    }
                ],
            )
        ranges.append(request.headers.get("range"))
        return httpx.Response(206, headers={"Content-Range": "bytes 3-5/6"}, content=b"def")

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    assert (
        run(
            ["data", "download", "raw", "archive.bin", "--output-file", str(output), "--resume", "--yes"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
            environ={"SHODAN_API_KEY": "test-key"},
            home=tmp_path,
            transport_factory=factory,
        )
        == 0
    )
    assert ranges == ["bytes=3-"]
    assert output.read_bytes() == content


def test_interrupted_dataset_download_preserves_partial_file(tmp_path: Path) -> None:
    output = tmp_path / "interrupted.bin"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.shodan.io":
            return httpx.Response(
                200,
                json=[
                    {
                        "name": "archive.bin",
                        "url": "https://downloads.example.invalid/archive",
                        "size": 100,
                    }
                ],
            )
        return httpx.Response(200, stream=FailingDownloadStream())

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stderr = io.StringIO()
    code = run(
        [
            "data",
            "download",
            "raw",
            "archive.bin",
            "--output-file",
            str(output),
            "--chunk-size",
            "3",
            "--yes",
        ],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 6
    assert output.with_name(f"{output.name}.part").read_bytes() == b"partia"
    assert not output.exists()


@pytest.mark.parametrize("failure", ["checksum", "size", "disk"])
def test_dataset_download_integrity_and_disk_failures(tmp_path: Path, failure: str) -> None:
    output = tmp_path / "output.bin"
    content = b"content"
    if failure == "disk":
        blocker = tmp_path / "not-a-directory"
        blocker.write_text("block", encoding="utf-8")
        output = blocker / "output.bin"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.shodan.io":
            return httpx.Response(
                200,
                json=[
                    {
                        "name": "archive.bin",
                        "url": "https://downloads.example.invalid/archive",
                        "size": len(content) + (1 if failure == "size" else 0),
                        "sha1": "0" * 40
                        if failure == "checksum"
                        else hashlib.sha1(content, usedforsecurity=False).hexdigest(),
                    }
                ],
            )
        return httpx.Response(200, content=content)

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stderr = io.StringIO()
    code = run(
        ["data", "download", "raw", "archive.bin", "--output-file", str(output), "--yes"],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == (2 if failure == "disk" else 7)
    expected_code = "usage" if failure == "disk" else "api"
    assert f'"code": "{expected_code}"' in stderr.getvalue()


@pytest.mark.parametrize(
    "metadata",
    [
        {"name": "archive.bin", "url": "https://downloads.example.invalid/archive"},
        {
            "name": "archive.bin",
            "url": "https://downloads.example.invalid/archive",
            "size": True,
        },
        {
            "name": "archive.bin",
            "url": "https://downloads.example.invalid/archive",
            "size": 7,
            "sha1": "not-a-sha1",
        },
    ],
)
def test_dataset_download_rejects_malformed_integrity_metadata_before_file_request(
    tmp_path: Path,
    metadata: dict[str, object],
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=[metadata])

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stderr = io.StringIO()
    code = run(
        [
            "data",
            "download",
            "raw",
            "archive.bin",
            "--output-file",
            str(tmp_path / "archive.bin"),
            "--yes",
        ],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 7
    assert '"code": "api"' in stderr.getvalue()
    assert len(requests) == 1


def test_dataset_download_rejects_directory_destination_before_transport(tmp_path: Path) -> None:
    destination = tmp_path / "existing-directory"
    destination.mkdir()
    code = run(
        [
            "data",
            "download",
            "raw",
            "archive.bin",
            "--output-file",
            str(destination),
            "--overwrite",
            "--yes",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=lambda _settings: pytest.fail("directory destination created a transport"),
    )
    assert code == 2


def test_dataset_download_preserves_existing_partial_without_explicit_resume_or_overwrite(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "archive.bin"
    partial = destination.with_name(f"{destination.name}.part")
    partial.write_bytes(b"preserve")
    stderr = io.StringIO()

    code = run(
        [
            "data",
            "download",
            "raw",
            "archive.bin",
            "--output-file",
            str(destination),
            "--yes",
        ],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={"SHODAN_API_KEY": "test-key"},
        home=tmp_path,
        transport_factory=lambda _settings: pytest.fail("existing partial created a transport"),
    )

    assert code == 2
    assert "partial" in json.loads(stderr.getvalue())["error"]["message"].lower()
    assert partial.read_bytes() == b"preserve"


def test_resuming_a_partial_download_is_not_claimed_reversible(tmp_path: Path) -> None:
    destination = tmp_path / "archive.bin"
    destination.with_name(f"{destination.name}.part").write_bytes(b"partial")
    stderr = io.StringIO()

    code = run(
        [
            "--dry-run",
            "data",
            "download",
            "raw",
            "archive.bin",
            "--output-file",
            str(destination),
            "--resume",
        ],
        stdout=io.StringIO(),
        stderr=stderr,
        environ={},
        home=tmp_path,
        transport_factory=lambda _settings: pytest.fail("unconfirmed resume created a transport"),
    )

    assert code == 0
    assert json.loads(stderr.getvalue())["data"]["preview"]["reversible"] is False


@pytest.mark.parametrize(
    "args",
    [
        ["org", "member", "add", "user@example.com"],
        ["org", "member", "remove", "user@example.com"],
        ["data", "download", "raw", "archive.bin"],
    ],
)
def test_strict_mode_requires_confirmation_for_enterprise_operations(tmp_path: Path, args: list[str]) -> None:
    created = False

    def forbidden(_settings: Settings) -> Any:
        nonlocal created
        created = True
        pytest.fail("transport created before confirmation")

    stderr = io.StringIO()
    assert (
        run(
            args,
            stdout=io.StringIO(),
            stderr=stderr,
            environ={"SHODAN_API_KEY": "test-key", "SHODAN_SAFETY_MODE": "strict"},
            home=tmp_path,
            transport_factory=forbidden,
        )
        == 2
    )
    assert created is False
    assert json.loads(stderr.getvalue())["error"]["code"] == "usage"


@pytest.mark.parametrize(
    "args",
    [
        ["data", "download", "../raw", "archive.bin", "--yes"],
        ["data", "download", "raw", "../archive.bin", "--yes"],
        ["data", "download", "raw", "archive.bin", "--resume", "--overwrite", "--yes"],
        ["data", "download", "raw", "archive.bin", "--chunk-size", "0", "--yes"],
        ["data", "download", "raw", "archive.bin", "--chunk-size", "16777217", "--yes"],
        ["org", "member", "add", "../user", "--yes"],
    ],
)
def test_enterprise_invalid_inputs_fail_before_transport(tmp_path: Path, args: list[str]) -> None:
    created = False

    def forbidden(_settings: Settings) -> Any:
        nonlocal created
        created = True
        pytest.fail("transport created for invalid input")

    assert (
        run(
            args,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
            environ={"SHODAN_API_KEY": "test-key"},
            home=tmp_path,
            transport_factory=forbidden,
        )
        == 2
    )
    assert created is False


def test_enterprise_manifest_entries_are_complete_and_contract_tested() -> None:
    operations = {operation["id"]: operation for operation in load_manifest(DEFAULT_MANIFEST)["operations"]}
    for operation_id in ENTERPRISE_OPERATION_IDS:
        assert operations[operation_id]["implementation"] == "complete"
        assert operations[operation_id]["contract_test"] == "complete"
