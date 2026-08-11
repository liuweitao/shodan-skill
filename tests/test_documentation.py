from __future__ import annotations

import io
import json
import re
import subprocess
from pathlib import Path

import httpx
import pytest

from scripts.verify_manual import verify as verify_manual
from shodan_skill.cli import run
from shodan_skill.config import Settings
from shodan_skill.transport import HttpTransport

README_COMMANDS = [
    ["host", "info", "8.8.8.8"],
    ["search", "hosts", "product:nginx", "--facets", "country:5", "--yes"],
    ["search", "count", "port:443"],
    ["dns", "domain", "example.com", "--history", "--yes"],
    ["exploits", "search", "apache", "--page", "2", "--omit-code"],
    ["stream", "ports", "22,443", "--limit", "10"],
]


@pytest.mark.parametrize("args", README_COMMANDS)
def test_readme_command_examples_execute_against_mocks(tmp_path: Path, args: list[str]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "stream.shodan.io":
            return httpx.Response(200, content=b'{"banner":true}\n' * 10)
        return httpx.Response(200, json={"matches": []})

    def factory(settings: Settings) -> HttpTransport:
        return HttpTransport(settings, client=httpx.Client(transport=httpx.MockTransport(handler)))

    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(
        args,
        stdout=stdout,
        stderr=stderr,
        environ={"SHODAN_API_KEY": "documentation-test-key"},
        home=tmp_path,
        transport_factory=factory,
    )
    assert code == 0, stderr.getvalue()
    payload = stdout.getvalue().splitlines()[0] if args[0] == "stream" else stdout.getvalue()
    assert json.loads(payload)["ok"] is True


def test_readme_release_claims_and_text_are_safe() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    readme_cn = Path("README_CN.md").read_text(encoding="utf-8")
    safety = Path("references/safety.md").read_text(encoding="utf-8")
    skill = Path("SKILL.md").read_text(encoding="utf-8")
    assert "not affiliated with, endorsed by, or sponsored by Shodan" in readme
    assert "非官方" in readme_cn
    assert "2.0.1" in readme
    assert "python -m pip install shodan-skill" in readme
    assert "python -m pip install shodan-skill" in readme_cn
    assert "img.shields.io/pypi/v/shodan-skill.svg" in readme
    assert "img.shields.io/pypi/v/shodan-skill.svg" in readme_cn
    assert readme.index("python -m pip install shodan-skill") < readme.index("## Verified scope")
    assert readme_cn.index("python -m pip install shodan-skill") < readme_cn.index("## 已验证范围")
    assert "major portable rewrite" in readme
    assert "重大可移植重构" in readme_cn
    assert "58 operations" in readme
    assert "45 REST" in readme and "8 Streaming" in readme and "3 Trends" in readme and "2 Exploits" in readme
    assert "~/.shodan/api_key" in readme and "~/.config/shodan/api_key" in readme
    assert "--debug" in readme and "heartbeat" in readme
    assert "--debug" in readme_cn and "heartbeat" in readme_cn
    assert "--output json" in readme_cn and "--output jsonl" in readme_cn and "--output human" in readme_cn
    assert "SHODAN_PROXY" in readme
    assert "credits_estimated" in readme and "credit_impact" in readme
    assert "refresh_official_snapshot.py --check" in readme
    assert "shodan.io/static" not in readme
    assert "�" not in readme
    assert not re.search(r"^### ", readme, re.MULTILINE)
    assert "target authorization for mutations, scans, alerts, and downloads" not in skill
    assert "without a second confirmation" in skill
    assert "SHODAN_SAFETY_MODE=strict" in readme
    assert "SHODAN_SAFETY_MODE=strict" in readme_cn
    assert "SHODAN_SAFETY_MODE=strict" in safety
    for path in (
        "manual/en/getting-started/installation.md",
        "manual/en/getting-started/quickstart.md",
        "manual/zh/getting-started/installation.md",
        "manual/zh/getting-started/quickstart.md",
    ):
        assert "python -m pip install shodan-skill" in Path(path).read_text(encoding="utf-8")
    for gate in (
        "SHODAN_LIVE_TESTS=1",
        "--allow-live-shodan",
        "--allow-shodan-credits",
        "SHODAN_MUTATING_TESTS=1",
        "--allow-shodan-mutations",
        "SHODAN_ENTERPRISE_TESTS=1",
        "SHODAN_TEST_TARGETS",
    ):
        assert gate in readme
        assert gate in readme_cn
        assert gate in safety
    for platform in ("openclaw", "codex", "claude-code", "hermes"):
        command = f"python scripts/install_skill.py --platform {platform}"
        assert command in readme
        assert command in readme_cn
    for group in (
        "host",
        "search",
        "scan",
        "alert",
        "notifier",
        "query",
        "dns",
        "tools",
        "account",
        "stream",
        "trends",
        "exploits",
        "data",
        "org",
        "reference",
    ):
        assert group in readme


def test_account_credit_balance_intents_route_to_api_info() -> None:
    skill = Path("SKILL.md").read_text(encoding="utf-8")
    reference = Path("references/dns-and-tools.md").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")
    readme_cn = Path("README_CN.md").read_text(encoding="utf-8")

    for text in (skill, reference, readme):
        assert "account api-info" in text
        assert "account profile" in text
        assert "query" in text and "scan" in text and "credit" in text
    assert "remaining-credit" in skill and "credit-balance" in skill
    assert "generic `credits` field" in reference
    assert "剩余查询或扫描积分" in readme_cn
    assert "通用的 `credits` 字段不能作为" in readme_cn


def test_markdown_layout_separates_runtime_and_project_documents() -> None:
    tracked_markdown = subprocess.run(
        ["git", "ls-files", "--", "*.md"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.splitlines()
    tracked_root_markdown = {Path(path).name for path in tracked_markdown if Path(path).parent == Path(".")}
    assert tracked_root_markdown == {"README.md", "README_CN.md", "SECURITY.md", "SKILL.md"}
    assert not re.search(r"[\u4e00-\u9fff]", Path("README.md").read_text(encoding="utf-8"))
    assert re.search(r"[\u4e00-\u9fff]", Path("README_CN.md").read_text(encoding="utf-8"))
    assert not list(Path("references").glob("*_CN.md"))
    tracked_docs = subprocess.run(
        ["git", "ls-files", "--", "docs/*.md"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.splitlines()
    assert tracked_docs == []
    assert "docs/" not in Path("SKILL.md").read_text(encoding="utf-8")


def test_bilingual_manual_is_complete_and_linked() -> None:
    assert verify_manual() == []


def test_gitignore_excludes_local_credential_files() -> None:
    patterns = set(Path(".gitignore").read_text(encoding="utf-8").splitlines())
    assert {
        ".env",
        ".env.*",
        ".envrc",
        ".direnv/",
        "api_key",
        "shodan_api_key",
        ".shodan/",
        ".pypirc",
        ".netrc",
        "_netrc",
        "pip.conf",
        "pip.ini",
        "*.key",
        "*.pem",
        "*.p12",
        "*.pfx",
        "*.jks",
        "*.keystore",
        "id_rsa*",
        "id_ed25519*",
        "id_ecdsa*",
        "id_dsa*",
        "/.agents/",
        "/.claude/",
        "/.codex/",
        "/.hermes/",
        "/.openclaw/",
        ".product-venv/",
        ".eggs/",
        "*.egg",
        "wheels/",
        "pip-wheel-metadata/",
    } <= patterns
    assert ".env.*" in patterns
    assert "api_key" in patterns


def test_operation_references_match_repaired_cli_contracts() -> None:
    streaming = Path("references/streaming.md").read_text(encoding="utf-8")
    mutations = Path("references/scan-and-alerts.md").read_text(encoding="utf-8")
    schemas = Path("references/data-schemas.md").read_text(encoding="utf-8")
    sdk_only = Path("references/sdk-only.md").read_text(encoding="utf-8")
    safety = Path("references/safety.md").read_text(encoding="utf-8")
    assert "--debug" in streaming and "heartbeat=false" in streaming and "case-sensitive" in streaming
    assert "--description TEXT" in mutations
    assert "--description TEXT --yes" not in mutations
    assert "[--description TEXT]" not in mutations
    assert "banner.schema.json" in schemas
    assert "api/exploit-specification" in schemas
    assert "api/event-specification" in schemas
    assert "/shodan/services" in sdk_only
    assert "/labs/honeyscore/{ip}" in sdk_only
    assert "/shodan/tags/{tags}" in sdk_only
    assert "ignores ambient" in safety and "SHODAN_PROXY" in safety
