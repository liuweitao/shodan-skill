from __future__ import annotations

import json
import os
import subprocess
import sysconfig
from pathlib import Path


def console_path() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return Path(sysconfig.get_path("scripts")) / f"shodan-skill{suffix}"


def run_console(*args: str, home: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env.pop("SHODAN_API_KEY", None)
    return subprocess.run(
        [str(console_path()), *args],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_installed_console_help_and_version(tmp_path: Path) -> None:
    help_result = run_console("--help", home=tmp_path)
    assert help_result.returncode == 0
    assert "Portable CLI" in help_result.stdout
    version_result = run_console("--version", home=tmp_path)
    assert version_result.returncode == 0
    assert version_result.stdout.strip() == "shodan-skill 2.0.1"


def test_installed_console_group_help_is_local_and_shows_subcommands(tmp_path: Path) -> None:
    for group in ("host", "search", "scan", "trends", "stream"):
        result = run_console(group, "--help", home=tmp_path)
        assert result.returncode == 0
        assert "{" in result.stdout
        assert "authentication" not in result.stderr


def test_installed_console_local_command_without_key(tmp_path: Path) -> None:
    result = run_console("reference", "filters", home=tmp_path)
    assert result.returncode == 0
    assert json.loads(result.stdout)["ok"] is True
    assert result.stderr == ""
