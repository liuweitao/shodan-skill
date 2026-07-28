from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "shodan_skill.py"


def run_shim(*args: str, home: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env.pop("SHODAN_API_KEY", None)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_shim_help_is_local(tmp_path: Path) -> None:
    result = run_shim("--help", home=tmp_path)
    assert result.returncode == 0
    assert "Portable CLI" in result.stdout


def test_shim_local_reference_is_local_and_deprecated(tmp_path: Path) -> None:
    result = run_shim("filters", home=tmp_path)
    assert result.returncode == 0
    assert json.loads(result.stdout)["ok"] is True
    assert "deprecated" in result.stderr


def test_shim_business_alias_requires_authentication(tmp_path: Path) -> None:
    result = run_shim("host", "192.0.2.1", home=tmp_path)
    assert result.returncode == 3
    assert result.stdout == ""
    assert json.loads(result.stderr[result.stderr.index("{") :])["error"]["code"] == "authentication"
