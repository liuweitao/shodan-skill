from __future__ import annotations

import os
import subprocess
import sys
import tarfile
import venv
import zipfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def test_wheel_build_and_contents_are_offline(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(tmp_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    wheel = next(tmp_path.glob("shodan_skill-*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        assert "shodan_skill/cli.py" in names
        assert "shodan_skill/transport.py" in names
        assert {
            "shodan_skill/commands/__init__.py",
            "shodan_skill/commands/operations.py",
            "shodan_skill/commands/streaming.py",
            "shodan_skill/commands/validation.py",
        } <= names
        assert not any(name.startswith("tests/") for name in names)
        entry_points = archive.read("shodan_skill-2.0.0.dist-info/entry_points.txt").decode()
        assert "shodan-skill = shodan_skill.cli:main" in entry_points


def test_sdist_does_not_ship_live_tests_without_the_repository_gates(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", str(tmp_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    sdist = next(tmp_path.glob("shodan_skill-*.tar.gz"))
    with tarfile.open(sdist, "r:gz") as archive:
        names = set(archive.getnames())
        assert not any("/tests/" in name for name in names)
        assert any(name.endswith("/src/shodan_skill/cli.py") for name in names)
        assert any(name.endswith("/SKILL.md") for name in names)
        assert any(name.endswith("/README_CN.md") for name in names)
        assert any(name.endswith("/scripts/install_skill.py") for name in names)
        assert any(name.endswith("/scripts/fixtures/skill-selection.yaml") for name in names)
        assert any(name.endswith("/references/api-coverage.yaml") for name in names)
        assert any(name.endswith("/references/official-api-snapshot.yaml") for name in names)
        assert any(name.endswith("/agents/openai.yaml") for name in names)
        assert any(name.endswith("/SECURITY.md") for name in names)
        assert any(name.endswith("/platforms/codex/shodan-skill/SKILL.md") for name in names)
        assert any(name.endswith("/platforms/claude-code/.claude/skills/shodan-skill/SKILL.md") for name in names)
        assert not any("/manual/" in name for name in names)
        assert not any(name.endswith("/mkdocs.yml") for name in names)
        assert not any(name.endswith("/requirements-docs.txt") for name in names)


def test_wheel_installs_and_runs_from_an_isolated_environment_offline(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheel"
    build_result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(wheel_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert build_result.returncode == 0, build_result.stderr
    wheel = next(wheel_dir.glob("shodan_skill-*.whl"))

    environment = tmp_path / "environment"
    venv.EnvBuilder(with_pip=True).create(environment)
    scripts = environment / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    console = scripts / ("shodan-skill.exe" if os.name == "nt" else "shodan-skill")
    clean_env = os.environ.copy()
    clean_env.pop("PYTHONPATH", None)
    clean_env["PYTHONNOUSERSITE"] = "1"
    site_result = subprocess.run(
        [str(python), "-c", "import site; print(site.getsitepackages()[0])"],
        cwd=tmp_path,
        env=clean_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert site_result.returncode == 0, site_result.stderr
    dependency_site = Path(httpx.__file__).resolve().parent.parent
    Path(site_result.stdout.strip(), "_offline-test-dependencies.pth").write_text(
        str(dependency_site),
        encoding="utf-8",
    )

    install_result = subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            str(wheel),
        ],
        cwd=tmp_path,
        env=clean_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert install_result.returncode == 0, install_result.stderr
    assert console.is_file()

    for option, expected in (("--help", "Portable CLI"), ("--version", "shodan-skill 2.0.0")):
        result = subprocess.run(
            [str(console), option],
            cwd=tmp_path,
            env=clean_env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert expected in result.stdout
        assert result.stderr == ""

    location = subprocess.run(
        [
            str(python),
            "-c",
            "import pathlib, shodan_skill; print(pathlib.Path(shodan_skill.__file__).resolve())",
        ],
        cwd=tmp_path,
        env=clean_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert location.returncode == 0, location.stderr
    assert environment.resolve() in Path(location.stdout.strip()).resolve().parents

    dependency_check = subprocess.run(
        [str(python), "-m", "pip", "check"],
        cwd=tmp_path,
        env=clean_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert dependency_check.returncode == 0, dependency_check.stdout + dependency_check.stderr
