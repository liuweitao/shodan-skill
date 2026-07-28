from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.build_bundles import REFERENCE_FILES, build_bundles
from scripts.install_skill import _reject_symlink_components, install
from scripts.install_skill import main as install_main
from scripts.verify_skill import (
    FORBIDDEN_PLACEHOLDERS,
    _frontmatter,
    _native_smoke_status,
    _validate_fixtures,
    main,
    verify,
)


def test_build_bundles_from_canonical_source(tmp_path: Path) -> None:
    output_root = tmp_path / "platforms"
    built = {name: Path(path) for name, path in build_bundles(output_root).items()}
    canonical = Path("SKILL.md").read_text(encoding="utf-8")
    assert built.keys() == {"openclaw", "codex", "claude-code", "hermes"}
    for name, bundle in built.items():
        skill = bundle / "SKILL.md"
        assert skill.is_file()
        text = skill.read_text(encoding="utf-8")
        if name == "openclaw":
            assert "openclaw:" in text
            assert "~/.openclaw/skills/shodan-skill" in text
            assert "shodan-skill --help" in text
        else:
            assert text == canonical
        assert not any(placeholder in text for placeholder in FORBIDDEN_PLACEHOLDERS)
        assert {path.name for path in (bundle / "references").iterdir()} == set(REFERENCE_FILES)
    assert yaml.safe_load((built["codex"] / "agents" / "openai.yaml").read_text(encoding="utf-8"))
    assert yaml.safe_load((built["openclaw"] / "openclaw.yaml").read_text(encoding="utf-8"))
    assert yaml.safe_load((built["hermes"] / "hermes.yaml").read_text(encoding="utf-8"))


def test_skill_build_and_validation_do_not_depend_on_docs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    shutil.copy2("SKILL.md", root / "SKILL.md")
    shutil.copytree("references", root / "references")
    shutil.copytree("agents", root / "agents")
    shutil.copytree("scripts/fixtures", root / "scripts" / "fixtures")
    package = root / "src" / "shodan_skill"
    package.mkdir(parents=True)
    shutil.copy2("src/shodan_skill/__init__.py", package / "__init__.py")
    monkeypatch.setattr("scripts.build_bundles.ROOT", root)

    build_bundles(root / "platforms")

    assert not (root / "docs").exists()
    assert len(verify(root)) == 4


def test_repository_skill_and_generated_bundles_validate() -> None:
    statuses = verify()
    assert len(statuses) == 4
    assert all(":" in status for status in statuses)


def test_verify_skill_cli_fails_on_native_smoke_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "scripts.verify_skill.verify",
        lambda: [
            "openclaw: unavailable",
            "codex: version-smoke-failed",
            "claude: unavailable",
            "hermes: unavailable",
        ],
    )
    assert main([]) == 1
    captured = capsys.readouterr()
    assert "version-smoke-failed" in captured.err
    assert "Skill and platform bundles valid" not in captured.out


def test_verify_skill_cli_allows_unavailable_native_runtimes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "scripts.verify_skill.verify",
        lambda: [
            "openclaw: unavailable",
            "codex: unavailable",
            "claude: unavailable",
            "hermes: unavailable",
        ],
    )
    assert main([]) == 0
    assert "Skill and platform bundles valid" in capsys.readouterr().out


@pytest.mark.parametrize(
    "failure",
    [
        OSError("cannot start"),
        subprocess.TimeoutExpired("codex", 15),
    ],
)
def test_discovered_native_runtime_start_failures_are_not_marked_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    monkeypatch.setattr("scripts.verify_skill.shutil.which", lambda _command: "codex")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr("scripts.verify_skill.subprocess.run", fail)
    assert _native_smoke_status("codex") == "codex: version-smoke-failed"


def test_permission_denied_native_runtime_is_reported_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scripts.verify_skill.shutil.which", lambda _command: "codex")
    monkeypatch.setattr(
        "scripts.verify_skill.subprocess.run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("access denied")),
    )

    assert _native_smoke_status("codex") == "codex: unavailable (permission denied)"


@pytest.mark.parametrize(
    ("platform", "relative"),
    [
        ("openclaw", ".openclaw/skills/shodan-skill"),
        ("codex", ".codex/skills/shodan-skill"),
        ("claude-code", ".claude/skills/shodan-skill"),
        ("hermes", ".hermes/skills/shodan-skill"),
    ],
)
def test_installer_uses_discovery_layouts(tmp_path: Path, platform: str, relative: str) -> None:
    destination = install(platform, tmp_path)
    assert destination == (tmp_path / relative).resolve()
    assert (destination / "SKILL.md").is_file()


def test_installer_rejects_redirected_path_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = (tmp_path / "home").resolve()
    outside = (tmp_path / "outside").resolve()
    home.mkdir()
    outside.mkdir()
    redirected_component = home / ".codex"
    real_resolve = Path.resolve

    def resolve_with_redirect(path: Path, *args: object, **kwargs: object) -> Path:
        if path == redirected_component:
            return outside
        return real_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve_with_redirect)
    with pytest.raises(ValueError, match="redirected path"):
        _reject_symlink_components(home, home / ".codex" / "skills" / "shodan-skill")


def test_installer_never_replaces_without_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    destination = install("codex", tmp_path)
    marker = destination / "user-file.txt"
    marker.write_text("preserve", encoding="utf-8")
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    with pytest.raises(FileExistsError):
        install("codex", tmp_path)
    assert marker.read_text(encoding="utf-8") == "preserve"
    assert install("codex", tmp_path, confirmed=True) == destination
    assert not marker.exists()


def test_installer_confirmation_requires_the_exact_yes_option(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = install("codex", tmp_path)
    marker = destination / "user-file.txt"
    marker.write_text("preserve", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["install_skill.py", "--platform", "codex", "--home", str(tmp_path), "--y"],
    )

    with pytest.raises(SystemExit):
        install_main()

    assert marker.read_text(encoding="utf-8") == "preserve"


def test_installer_noninteractive_prompt_failure_preserves_existing_installation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = install("codex", tmp_path)
    marker = destination / "user-file.txt"
    marker.write_text("preserve", encoding="utf-8")

    def fail_input(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", fail_input)

    with pytest.raises(FileExistsError, match="--yes"):
        install("codex", tmp_path)

    assert marker.read_text(encoding="utf-8") == "preserve"


def test_installer_copy_failure_preserves_existing_installation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = install("codex", tmp_path)
    marker = destination / "user-file.txt"
    marker.write_text("preserve", encoding="utf-8")
    real_copytree = shutil.copytree

    def fail_bundle_copy(source: Path, target: Path, *args: object, **kwargs: object) -> None:
        if Path(source).name == "shodan-skill":
            Path(target).mkdir(parents=True)
            Path(target, "incomplete.txt").write_text("partial", encoding="utf-8")
            raise OSError("simulated copy failure")
        real_copytree(source, target, *args, **kwargs)

    monkeypatch.setattr("scripts.install_skill.shutil.copytree", fail_bundle_copy)
    with pytest.raises(OSError, match="simulated copy failure"):
        install("codex", tmp_path, confirmed=True)

    assert marker.read_text(encoding="utf-8") == "preserve"


def test_installer_does_not_replace_destination_that_appears_during_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / ".codex" / "skills" / "shodan-skill"
    marker = destination / "created-concurrently.txt"
    real_copytree = shutil.copytree

    def copy_then_create_destination(source: Path, target: Path, *args: object, **kwargs: object) -> Path:
        result = real_copytree(source, target, *args, **kwargs)
        if Path(target).name == "new":
            destination.mkdir(parents=True)
            marker.write_text("preserve", encoding="utf-8")
        return result

    monkeypatch.setattr("scripts.install_skill.shutil.copytree", copy_then_create_destination)

    with pytest.raises(FileExistsError, match="appeared during installation"):
        install("codex", tmp_path)

    assert marker.read_text(encoding="utf-8") == "preserve"


def test_installer_replacement_failure_rolls_back_existing_installation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = install("codex", tmp_path)
    marker = destination / "user-file.txt"
    marker.write_text("preserve", encoding="utf-8")
    real_replace = Path.replace

    def fail_new_bundle(source: Path, target: Path) -> Path:
        if source.name == "new":
            raise OSError("simulated replacement failure")
        return real_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_new_bundle)
    with pytest.raises(OSError, match="simulated replacement failure"):
        install("codex", tmp_path, confirmed=True)

    assert marker.read_text(encoding="utf-8") == "preserve"


def test_verify_rejects_bundle_content_drift(tmp_path: Path) -> None:
    shutil.copytree(Path.cwd(), tmp_path / "repo", ignore=shutil.ignore_patterns(".git", ".venv", "build", "dist"))
    root = tmp_path / "repo"
    bundle_skill = root / "platforms" / "codex" / "shodan-skill" / "SKILL.md"
    bundle_skill.write_text(bundle_skill.read_text(encoding="utf-8") + "\nstale copy\n", encoding="utf-8")

    with pytest.raises(ValueError, match="differs from the canonical source"):
        verify(root)


def test_selection_fixture_validator_rejects_a_brand_only_positive(tmp_path: Path) -> None:
    fixture_dir = tmp_path / "scripts" / "fixtures"
    fixture_dir.mkdir(parents=True)
    fixtures = Path("scripts/fixtures/skill-selection.yaml").read_text(encoding="utf-8")
    fixture_dir.joinpath("skill-selection.yaml").write_text(
        fixtures.replace("Use Shodan to inspect the services exposed by 8.8.8.8.", "Shodan", 1),
        encoding="utf-8",
    )
    description = str(_frontmatter(Path("SKILL.md"))["description"])

    with pytest.raises(ValueError, match="scope"):
        _validate_fixtures(tmp_path, description)


def test_verify_rejects_unreferenced_bundle_files_and_stale_metadata(tmp_path: Path) -> None:
    shutil.copytree(
        Path.cwd(),
        tmp_path / "repo",
        ignore=shutil.ignore_patterns(".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "build", "dist"),
    )
    root = tmp_path / "repo"
    extra = root / "platforms" / "hermes" / "shodan-skill" / "obsolete.txt"
    extra.write_text("stale", encoding="utf-8")
    with pytest.raises(ValueError, match="file inventory"):
        verify(root)

    extra.unlink()
    metadata = root / "platforms" / "openclaw" / "shodan-skill" / "openclaw.yaml"
    metadata.write_text(metadata.read_text(encoding="utf-8").replace('version: "2.0.0"', 'version: "9.9.9"'))
    with pytest.raises(ValueError, match="metadata"):
        verify(root)
