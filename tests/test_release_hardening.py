from __future__ import annotations

import re
from pathlib import Path

import yaml

from scripts.verify_release import package_versions, verify_release

ROOT = Path(__file__).resolve().parents[1]
PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$")
EXPECTED_ACTIONS = {
    "actions/attest-build-provenance",
    "actions/checkout",
    "actions/deploy-pages",
    "actions/setup-python",
    "actions/upload-artifact",
    "actions/upload-pages-artifact",
    "github/codeql-action/analyze",
    "github/codeql-action/init",
}


def _write_release_fixture(root: Path, project_version: str, package_version: str) -> None:
    root.joinpath("src", "shodan_skill").mkdir(parents=True)
    root.joinpath("pyproject.toml").write_text(
        f'[build-system]\nrequires = []\n\n[project]\nname = "fixture"\nversion = "{project_version}"\n',
        encoding="utf-8",
    )
    root.joinpath("src", "shodan_skill", "__init__.py").write_text(
        f'__version__ = "{package_version}"\n',
        encoding="utf-8",
    )


def test_release_versions_match_and_helper_supports_python_310() -> None:
    assert package_versions() == ("2.0.0", "2.0.0")
    assert verify_release(tag="v2.0.0") == []
    source = ROOT.joinpath("scripts", "verify_release.py").read_text(encoding="utf-8")
    assert "import tomllib" not in source


def test_release_verifier_rejects_mismatch_bad_shape_and_wrong_tag(tmp_path: Path) -> None:
    mismatch = tmp_path / "mismatch"
    _write_release_fixture(mismatch, "2.0.0", "2.0.1")
    assert "does not match package version" in verify_release(root=mismatch)[0]

    bad_shape = tmp_path / "bad-shape"
    _write_release_fixture(bad_shape, "03.0.0", "03.0.0")
    assert "not release-shaped" in verify_release(root=bad_shape)[0]

    valid = tmp_path / "valid"
    _write_release_fixture(valid, "1.2.3", "1.2.3")
    assert verify_release(root=valid, tag="v1.2.4") == ["release tag v1.2.4 does not match package version 1.2.3"]


def test_project_metadata_exposes_security_and_release_inputs() -> None:
    pyproject = ROOT.joinpath("pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "2.0.0"' in pyproject
    assert 'Security = "https://github.com/liuweitao/shodan-skill/security/policy"' in pyproject
    assert '"cyclonedx-bom>=7.3,<8"' in pyproject
    assert '"Programming Language :: Python :: 3.10"' in pyproject
    assert '"Programming Language :: Python :: 3.14"' in pyproject

    manifest = ROOT.joinpath("MANIFEST.in").read_text(encoding="utf-8")
    assert "include SECURITY.md" in manifest
    assert "prune tests" in manifest and "prune .github" in manifest


def test_every_github_workflow_is_valid_yaml_and_pins_external_actions() -> None:
    workflows = sorted(ROOT.joinpath(".github", "workflows").glob("*.yml"))
    assert {path.name for path in workflows} == {
        "ci.yml",
        "codeql.yml",
        "docs-drift.yml",
        "docs.yml",
        "release.yml",
    }
    observed: dict[str, set[str]] = {}
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        parsed = yaml.load(text, Loader=yaml.BaseLoader)
        assert isinstance(parsed, dict), workflow
        action_values = re.findall(r"^\s*(?:-\s+)?uses:\s+(\S+)", text, flags=re.MULTILINE)
        assert action_values, workflow
        assert all(PINNED_ACTION.fullmatch(value) for value in action_values), workflow
        for value in action_values:
            action, commit = value.split("@", maxsplit=1)
            observed.setdefault(action, set()).add(commit)

    assert observed.keys() == EXPECTED_ACTIONS
    assert all(len(commits) == 1 for commits in observed.values())
    assert observed["github/codeql-action/init"] == observed["github/codeql-action/analyze"]


def test_ci_runs_branch_pushes_only_on_master_and_checks_pull_requests() -> None:
    workflow = ROOT.joinpath(".github", "workflows", "ci.yml")
    parsed = yaml.load(workflow.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert parsed["on"]["push"]["branches"] == ["master"]
    assert "pull_request" in parsed["on"]


def test_supply_chain_and_documentation_workflows_have_expected_gates() -> None:
    release = ROOT.joinpath(".github", "workflows", "release.yml").read_text(encoding="utf-8")
    assert "tags:" in release and '"v*"' in release
    assert "types: [published]" not in release
    assert "id-token: write" in release
    assert "attestations: write" in release
    assert "python -m pip check" in release
    assert "python -m pytest --cov=shodan_skill --cov-report=term-missing --cov-fail-under=90" in release
    assert "cyclonedx-py environment" in release
    assert "SHA256SUMS" in release
    assert "actions/attest-build-provenance@" in release
    assert "python scripts/verify_release.py --tag" in release
    assert "gh release create" in release
    assert "gh release upload" in release
    assert "twine upload" not in release

    codeql = ROOT.joinpath(".github", "workflows", "codeql.yml").read_text(encoding="utf-8")
    assert "github/codeql-action/init@" in codeql
    assert "github/codeql-action/analyze@" in codeql
    assert "security-extended" in codeql

    drift = ROOT.joinpath(".github", "workflows", "docs-drift.yml").read_text(encoding="utf-8")
    assert "schedule:" in drift
    assert "refresh_official_snapshot.py --check" in drift


def test_ci_separates_quality_and_compatibility_work_without_duplicate_builds() -> None:
    ci = ROOT.joinpath(".github", "workflows", "ci.yml").read_text(encoding="utf-8")
    assert "concurrency:" in ci
    assert "cancel-in-progress: true" in ci
    assert "quality:" in ci
    assert "compatibility:" in ci
    assert "cache: pip" in ci
    assert "os: [ubuntu-latest, windows-latest, macos-latest]" in ci
    assert 'python: ["3.10", "3.12", "3.14"]' in ci
    assert ci.count("python -m pytest --cov=shodan_skill --cov-report=term-missing --cov-fail-under=90") == 1
    assert ci.count("python -m ruff check .") == 1
    assert ci.count("python -m mypy src/shodan_skill") == 1
    assert ci.count("python -m build") == 1


def test_dependabot_and_private_security_reporting_are_configured() -> None:
    dependabot = yaml.safe_load(ROOT.joinpath(".github", "dependabot.yml").read_text(encoding="utf-8"))
    updates = {update["package-ecosystem"]: update for update in dependabot["updates"]}
    assert updates.keys() == {
        "pip",
        "github-actions",
    }
    assert all(update["schedule"]["interval"] == "weekly" for update in updates.values())
    assert updates["github-actions"]["groups"]["github-actions"]["patterns"] == ["*"]

    security = ROOT.joinpath("SECURITY.md").read_text(encoding="utf-8")
    assert "private vulnerability reporting" in security
    assert "security/advisories/new" in security
    assert "Do not include a real Shodan API key" in security
    assert "A configured API key does not authorize live scanning" in security
