from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from scripts.prepare_snapshot_update import prepare_update

ROOT = Path(__file__).resolve().parents[1]


def workflow(name: str) -> dict:
    return yaml.load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def protected_repository() -> dict:
    settings = json.loads((ROOT / ".github/maintenance-settings.json").read_text())
    return {
        "data": {
            "repository": {
                "autoMergeAllowed": True,
                "defaultBranchRef": {
                    "branchProtectionRule": {
                        "isAdminEnforced": True,
                        "requiresStatusChecks": True,
                        "requiresStrictStatusChecks": True,
                        "requiresConversationResolution": True,
                        "allowsForcePushes": False,
                        "allowsDeletions": False,
                        "requiredStatusChecks": [
                            {"context": check["context"], "app": {"databaseId": check["app_id"]}}
                            for check in settings["branch_protection"]["required_status_checks"]["checks"]
                        ],
                    }
                },
            }
        }
    }


def run_gate(tmp_path: Path, response: dict) -> subprocess.CompletedProcess:
    steps = workflow("dependabot-automerge.yml")["jobs"]["enable"]["steps"]
    code = next(step["run"] for step in steps if step.get("id") == "protection")
    (tmp_path / "maintenance-protection.json").write_text(json.dumps(response))
    return subprocess.run(
        [sys.executable, "-c", code],
        env={**os.environ, "RUNNER_TEMP": str(tmp_path), "GITHUB_OUTPUT": str(tmp_path / "output")},
        text=True,
        capture_output=True,
        check=False,
    )


def test_merge_gate_accepts_only_the_configured_protection(tmp_path: Path) -> None:
    result = run_gate(tmp_path, protected_repository())
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "output").read_text() == "ready=true\n"


@pytest.mark.parametrize(
    "weakened",
    [
        "absent",
        "autoMergeAllowed",
        "isAdminEnforced",
        "requiresStatusChecks",
        "requiresStrictStatusChecks",
        "requiresConversationResolution",
        "allowsForcePushes",
        "allowsDeletions",
        "missing-check",
        "wrong-app",
    ],
)
def test_merge_gate_fails_closed_for_incomplete_or_weaker_protection(tmp_path: Path, weakened: str) -> None:
    response = protected_repository()
    repository = response["data"]["repository"]
    protection = repository["defaultBranchRef"]["branchProtectionRule"]
    if weakened == "absent":
        repository["defaultBranchRef"]["branchProtectionRule"] = None
    elif weakened == "autoMergeAllowed":
        repository[weakened] = False
    elif weakened == "missing-check":
        protection["requiredStatusChecks"].pop()
    elif weakened == "wrong-app":
        protection["requiredStatusChecks"][0]["app"]["databaseId"] = 0
    else:
        protection[weakened] = not protection[weakened]
    result = run_gate(tmp_path, response)
    assert result.returncode != 0
    assert "Auto-merge refused" in result.stderr
    assert not (tmp_path / "output").exists()


def test_privileged_merge_workflow_never_checks_out_pr_code_or_skips_metadata_verification() -> None:
    automation = workflow("dependabot-automerge.yml")
    assert set(automation["on"]) == {"pull_request_target", "pull_request", "repository_dispatch", "workflow_dispatch"}
    assert "github.event_name == 'pull_request_target'" in automation["jobs"]["enable"]["if"]
    audit = automation["jobs"]["audit"]
    assert audit["permissions"] == {"contents": "read"}
    assert "gh pr merge" not in "\n".join(step.get("run", "") for step in audit["steps"])
    assert audit["steps"][-1]["run"] == next(
        step["run"] for step in automation["jobs"]["enable"]["steps"] if step.get("id") == "protection"
    )
    job = automation["jobs"]["enable"]
    assert "dependabot[bot]" in job["if"]
    assert "head.repo.full_name == github.repository" in job["if"]
    assert "base.ref == github.event.repository.default_branch" in job["if"]
    assert job["permissions"] == {"contents": "write", "pull-requests": "write"}
    uses = [step for step in job["steps"] if "uses" in step]
    assert len(uses) == 1 and uses[0]["uses"].startswith("dependabot/fetch-metadata@")
    assert set(uses[0]["with"]) == {"github-token"}
    read = next(step for step in job["steps"] if step["name"] == "Read effective branch protection")
    assert "semver-major" not in read["if"]
    assert "semver-minor" in read["if"] and "semver-patch" in read["if"]
    assert "maintainer-changes == 'false'" in read["if"]
    merge = job["steps"][-1]
    assert merge["if"] == "steps.protection.outputs.ready == 'true'"
    assert "--auto --squash --match-head-commit" in merge["run"]
    assert "${{" not in merge["run"]


def test_documentation_job_only_proposes_allowed_files_and_never_merges() -> None:
    job = workflow("docs-drift.yml")["jobs"]["compare"]
    assert job["permissions"] == {"contents": "write", "pull-requests": "write"}
    proposal = next(step for step in job["steps"] if step.get("id") == "proposal")
    assert proposal["if"] == "steps.snapshot.outputs.drift == 'true'"
    assert proposal["with"]["branch"] == "automation/official-documentation"
    assert proposal["with"]["add-paths"].splitlines() == [
        "references/official-api-snapshot.yaml",
        "references/api-coverage.yaml",
        "platforms/",
    ]
    assert "gh pr merge" not in "\n".join(step.get("run", "") for step in job["steps"])


@pytest.fixture
def snapshot_fixture(tmp_path: Path) -> tuple[Path, dict, str]:
    references = tmp_path / "references"
    references.mkdir()
    snapshot = yaml.safe_load((ROOT / "references/official-api-snapshot.yaml").read_text())
    (references / "official-api-snapshot.yaml").write_text(yaml.safe_dump(snapshot))
    manifest = (ROOT / "references/api-coverage.yaml").read_text()
    (references / "api-coverage.yaml").write_text(manifest)
    return tmp_path, snapshot, manifest


def test_prepare_update_changes_only_snapshot_and_retrieval_metadata(snapshot_fixture) -> None:
    root, snapshot, old_manifest = snapshot_fixture
    candidate = root / "candidate.yaml"
    snapshot["retrieved_at"] = "2026-11-11"
    snapshot["sources"]["rest"]["document_sha256"] = "1" * 64
    candidate.write_text(yaml.safe_dump(snapshot))
    assert prepare_update(candidate, root=root)
    assert yaml.safe_load((root / "references/official-api-snapshot.yaml").read_text()) == snapshot
    old_date = yaml.safe_load(old_manifest)["official_retrieved"]
    assert (root / "references/api-coverage.yaml").read_text() == old_manifest.replace(str(old_date), "2026-11-11", 1)


def test_prepare_date_only_or_invalid_candidate_does_not_modify_sources(snapshot_fixture) -> None:
    root, snapshot, manifest = snapshot_fixture
    accepted = (root / "references/official-api-snapshot.yaml").read_bytes()
    candidate = root / "candidate.yaml"
    snapshot["retrieved_at"] = "2026-11-11"
    candidate.write_text(yaml.safe_dump(snapshot))
    assert not prepare_update(candidate, root=root)
    broken = deepcopy(snapshot)
    broken["sources"]["rest"]["operation_count"] = 0
    candidate.write_text(yaml.safe_dump(broken))
    with pytest.raises(ValueError):
        prepare_update(candidate, root=root)
    assert (root / "references/official-api-snapshot.yaml").read_bytes() == accepted
    assert (root / "references/api-coverage.yaml").read_text() == manifest


def test_new_operations_do_not_gain_automatic_implementation_or_test_claims(snapshot_fixture) -> None:
    root, snapshot, old_manifest = snapshot_fixture
    snapshot["operations"].append({"api": "rest", "method": "GET", "path": "/new/upstream/operation"})
    snapshot["sources"]["rest"]["operation_count"] += 1
    candidate = root / "candidate.yaml"
    candidate.write_text(yaml.safe_dump(snapshot))
    assert prepare_update(candidate, root=root)
    assert (root / "references/api-coverage.yaml").read_text() == old_manifest


def test_bad_manifest_date_field_is_rejected_before_snapshot_changes(snapshot_fixture) -> None:
    root, snapshot, manifest = snapshot_fixture
    accepted = (root / "references/official-api-snapshot.yaml").read_bytes()
    snapshot["sources"]["rest"]["document_sha256"] = "2" * 64
    candidate = root / "candidate.yaml"
    candidate.write_text(yaml.safe_dump(snapshot))
    bad = manifest.replace("official_retrieved:", "previous_retrieved:", 1)
    (root / "references/api-coverage.yaml").write_text(bad)
    with pytest.raises(ValueError, match="exactly one"):
        prepare_update(candidate, root=root)
    assert (root / "references/official-api-snapshot.yaml").read_bytes() == accepted
    assert (root / "references/api-coverage.yaml").read_text() == bad
