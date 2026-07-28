from __future__ import annotations

import argparse
import copy

import pytest

from scripts.verify_coverage import (
    DEFAULT_MANIFEST,
    load_manifest,
    verify_collected_contract_tests,
    verify_manifest,
)
from shodan_skill.cli import build_parser


def manifest() -> dict:
    return load_manifest(DEFAULT_MANIFEST)


def test_current_manifest_matches_official_inventory() -> None:
    assert verify_manifest(manifest()) == []


def _leaf_commands(parser: argparse.ArgumentParser, prefix: tuple[str, ...] = ()) -> set[str]:
    subparsers = next(
        (action for action in parser._actions if isinstance(action, argparse._SubParsersAction)),
        None,
    )
    if subparsers is None:
        return {" ".join(prefix)}
    commands: set[str] = set()
    for name, child in subparsers.choices.items():
        commands.update(_leaf_commands(child, (*prefix, name)))
    return commands


def test_every_manifest_cli_mapping_exists_and_only_documented_local_commands_are_extra() -> None:
    manifest_commands = {operation["cli"] for operation in manifest()["operations"]}
    parser_commands = _leaf_commands(build_parser())

    assert manifest_commands <= parser_commands
    assert parser_commands - manifest_commands == {
        "data download",
        "reference datapedia",
        "reference filters",
    }


def test_verifier_detects_missing_operation() -> None:
    data = copy.deepcopy(manifest())
    data["operations"].pop()
    errors = verify_manifest(data)
    assert any("missing official operation" in error for error in errors)
    assert any("exactly 58 entries" in error for error in errors)


def test_verifier_detects_duplicate_operation_and_id() -> None:
    data = copy.deepcopy(manifest())
    data["operations"][-1] = copy.deepcopy(data["operations"][0])
    errors = verify_manifest(data)
    assert any(error.startswith("duplicate id:") for error in errors)
    assert any(error.startswith("duplicate operation:") for error in errors)


def test_verifier_detects_malformed_entry() -> None:
    data = copy.deepcopy(manifest())
    del data["operations"][0]["cli"]
    errors = verify_manifest(data)
    assert any("missing fields: cli" in error for error in errors)


def test_verifier_requires_custom_stream_query() -> None:
    data = copy.deepcopy(manifest())
    custom = next(operation for operation in data["operations"] if operation["id"] == "shodan-stream-custom")
    custom["required_query"] = []
    assert "streaming /shodan/custom must require the query parameter" in verify_manifest(data)


def test_completion_gate_rejects_incomplete_states() -> None:
    data = copy.deepcopy(manifest())
    data["operations"][0]["implementation"] = "planned"
    data["operations"][0]["contract_test"] = "planned"
    errors = verify_manifest(data, require_complete=True)
    assert any("implementation is not complete" in error for error in errors)
    assert any("contract test is not complete" in error for error in errors)


def test_every_contract_test_link_can_be_checked_against_pytest_collection() -> None:
    data = manifest()
    expected = {node for operation in data["operations"] for node in operation["contract_tests"]}
    assert len(expected) == 58
    assert verify_collected_contract_tests(data, expected) == []

    missing = next(iter(expected))
    errors = verify_collected_contract_tests(data, expected - {missing})
    assert errors == [
        f"{next(operation['id'] for operation in data['operations'] if missing in operation['contract_tests'])}: "
        f"contract test is not collected by pytest: {missing}"
    ]


def test_verifier_does_not_allow_the_manifest_to_invent_completion_states() -> None:
    data = copy.deepcopy(manifest())
    data["allowed_states"]["implementation"].append("claimed-complete")
    data["operations"][0]["implementation"] = "claimed-complete"

    errors = verify_manifest(data)

    assert any("allowed implementation states" in error for error in errors)
    assert any("invalid implementation state" in error for error in errors)


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("api", [], "invalid api family"),
        ("method", {}, "invalid HTTP method"),
        ("access", [], "invalid access value"),
        ("credit_impact", {}, "invalid credit_impact value"),
        ("required_query", [{}], "required_query"),
        ("risk", [{}], "invalid risk classification"),
        ("implementation", [], "invalid implementation state"),
        ("contract_test", {}, "invalid contract_test state"),
        ("contract_tests", ["not-a-pytest-node"], "contract_tests"),
        ("live_test", [], "invalid live_test state"),
        ("docs_url", [], "docs_url"),
    ],
)
def test_verifier_reports_malformed_nested_types_without_crashing(
    field: str,
    value: object,
    expected: str,
) -> None:
    data = copy.deepcopy(manifest())
    data["operations"][0][field] = value

    assert any(expected in error for error in verify_manifest(data))


def test_verifier_detects_duplicate_cli_mapping() -> None:
    data = copy.deepcopy(manifest())
    data["operations"][1]["cli"] = data["operations"][0]["cli"]

    assert any(error.startswith("duplicate cli mapping:") for error in verify_manifest(data))


def test_verifier_detects_duplicate_contract_test_mapping() -> None:
    data = copy.deepcopy(manifest())
    data["operations"][1]["contract_tests"] = data["operations"][0]["contract_tests"]

    assert any(error.startswith("duplicate contract test mapping:") for error in verify_manifest(data))


def test_verifier_rejects_nonofficial_or_cross_family_documentation_links() -> None:
    data = copy.deepcopy(manifest())
    data["operations"][0]["docs_url"] = "https://example.com/api"
    data["operations"][-1]["docs_url"] = "https://developer.shodan.io/api"

    errors = verify_manifest(data)

    assert sum("docs_url must match the official documentation" in error for error in errors) == 2


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("schema_version", 2, "schema_version"),
        ("official_snapshot", "references/stale.yaml", "official_snapshot"),
        ("official_retrieved", "not-a-date", "official_retrieved"),
        ("representation_notes", [], "representation_notes"),
    ],
)
def test_verifier_validates_manifest_metadata(field: str, value: object, expected: str) -> None:
    data = copy.deepcopy(manifest())
    data[field] = value

    assert any(expected in error for error in verify_manifest(data))
