#!/usr/bin/env python3
"""Validate the documented Shodan API coverage manifest."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "references" / "api-coverage.yaml"
DEFAULT_SNAPSHOT = ROOT / "references" / "official-api-snapshot.yaml"
API_FAMILIES = {
    "rest": "https://developer.shodan.io/api",
    "streaming": "https://developer.shodan.io/api/stream",
    "trends": "https://developer.shodan.io/api/trends",
    "exploits": "https://developer.shodan.io/api/exploits/rest",
}

REQUIRED_FIELDS = {
    "id",
    "api",
    "method",
    "path",
    "cli",
    "access",
    "credit_impact",
    "mutation",
    "destructive",
    "required_query",
    "risk",
    "implementation",
    "contract_test",
    "contract_tests",
    "live_test",
    "live_test_reason",
    "docs_url",
}
VALID_RISKS = {
    "read-only",
    "credit-consuming",
    "state-changing",
    "destructive",
    "enterprise-only",
}
VALID_ACCESS = {"standard", "enterprise"}
VALID_CREDIT = {"none", "conditional", "query", "scan", "unknown"}
ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
QUERY_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
CLI_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*(?: [a-z0-9]+(?:-[a-z0-9]+)*){1,2}$")
CONTRACT_NODE_PATTERN = re.compile(r"^tests/[a-z0-9_/]+\.py::test_[a-z0-9_]+(?:\[[A-Za-z0-9_.:/,@{}+-]+\])?$")
EXPECTED_STATES = {
    "implementation": {"planned", "partial", "complete"},
    "contract_test": {"planned", "complete"},
    "live_test": {"not-run", "passed", "failed", "skipped"},
}


def load_official_snapshot(path: Path = DEFAULT_SNAPSHOT) -> dict[str, Any]:
    """Load and structurally validate the checked-in official documentation snapshot."""
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError("official snapshot root must be a mapping")
    if data.get("schema_version") != 1:
        raise ValueError("official snapshot schema_version must be 1")
    retrieved_at = data.get("retrieved_at")
    if not isinstance(retrieved_at, (str, date)):
        raise ValueError("official snapshot retrieved_at must be an ISO date")
    try:
        date.fromisoformat(str(retrieved_at))
    except ValueError as exc:
        raise ValueError("official snapshot retrieved_at must be an ISO date") from exc
    sources = data.get("sources")
    if not isinstance(sources, Mapping) or set(sources) != set(API_FAMILIES):
        raise ValueError("official snapshot must contain every configured API source")
    for family, expected_url in API_FAMILIES.items():
        source = sources.get(family)
        if not isinstance(source, Mapping):
            raise ValueError(f"official snapshot {family} source must be a mapping")
        if source.get("url") != expected_url:
            raise ValueError(f"official snapshot {family} URL does not match the configured official source")
        digest = source.get("document_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"official snapshot {family} document hash is invalid")
        count = source.get("operation_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError(f"official snapshot {family} operation count is invalid")
    operations = data.get("operations")
    if not isinstance(operations, list) or not operations:
        raise ValueError("official snapshot operations must be a non-empty list")
    keys: list[tuple[str, str, str]] = []
    for index, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            raise ValueError(f"official snapshot operation[{index}] must be a mapping")
        api, method, path_value = operation.get("api"), operation.get("method"), operation.get("path")
        if api not in API_FAMILIES:
            raise ValueError(f"official snapshot operation[{index}] has an invalid API family")
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            raise ValueError(f"official snapshot operation[{index}] has an invalid HTTP method")
        if not isinstance(path_value, str) or not path_value.startswith("/") or "?" in path_value:
            raise ValueError(f"official snapshot operation[{index}] has an invalid path")
        keys.append((str(api), str(method), path_value))
    duplicates = [key for key, count in Counter(keys).items() if count > 1]
    if duplicates:
        raise ValueError(f"official snapshot contains duplicate operations: {duplicates!r}")
    for family in API_FAMILIES:
        actual_count = sum(api == family for api, _method, _path in keys)
        if sources[family]["operation_count"] != actual_count:
            raise ValueError(f"official snapshot {family} operation count does not match its inventory")
    return data


def _snapshot_inventory(data: Mapping[str, Any]) -> dict[str, set[tuple[str, str]]]:
    inventory = {family: set() for family in API_FAMILIES}
    for operation in data["operations"]:
        inventory[str(operation["api"])].add((str(operation["method"]), str(operation["path"])))
    return inventory


OFFICIAL_SNAPSHOT = load_official_snapshot()
OFFICIAL_OPERATIONS = _snapshot_inventory(OFFICIAL_SNAPSHOT)
OFFICIAL_DOCS = {family: str(OFFICIAL_SNAPSHOT["sources"][family]["url"]) for family in API_FAMILIES}


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    """Load a manifest and require a mapping at its root."""
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError("manifest root must be a mapping")
    return data


def verify_manifest(data: dict[str, Any], *, require_complete: bool = False) -> list[str]:
    """Return all manifest validation errors."""
    errors: list[str] = []
    operations = data.get("operations")
    if not isinstance(operations, list):
        return ["operations must be a list"]
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if data.get("official_snapshot") != "references/official-api-snapshot.yaml":
        errors.append("official_snapshot must reference references/official-api-snapshot.yaml")
    retrieved = data.get("official_retrieved")
    if isinstance(retrieved, str):
        try:
            date.fromisoformat(retrieved)
        except ValueError:
            errors.append("official_retrieved must be an ISO date")
    elif not isinstance(retrieved, date):
        errors.append("official_retrieved must be an ISO date")
    if str(retrieved) != str(OFFICIAL_SNAPSHOT["retrieved_at"]):
        errors.append("official_retrieved must match the checked-in official snapshot")
    representation_notes = data.get("representation_notes")
    if (
        not isinstance(representation_notes, list)
        or not representation_notes
        or any(not isinstance(note, str) or not note.strip() for note in representation_notes)
    ):
        errors.append("representation_notes must be a non-empty list of strings")

    allowed_value = data.get("allowed_states", {})
    if not isinstance(allowed_value, Mapping):
        errors.append("allowed_states must be a mapping")
        allowed: Mapping[str, Any] = {}
    else:
        allowed = allowed_value
    for category, expected in EXPECTED_STATES.items():
        configured = allowed.get(category)
        if (
            not isinstance(configured, list)
            or any(not isinstance(state, str) for state in configured)
            or set(configured) != expected
            or len(configured) != len(expected)
        ):
            errors.append(f"allowed {category} states must be exactly: {', '.join(sorted(expected))}")

    ids: list[str] = []
    keys: list[tuple[str, str, str]] = []
    cli_mappings: list[str] = []
    contract_nodes: list[str] = []
    actual: dict[str, set[tuple[str, str]]] = {family: set() for family in OFFICIAL_OPERATIONS}

    for index, operation in enumerate(operations):
        label = f"operation[{index}]"
        if not isinstance(operation, dict):
            errors.append(f"{label} must be a mapping")
            continue
        missing_fields = REQUIRED_FIELDS - operation.keys()
        if missing_fields:
            errors.append(f"{label} missing fields: {', '.join(sorted(missing_fields))}")
            continue

        operation_id = operation["id"]
        api = operation["api"]
        method = operation["method"]
        path = operation["path"]
        label = str(operation_id)
        if not isinstance(operation_id, str) or not ID_PATTERN.fullmatch(operation_id):
            errors.append(f"{label}: invalid id")
        else:
            ids.append(operation_id)
        if not isinstance(api, str) or api not in OFFICIAL_OPERATIONS:
            errors.append(f"{label}: invalid api family {api!r}")
        if not isinstance(method, str) or method not in {"GET", "POST", "PUT", "DELETE"}:
            errors.append(f"{label}: invalid HTTP method {method!r}")
        if not isinstance(path, str) or not path.startswith("/") or "?" in path:
            errors.append(f"{label}: path must start with / and exclude query parameters")
        if isinstance(api, str) and isinstance(method, str) and isinstance(path, str):
            keys.append((api, method, path))
            if api in actual:
                actual[api].add((method, path))
        cli = operation["cli"]
        if not isinstance(cli, str) or not CLI_PATTERN.fullmatch(cli):
            errors.append(f"{label}: cli mapping is required")
        else:
            cli_mappings.append(cli)
        access = operation["access"]
        if not isinstance(access, str) or access not in VALID_ACCESS:
            errors.append(f"{label}: invalid access value")
        credit_impact = operation["credit_impact"]
        if not isinstance(credit_impact, str) or credit_impact not in VALID_CREDIT:
            errors.append(f"{label}: invalid credit_impact value")
        mutation = operation["mutation"]
        destructive = operation["destructive"]
        if not isinstance(mutation, bool) or not isinstance(destructive, bool):
            errors.append(f"{label}: mutation and destructive must be booleans")
        required_query = operation["required_query"]
        if (
            not isinstance(required_query, list)
            or any(not isinstance(name, str) or not QUERY_NAME_PATTERN.fullmatch(name) for name in required_query)
            or (isinstance(required_query, list) and len(required_query) != len(set(map(str, required_query))))
        ):
            errors.append(f"{label}: required_query must be a list")
        risks = operation["risk"]
        if (
            not isinstance(risks, list)
            or not risks
            or any(not isinstance(risk, str) for risk in risks)
            or (isinstance(risks, list) and all(isinstance(risk, str) for risk in risks) and set(risks) - VALID_RISKS)
            or (
                isinstance(risks, list)
                and all(isinstance(risk, str) for risk in risks)
                and len(risks) != len(set(risks))
            )
        ):
            errors.append(f"{label}: invalid risk classification")
            risk_set: set[str] = set()
        else:
            risk_set = set(risks)
        if mutation is True and "state-changing" not in risk_set:
            errors.append(f"{label}: mutations must be classified state-changing")
        if mutation is False and "read-only" not in risk_set:
            errors.append(f"{label}: non-mutations must be classified read-only")
        if mutation is True and "read-only" in risk_set:
            errors.append(f"{label}: mutations cannot be classified read-only")
        if destructive is True and (mutation is not True or "destructive" not in risk_set):
            errors.append(f"{label}: destructive operations must be mutations classified destructive")
        if destructive is False and "destructive" in risk_set:
            errors.append(f"{label}: non-destructive operations cannot be classified destructive")
        if access == "enterprise" and "enterprise-only" not in risk_set:
            errors.append(f"{label}: enterprise access must be classified enterprise-only")
        if access == "standard" and "enterprise-only" in risk_set:
            errors.append(f"{label}: standard access cannot be classified enterprise-only")
        if (
            isinstance(credit_impact, str)
            and credit_impact in VALID_CREDIT - {"none"}
            and "credit-consuming" not in risk_set
        ):
            errors.append(f"{label}: credit impact must be classified credit-consuming")
        if credit_impact == "none" and "credit-consuming" in risk_set:
            errors.append(f"{label}: no-credit operations cannot be classified credit-consuming")
        implementation = operation["implementation"]
        contract_test = operation["contract_test"]
        contract_tests = operation["contract_tests"]
        live_test = operation["live_test"]
        if not isinstance(implementation, str) or implementation not in EXPECTED_STATES["implementation"]:
            errors.append(f"{label}: invalid implementation state")
        if not isinstance(contract_test, str) or contract_test not in EXPECTED_STATES["contract_test"]:
            errors.append(f"{label}: invalid contract_test state")
        if (
            not isinstance(contract_tests, list)
            or not contract_tests
            or any(not isinstance(node, str) or not CONTRACT_NODE_PATTERN.fullmatch(node) for node in contract_tests)
            or (
                isinstance(contract_tests, list)
                and all(isinstance(node, str) for node in contract_tests)
                and len(contract_tests) != len(set(contract_tests))
            )
        ):
            errors.append(f"{label}: contract_tests must contain valid pytest node IDs")
        else:
            contract_nodes.extend(contract_tests)
        if not isinstance(live_test, str) or live_test not in EXPECTED_STATES["live_test"]:
            errors.append(f"{label}: invalid live_test state")
        live_test_reason = operation["live_test_reason"]
        if live_test != "passed" and (not isinstance(live_test_reason, str) or not live_test_reason.strip()):
            errors.append(f"{label}: non-passing live tests require a reason")
        docs_url = operation["docs_url"]
        expected_docs_url = OFFICIAL_DOCS.get(api) if isinstance(api, str) else None
        if not isinstance(docs_url, str) or docs_url != expected_docs_url:
            errors.append(f"{label}: docs_url must match the official documentation for its API family")
        if require_complete and implementation != "complete":
            errors.append(f"{label}: implementation is not complete")
        if require_complete and contract_test != "complete":
            errors.append(f"{label}: contract test is not complete")

    for duplicate_id, count in Counter(ids).items():
        if count > 1:
            errors.append(f"duplicate id: {duplicate_id}")
    for duplicate_key, count in Counter(keys).items():
        if count > 1:
            errors.append(f"duplicate operation: {' '.join(duplicate_key)}")
    for duplicate_cli, count in Counter(cli_mappings).items():
        if count > 1:
            errors.append(f"duplicate cli mapping: {duplicate_cli}")
    for duplicate_node, count in Counter(contract_nodes).items():
        if count > 1:
            errors.append(f"duplicate contract test mapping: {duplicate_node}")

    for family, expected in OFFICIAL_OPERATIONS.items():
        missing = expected - actual[family]
        extra = actual[family] - expected
        for method, path in sorted(missing):
            errors.append(f"missing official operation: {family} {method} {path}")
        for method, path in sorted(extra):
            errors.append(f"undocumented operation: {family} {method} {path}")

    expected_count = sum(len(items) for items in OFFICIAL_OPERATIONS.values())
    if data.get("official_operation_count") != expected_count:
        errors.append(f"official_operation_count must be {expected_count}")
    if len(operations) != expected_count:
        errors.append(f"operations must contain exactly {expected_count} entries")
    if data.get("family_counts") != {family: len(items) for family, items in OFFICIAL_OPERATIONS.items()}:
        errors.append("family_counts do not match the official inventory")
    custom = [
        op
        for op in operations
        if isinstance(op, dict) and op.get("api") == "streaming" and op.get("path") == "/shodan/custom"
    ]
    if custom and (
        not isinstance(custom[0].get("required_query"), list) or "query" not in custom[0].get("required_query", [])
    ):
        errors.append("streaming /shodan/custom must require the query parameter")
    return errors


def collect_pytest_nodeids(*, timeout: float = 60.0) -> set[str]:
    """Collect pytest node IDs in a subprocess without executing tests."""
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise ValueError(f"pytest contract collection failed: {diagnostic[:500]}")
    return {
        line.strip().replace("\\", "/")
        for line in completed.stdout.splitlines()
        if line.strip().startswith("tests/") and "::" in line
    }


def verify_collected_contract_tests(data: Mapping[str, Any], collected_nodeids: set[str]) -> list[str]:
    """Require every manifest contract node to be present in pytest collection."""
    errors: list[str] = []
    operations = data.get("operations")
    if not isinstance(operations, list):
        return ["operations must be a list before contract tests can be collected"]
    for operation in operations:
        if not isinstance(operation, Mapping):
            continue
        operation_id = operation.get("id", "unknown")
        contract_tests = operation.get("contract_tests")
        if not isinstance(contract_tests, list):
            continue
        for node in contract_tests:
            if isinstance(node, str) and node not in collected_nodeids:
                errors.append(f"{operation_id}: contract test is not collected by pytest: {node}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument(
        "--skip-contract-collection",
        action="store_true",
        help="Skip pytest --collect-only verification of operation-specific contract node IDs",
    )
    args = parser.parse_args(argv)
    try:
        data = load_manifest(args.manifest)
        errors = verify_manifest(data, require_complete=args.require_complete)
        if not errors and not args.skip_contract_collection:
            errors.extend(verify_collected_contract_tests(data, collect_pytest_nodeids()))
    except (OSError, subprocess.TimeoutExpired, ValueError, yaml.YAMLError) as exc:
        print(f"coverage manifest error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Coverage manifest valid: {len(data['operations'])} official operations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
