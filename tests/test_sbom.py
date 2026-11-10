from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.verify_sbom import verify_sbom


@pytest.fixture
def sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"name": "shodan-skill", "version": "2.0.1"},
            {"name": "httpx", "version": "0.28.1"},
            {"name": "certifi", "version": "2026.10.19"},
        ],
    }


def test_sbom_requires_correct_product_version_and_dependencies(sbom: dict) -> None:
    verify_sbom(sbom, version="2.0.1")
    changed = deepcopy(sbom)
    changed["components"][0]["name"] = "shodan_skill"
    verify_sbom(changed, version="2.0.1")
    with pytest.raises(ValueError, match="version"):
        verify_sbom(sbom, version="2.0.2")
    for name in ("shodan-skill", "httpx", "certifi"):
        changed = deepcopy(sbom)
        changed["components"] = [component for component in changed["components"] if component["name"] != name]
        with pytest.raises(ValueError, match="must contain"):
            verify_sbom(changed, version="2.0.1")
    with pytest.raises(ValueError, match=r"CycloneDX 1\.6"):
        verify_sbom({**sbom, "specVersion": "1.5"}, version="2.0.1")
