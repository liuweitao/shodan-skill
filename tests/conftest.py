"""Pytest configuration with fail-closed live Shodan gates."""

from __future__ import annotations

import os

import pytest

from tests.live_support import live_gate_reason, marker_configuration_error

LIVE_MARKERS = {"live", "credit", "mutating", "enterprise", "targeted"}


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("shodan-live")
    group.addoption("--allow-live-shodan", action="store_true", help="authorize read-only live Shodan tests")
    group.addoption("--allow-shodan-credits", action="store_true", help="authorize live tests that consume credits")
    group.addoption("--allow-shodan-mutations", action="store_true", help="authorize live state-changing tests")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        markers = {name for name in LIVE_MARKERS if item.get_closest_marker(name) is not None}
        configuration_error = marker_configuration_error(markers)
        if configuration_error:
            raise pytest.UsageError(f"{item.nodeid}: {configuration_error}")
        reason = live_gate_reason(
            markers,
            os.environ,
            allow_live=bool(config.getoption("--allow-live-shodan")),
            allow_credits=bool(config.getoption("--allow-shodan-credits")),
            allow_mutations=bool(config.getoption("--allow-shodan-mutations")),
        )
        if reason:
            item.add_marker(pytest.mark.skip(reason=f"live Shodan test disabled: {reason}"))
