from __future__ import annotations

import pytest

from tests.live_support import authorized_targets, live_gate_reason, marker_configuration_error


def test_non_live_test_has_no_gate() -> None:
    assert live_gate_reason(set(), {}, allow_live=False, allow_credits=False, allow_mutations=False) is None


def test_environment_flag_alone_does_not_authorize_live_test() -> None:
    reason = live_gate_reason(
        {"live"},
        {"SHODAN_LIVE_TESTS": "1"},
        allow_live=False,
        allow_credits=False,
        allow_mutations=False,
    )
    assert reason is not None and "--allow-live-shodan" in reason


def test_dangerous_markers_without_live_marker_fail_closed() -> None:
    assert marker_configuration_error({"mutating"}) == "mutating markers require the live marker"
    assert marker_configuration_error({"enterprise", "credit"}) == "credit, enterprise markers require the live marker"
    assert marker_configuration_error({"live", "mutating"}) is None


@pytest.mark.parametrize(
    ("markers", "environ", "options", "expected"),
    [
        ({"live"}, {}, (True, False, False), "SHODAN_LIVE_TESTS"),
        ({"live", "credit"}, {"SHODAN_LIVE_TESTS": "1"}, (True, False, False), "credits"),
        (
            {"live", "mutating"},
            {"SHODAN_LIVE_TESTS": "1"},
            (True, False, True),
            "SHODAN_MUTATING_TESTS",
        ),
        (
            {"live", "enterprise"},
            {"SHODAN_LIVE_TESTS": "1"},
            (True, False, False),
            "SHODAN_ENTERPRISE_TESTS",
        ),
        (
            {"live", "targeted"},
            {"SHODAN_LIVE_TESTS": "1"},
            (True, False, False),
            "SHODAN_TEST_TARGETS",
        ),
    ],
)
def test_live_gate_reports_each_missing_requirement(
    markers: set[str],
    environ: dict[str, str],
    options: tuple[bool, bool, bool],
    expected: str,
) -> None:
    reason = live_gate_reason(
        markers,
        environ,
        allow_live=options[0],
        allow_credits=options[1],
        allow_mutations=options[2],
    )
    assert reason is not None and expected in reason


def test_all_mutating_target_gates_can_be_opened_explicitly() -> None:
    environ = {
        "SHODAN_LIVE_TESTS": "1",
        "SHODAN_MUTATING_TESTS": "1",
        "SHODAN_TEST_TARGETS": "192.0.2.1,2001:db8::/126",
    }
    assert (
        live_gate_reason(
            {"live", "mutating", "targeted"},
            environ,
            allow_live=True,
            allow_credits=False,
            allow_mutations=True,
        )
        is None
    )
    assert authorized_targets(environ) == ("192.0.2.1/32", "2001:db8::/126")


@pytest.mark.parametrize("value", ["not-an-ip", "fe80::1%adapter"])
def test_authorized_targets_reject_invalid_input(value: str) -> None:
    with pytest.raises(ValueError):
        authorized_targets({"SHODAN_TEST_TARGETS": value})
