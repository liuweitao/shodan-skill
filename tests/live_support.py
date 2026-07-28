"""Pure gate evaluation helpers for optional live Shodan tests."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping

DANGEROUS_MARKERS = {"credit", "mutating", "enterprise", "targeted"}


def authorized_targets(environ: Mapping[str, str]) -> tuple[str, ...]:
    """Return validated, canonical networks explicitly supplied by the operator."""
    raw = environ.get("SHODAN_TEST_TARGETS", "")
    values = tuple(value.strip() for value in raw.split(",") if value.strip())
    if not values:
        return ()
    if any("%" in value for value in values):
        raise ValueError("scoped IPv6 targets are not supported")
    return tuple(str(ipaddress.ip_network(value, strict=False)) for value in values)


def marker_configuration_error(markers: set[str]) -> str | None:
    """Return a fail-closed collection error for an unsafe marker combination."""
    dangerous = markers & DANGEROUS_MARKERS
    if dangerous and "live" not in markers:
        return f"{', '.join(sorted(dangerous))} markers require the live marker"
    return None


def live_gate_reason(
    markers: set[str],
    environ: Mapping[str, str],
    *,
    allow_live: bool,
    allow_credits: bool,
    allow_mutations: bool,
) -> str | None:
    """Return why a live test must be skipped, or None when every gate is open."""
    if "live" not in markers:
        return None
    if environ.get("SHODAN_LIVE_TESTS") != "1":
        return "SHODAN_LIVE_TESTS=1 is required"
    if not allow_live:
        return "--allow-live-shodan is required for this pytest invocation"
    if "credit" in markers and not allow_credits:
        return "--allow-shodan-credits is required for credit-consuming tests"
    if "mutating" in markers:
        if environ.get("SHODAN_MUTATING_TESTS") != "1":
            return "SHODAN_MUTATING_TESTS=1 is required for mutations"
        if not allow_mutations:
            return "--allow-shodan-mutations is required for this pytest invocation"
    if "enterprise" in markers and environ.get("SHODAN_ENTERPRISE_TESTS") != "1":
        return "SHODAN_ENTERPRISE_TESTS=1 is required for Enterprise tests"
    if "targeted" in markers:
        try:
            targets = authorized_targets(environ)
        except ValueError:
            return "SHODAN_TEST_TARGETS must contain only valid authorized IP addresses or CIDRs"
        if not targets:
            return "SHODAN_TEST_TARGETS must contain at least one authorized target"
    return None
