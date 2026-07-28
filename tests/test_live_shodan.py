"""Optional real-API smoke tests; collection is fail-closed in tests/conftest.py."""

from __future__ import annotations

import ipaddress
import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from shodan_skill.config import Settings
from shodan_skill.errors import AuthenticationError
from shodan_skill.transport import ApiFamily, HttpTransport
from tests.live_support import authorized_targets


@pytest.fixture
def live_transport() -> Iterator[HttpTransport]:
    try:
        transport = HttpTransport(Settings.load())
    except AuthenticationError as exc:
        pytest.skip(str(exc))
    with transport:
        yield transport


@pytest.mark.live
@pytest.mark.parametrize(
    ("api", "path", "params"),
    [
        ("rest", "/api-info", None),
        ("rest", "/tools/myip", None),
        ("rest", "/shodan/host/search/filters", None),
        ("rest", "/shodan/host/search/facets", None),
        ("rest", "/shodan/host/count", {"query": "port:443"}),
        ("exploits", "/count", {"query": "apache"}),
    ],
)
def test_live_read_only_smoke(
    live_transport: HttpTransport,
    api: ApiFamily,
    path: str,
    params: dict[str, str] | None,
) -> None:
    assert live_transport.request(api, "GET", path, params=params) is not None


@pytest.mark.live
@pytest.mark.targeted
def test_live_authorized_host_info(live_transport: HttpTransport) -> None:
    network = ipaddress.ip_network(authorized_targets(os.environ)[0])
    result = live_transport.request("rest", "GET", f"/shodan/host/{network.network_address}", params={"minify": "true"})
    assert isinstance(result, dict)


@pytest.mark.live
@pytest.mark.credit
def test_live_dns_domain_credit_opt_in(live_transport: HttpTransport) -> None:
    assert isinstance(live_transport.request("rest", "GET", "/dns/domain/example.com", retry=False), dict)


@pytest.mark.live
@pytest.mark.enterprise
@pytest.mark.parametrize(("api", "path"), [("trends", "/api/v1/search/filters"), ("rest", "/shodan/data")])
def test_live_enterprise_read_only(live_transport: HttpTransport, api: ApiFamily, path: str) -> None:
    assert live_transport.request(api, "GET", path) is not None


@pytest.mark.live
@pytest.mark.mutating
@pytest.mark.targeted
def test_live_create_and_remove_alert(live_transport: HttpTransport) -> None:
    target = authorized_targets(os.environ)[0]
    name = f"shodan-skill-live-test-{uuid.uuid4().hex}"
    alert_id: str | None = None
    try:
        created = live_transport.request(
            "rest",
            "POST",
            "/shodan/alert",
            json_body={"name": name, "filters": {"ip": [target]}, "expires": 3600},
        )
        if isinstance(created, dict) and created.get("id") is not None:
            alert_id = str(created["id"])
        assert alert_id
    finally:
        if alert_id is None:
            alerts: Any = live_transport.request("rest", "GET", "/shodan/alert/info")
            if isinstance(alerts, list):
                match = next((item for item in alerts if isinstance(item, dict) and item.get("name") == name), None)
                if isinstance(match, dict) and match.get("id") is not None:
                    alert_id = str(match["id"])
        if alert_id is not None:
            live_transport.request("rest", "DELETE", f"/shodan/alert/{alert_id}")
