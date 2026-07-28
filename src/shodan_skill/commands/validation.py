"""Reusable command argument normalization and validation."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from pathlib import Path

from shodan_skill.errors import UsageError
from shodan_skill.transport import MAX_DOWNLOAD_CHUNK_SIZE

DOMAIN_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def positive(value: int | None, name: str) -> None:
    if value is not None and value < 1:
        raise UsageError(f"{name} must be at least 1")


def download_chunk_size(value: int) -> int:
    if value < 1 or value > MAX_DOWNLOAD_CHUNK_SIZE:
        raise UsageError(f"chunk-size must be between 1 and {MAX_DOWNLOAD_CHUNK_SIZE}")
    return value


def query(value: str) -> str:
    if not value.strip():
        raise UsageError("Query must not be blank.")
    return value


def domain(value: str) -> str:
    try:
        normalized = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UsageError(f"Invalid domain: {value}") from exc
    if (
        not normalized
        or len(normalized) > 253
        or any(not DOMAIN_LABEL.fullmatch(label) for label in normalized.split("."))
    ):
        raise UsageError(f"Invalid domain: {value}")
    return normalized


def domains(value: str) -> str:
    items = value.split(",")
    if not items or any(not item for item in items):
        raise UsageError("At least one domain is required.")
    return ",".join(domain(item) for item in items)


def ips(value: str) -> str:
    items = value.split(",")
    if not items or any(not item for item in items):
        raise UsageError("At least one IP address is required.")
    try:
        if any("%" in item for item in items):
            raise ValueError("scoped IPv6 addresses are not supported")
        return ",".join(str(ipaddress.ip_address(item)) for item in items)
    except ValueError as exc:
        raise UsageError(f"Invalid IP address list: {value}") from exc


def networks(value: str) -> tuple[tuple[str, ...], int]:
    items = tuple(value.split(","))
    if not items or any(not item for item in items):
        raise UsageError("At least one IP address or CIDR is required.")
    try:
        if any("%" in item for item in items):
            raise ValueError("scoped IPv6 networks are not supported")
        parsed = tuple(ipaddress.ip_network(item, strict=False) for item in items)
        ipv4_networks = (network for network in parsed if isinstance(network, ipaddress.IPv4Network))
        ipv6_networks = (network for network in parsed if isinstance(network, ipaddress.IPv6Network))
        collapsed: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
            *ipaddress.collapse_addresses(ipv4_networks),
            *ipaddress.collapse_addresses(ipv6_networks),
        )
    except ValueError as exc:
        raise UsageError(f"Invalid scan or alert target list: {value}") from exc
    canonical = tuple(
        str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
        for network in collapsed
    )
    return canonical, sum(network.num_addresses for network in collapsed)


def protocol(value: str) -> str:
    if value != value.strip() or not re.fullmatch(r"[A-Za-z0-9._+-]+", value):
        raise UsageError(f"Invalid scan protocol: {value!r}")
    return value


def services(values: Sequence[str]) -> list[list[object]]:
    parsed_services: list[list[object]] = []
    for value in values:
        try:
            port_text, protocol_name = value.split(":", 1)
            port = int(port_text)
        except ValueError as exc:
            raise UsageError(f"Invalid service {value!r}; use PORT:PROTOCOL") from exc
        if not 1 <= port <= 65535:
            raise UsageError(f"Invalid service {value!r}; use PORT:PROTOCOL")
        parsed_services.append([port, protocol(protocol_name)])
    return parsed_services


def key_values(values: Sequence[str], *, required: bool = True) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise UsageError("Invalid notifier argument; use NAME=VALUE")
        name, item = value.split("=", 1)
        if not name.strip() or name != name.strip() or not item.strip():
            raise UsageError("Invalid notifier argument; use NAME=VALUE")
        if name.casefold() in {"provider", "description"}:
            raise UsageError(f"Notifier argument name is reserved: {name}")
        result[name] = item
    if required and not result:
        raise UsageError("At least one --arg NAME=VALUE is required.")
    return result


def validate_download_destination(destination: Path, *, resume: bool, overwrite: bool) -> None:
    partial = destination.with_name(f"{destination.name}.part")
    if destination.exists() and destination.is_dir():
        raise UsageError("Output file points to a directory.")
    if destination.parent.exists() and not destination.parent.is_dir():
        raise UsageError("Output file parent is not a directory.")
    if partial.is_symlink():
        raise UsageError("Refusing to write through a symbolic partial-download path.")
    if partial.exists() and partial.is_dir():
        raise UsageError("Partial-download path points to a directory.")
    if partial.exists() and not (resume or overwrite):
        raise UsageError("Partial download already exists; use --resume or --overwrite to replace it.")
    if destination.exists() and not overwrite:
        raise UsageError("Output file already exists; use --overwrite to replace it.")


def stream_selector(value: str, kind: str) -> str:
    items = value.split(",")
    if not items or any(not item for item in items):
        raise UsageError(f"At least one {kind} is required.")
    if kind == "port":
        try:
            ports = [int(item) for item in items]
        except ValueError as exc:
            raise UsageError(f"Invalid port list: {value}") from exc
        if any(port < 1 or port > 65535 for port in ports):
            raise UsageError(f"Invalid port list: {value}")
        return ",".join(str(port) for port in ports)
    if kind == "country":
        if any(not re.fullmatch(r"[A-Za-z]{2}", item) for item in items):
            raise UsageError(f"Invalid country-code list: {value}")
        return ",".join(item.upper() for item in items)
    if kind == "ASN":
        if any(not re.fullmatch(r"(?:AS)?\d+", item, re.IGNORECASE) for item in items):
            raise UsageError(f"Invalid ASN list: {value}")
        asns = [int(item[2:] if item.upper().startswith("AS") else item) for item in items]
        if any(asn < 1 or asn > 4_294_967_295 for asn in asns):
            raise UsageError(f"Invalid ASN list: {value}")
        return ",".join(str(asn) for asn in asns)
    if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", item, re.IGNORECASE) for item in items):
        raise UsageError(f"Invalid CVE list: {value}")
    return ",".join(item.upper() for item in items)


def path_token(value: str, name: str, *, allow_at: bool = False) -> str:
    pattern = r"[A-Za-z0-9._+@-]+" if allow_at else r"[A-Za-z0-9._+-]+"
    if not value or value in {".", ".."} or not re.fullmatch(pattern, value):
        raise UsageError(f"Invalid {name}: {value}")
    return value


def ip(value: str) -> str:
    try:
        if "%" in value:
            raise ValueError("scoped IPv6 addresses are not supported")
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise UsageError(f"Invalid IP address: {value}") from exc


def service_path_token(value: str) -> str:
    try:
        host, port_text = value.rsplit(":", 1)
        address = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        if "%" in address:
            raise ValueError("scoped IPv6 addresses are not supported")
        ipaddress.ip_address(address)
        port = int(port_text)
    except ValueError as exc:
        raise UsageError(f"Invalid ignored service: {value}; use IP:PORT") from exc
    if not 1 <= port <= 65535:
        raise UsageError(f"Invalid ignored service: {value}; use IP:PORT")
    return value


def trigger_path_token(value: str, *, allow_multiple: bool) -> str:
    triggers = value.split(",")
    if not allow_multiple and len(triggers) != 1:
        raise UsageError("Ignore and unignore operations accept exactly one alert trigger.")
    if not triggers or any(not trigger for trigger in triggers):
        raise UsageError(f"Invalid alert trigger list: {value}")
    return ",".join(path_token(trigger, "alert trigger") for trigger in triggers)
