"""Non-streaming Shodan command implementations."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from shodan_skill.commands.validation import (
    domain,
    domains,
    download_chunk_size,
    ip,
    ips,
    key_values,
    networks,
    path_token,
    positive,
    protocol,
    query,
    service_path_token,
    services,
    trigger_path_token,
    validate_download_destination,
)
from shodan_skill.errors import ApiError, InternalError, UsageError
from shodan_skill.transport import HttpTransport


def execute(args: argparse.Namespace, transport: HttpTransport) -> Any:
    """Execute one validated non-streaming CLI command."""
    group, action = args.group, args.action
    if (group, action) == ("host", "info"):
        host_ip = ip(args.ip)
        return transport.request(
            "rest",
            "GET",
            f"/shodan/host/{host_ip}",
            params={"history": str(args.history).lower(), "minify": str(args.minify).lower()},
        )
    if group == "search":
        if action in {"facets", "filters"}:
            return transport.request("rest", "GET", f"/shodan/host/search/{action}")
        if action == "tokens":
            return transport.request("rest", "GET", "/shodan/host/search/tokens", params={"query": query(args.query)})
        params = {"query": query(args.query), "facets": args.facets}
        if action == "hosts":
            positive(args.page, "page")
            positive(args.limit, "limit")
            params.update(
                {
                    "page": args.page,
                    "minify": str(args.minify).lower(),
                    "fields": args.fields,
                }
            )
            result = transport.request("rest", "GET", "/shodan/host/search", params=params, retry=False)
            return _limit_matches(result, args.limit)
        return transport.request("rest", "GET", "/shodan/host/count", params=params)
    if group == "scan":
        if action == "submit":
            scan_networks, _count = networks(args.ips)
            scan_services = services(args.service)
            ips_value = ",".join(scan_networks)
            if scan_services:
                ips_value = json.dumps(
                    {network: scan_services for network in scan_networks},
                    separators=(",", ":"),
                )
            form_body: dict[str, object] = {"ips": ips_value}
            if args.force:
                form_body["force"] = "true"
            return transport.request("rest", "POST", "/shodan/scan", form_body=form_body)
        if action == "internet":
            return transport.request(
                "rest",
                "POST",
                "/shodan/scan/internet",
                form_body={"port": args.port, "protocol": protocol(args.protocol)},
            )
        if action == "list":
            positive(args.page, "page")
            return transport.request("rest", "GET", "/shodan/scans", params={"page": args.page})
        if action == "status":
            scan_id = path_token(args.id, "scan identifier")
            return transport.request("rest", "GET", f"/shodan/scan/{scan_id}")
        return transport.request("rest", "GET", f"/shodan/{action}")
    if group == "alert":
        if action == "list":
            alert_params = (
                None if args.include_expired is None else {"include_expired": str(args.include_expired).lower()}
            )
            if alert_params is None:
                return transport.request("rest", "GET", "/shodan/alert/info")
            return transport.request("rest", "GET", "/shodan/alert/info", params=alert_params)
        if action == "info":
            alert_id = path_token(args.id, "alert identifier")
            alert_params = (
                None if args.include_expired is None else {"include_expired": str(args.include_expired).lower()}
            )
            if alert_params is None:
                return transport.request("rest", "GET", f"/shodan/alert/{alert_id}/info")
            return transport.request("rest", "GET", f"/shodan/alert/{alert_id}/info", params=alert_params)
        if action == "triggers":
            return transport.request("rest", "GET", "/shodan/alert/triggers")
        if action == "create":
            alert_networks, _count = networks(args.networks)
            return transport.request(
                "rest",
                "POST",
                "/shodan/alert",
                json_body={"name": args.name, "filters": {"ip": list(alert_networks)}, "expires": args.expires},
            )
        if action == "edit":
            alert_networks, _count = networks(args.networks)
            alert_id = path_token(args.id, "alert identifier")
            return transport.request(
                "rest",
                "POST",
                f"/shodan/alert/{alert_id}",
                json_body={"filters": {"ip": list(alert_networks)}},
            )
        if action == "delete":
            alert_id = path_token(args.id, "alert identifier")
            return transport.request("rest", "DELETE", f"/shodan/alert/{alert_id}")
        if action == "trigger":
            alert_id = path_token(args.id, "alert identifier")
            trigger = trigger_path_token(args.trigger, allow_multiple=args.detail in {"enable", "disable"})
            method = "PUT" if args.detail in {"enable", "ignore"} else "DELETE"
            path = f"/shodan/alert/{alert_id}/trigger/{trigger}"
            if args.detail in {"ignore", "unignore"}:
                path += f"/ignore/{service_path_token(args.service)}"
            return transport.request("rest", method, path)
        alert_id = path_token(args.id, "alert identifier")
        notifier_id = path_token(args.notifier_id, "notifier identifier")
        method = "PUT" if args.detail == "add" else "DELETE"
        return transport.request("rest", method, f"/shodan/alert/{alert_id}/notifier/{notifier_id}")
    if group == "dns":
        if action == "domain":
            positive(args.page, "page")
            domain_name = domain(args.domain)
            return transport.request(
                "rest",
                "GET",
                f"/dns/domain/{domain_name}",
                params={"history": str(args.history).lower(), "type": args.type, "page": args.page},
                retry=False,
            )
        if action == "resolve":
            return transport.request("rest", "GET", "/dns/resolve", params={"hostnames": domains(args.hostnames)})
        return transport.request("rest", "GET", "/dns/reverse", params={"ips": ips(args.ips)})
    if group == "account":
        path = "/account/profile" if action == "profile" else "/api-info"
        return transport.request("rest", "GET", path)
    if group == "tools":
        return transport.request("rest", "GET", f"/tools/{action}")
    if group == "query":
        if action == "list":
            positive(args.page, "page")
            return transport.request(
                "rest",
                "GET",
                "/shodan/query",
                params={"page": args.page, "sort": args.sort, "order": args.order},
            )
        if action == "search":
            positive(args.page, "page")
            return transport.request(
                "rest",
                "GET",
                "/shodan/query/search",
                params={"query": query(args.query), "page": args.page},
            )
        positive(args.limit, "limit")
        return transport.request("rest", "GET", "/shodan/query/tags", params={"size": args.limit})
    if group == "notifier":
        if action == "list":
            return transport.request("rest", "GET", "/notifier")
        if action == "providers":
            return transport.request("rest", "GET", "/notifier/provider")
        if action == "info":
            notifier_id = path_token(args.id, "notifier identifier")
            return transport.request("rest", "GET", f"/notifier/{notifier_id}")
        if action == "create":
            form: dict[str, object] = {"provider": args.provider, **key_values(args.arg)}
            form["description"] = args.description
            return transport.request("rest", "POST", "/notifier", form_body=form)
        if action == "edit":
            notifier_id = path_token(args.id, "notifier identifier")
            return transport.request("rest", "PUT", f"/notifier/{notifier_id}", form_body=key_values(args.arg))
        notifier_id = path_token(args.id, "notifier identifier")
        return transport.request("rest", "DELETE", f"/notifier/{notifier_id}")
    if group == "data":
        if action == "list":
            return transport.request("rest", "GET", "/shodan/data")
        dataset = path_token(args.dataset, "dataset")
        destination: Path | None = None
        name: str | None = None
        if action == "download":
            download_chunk_size(args.chunk_size)
            name = path_token(args.name, "dataset file")
            destination = args.output_file or Path(f"{dataset}-{name}")
            if args.resume and args.overwrite:
                raise UsageError("--resume and --overwrite cannot be used together.")
            validate_download_destination(destination, resume=args.resume, overwrite=args.overwrite)
        files = transport.request("rest", "GET", f"/shodan/data/{dataset}")
        if action == "files":
            return files
        if destination is None or name is None:
            raise InternalError("Dataset download arguments were not initialized.")
        if not isinstance(files, list):
            raise ApiError("Shodan returned invalid dataset file metadata.")
        metadata = next((item for item in files if isinstance(item, dict) and item.get("name") == name), None)
        if metadata is None:
            raise UsageError(f"Dataset file not found: {name}")
        if not isinstance(metadata.get("url"), str) or not metadata["url"]:
            raise ApiError("Shodan returned invalid dataset download metadata.")
        size = metadata.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ApiError("Shodan returned invalid dataset size metadata.")
        expected_size = size
        expected_sha1: str | None = None
        if args.verify:
            checksum = metadata.get("sha1")
            if checksum is not None and (
                not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", checksum)
            ):
                raise ApiError("Shodan returned invalid dataset checksum metadata.")
            expected_sha1 = checksum
        return transport.download_file(
            metadata["url"],
            destination,
            expected_size=expected_size,
            expected_sha1=expected_sha1,
            resume=args.resume,
            overwrite=args.overwrite,
            chunk_size=args.chunk_size,
        )
    if group == "org":
        if action == "info":
            return transport.request("rest", "GET", "/org")
        user = path_token(args.user, "organization user", allow_at=True)
        method = "PUT" if args.detail == "add" else "DELETE"
        notification = getattr(args, "notify", None)
        org_params = None if notification is None else {"notify": str(notification).lower()}
        return transport.request("rest", method, f"/org/member/{user}", params=org_params)
    if group == "exploits":
        if action == "count":
            return transport.request(
                "exploits",
                "GET",
                "/count",
                params={"query": query(args.query), "facets": args.facets},
            )
        positive(args.page, "page")
        positive(args.limit, "limit")
        positive(args.truncate_code, "truncate-code")
        result = transport.request(
            "exploits",
            "GET",
            "/search",
            params={"query": query(args.query), "page": args.page, "facets": args.facets},
        )
        result = _limit_matches(result, args.limit)
        return _reduce_exploit_code(result, omit=args.omit_code, truncate=args.truncate_code)
    if group == "trends":
        path = "/api/v1/search" if action == "search" else f"/api/v1/search/{action}"
        trends_params: Mapping[str, object] | None = (
            {"query": query(args.query), "facets": args.facets} if action == "search" else None
        )
        return transport.request("trends", "GET", path, params=trends_params)
    raise InternalError(f"No implementation for {group} {action}")


def _limit_matches(result: Any, limit: int | None) -> Any:
    if limit is None or not isinstance(result, dict) or not isinstance(result.get("matches"), list):
        return result
    limited = dict(result)
    limited["matches"] = limited["matches"][:limit]
    return limited


def _reduce_exploit_code(result: Any, *, omit: bool, truncate: int | None) -> Any:
    if not (omit or truncate) or not isinstance(result, dict) or not isinstance(result.get("matches"), list):
        return result
    reduced = dict(result)
    reduced_matches: list[Any] = []
    for match in result["matches"]:
        if not isinstance(match, dict):
            reduced_matches.append(match)
            continue
        item = dict(match)
        if omit:
            item.pop("code", None)
        elif isinstance(item.get("code"), str):
            item["code"] = item["code"][:truncate]
        reduced_matches.append(item)
    reduced["matches"] = reduced_matches
    return reduced
