"""Portable grouped CLI and deprecated prototype aliases."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn, TextIO, cast

from shodan_skill import __version__
from shodan_skill.commands import execute, run_stream
from shodan_skill.commands.validation import (
    domain as _domain,
)
from shodan_skill.commands.validation import (
    domains as _domains,
)
from shodan_skill.commands.validation import (
    download_chunk_size as _download_chunk_size,
)
from shodan_skill.commands.validation import (
    ip as _ip,
)
from shodan_skill.commands.validation import (
    ips as _ips,
)
from shodan_skill.commands.validation import (
    key_values as _key_values,
)
from shodan_skill.commands.validation import (
    networks as _networks,
)
from shodan_skill.commands.validation import (
    path_token as _path_token,
)
from shodan_skill.commands.validation import (
    positive as _positive,
)
from shodan_skill.commands.validation import (
    protocol as _protocol,
)
from shodan_skill.commands.validation import (
    query as _query,
)
from shodan_skill.commands.validation import (
    service_path_token as _service_path_token,
)
from shodan_skill.commands.validation import (
    services as _services,
)
from shodan_skill.commands.validation import (
    stream_selector as _stream_selector,
)
from shodan_skill.commands.validation import (
    trigger_path_token as _trigger_path_token,
)
from shodan_skill.commands.validation import (
    validate_download_destination as _validate_download_destination,
)
from shodan_skill.config import Settings
from shodan_skill.errors import (
    InternalError,
    InterruptedError,
    ShodanSkillError,
    UsageError,
)
from shodan_skill.output import error_envelope, success_envelope, write_payload
from shodan_skill.safety import OperationPreview, require_confirmation, resolve_safety_mode
from shodan_skill.transport import HttpTransport

TransportFactory = Callable[[Settings], HttpTransport]

LEGACY_PREFIXES: dict[str, tuple[str, ...]] = {
    "host": ("host", "info"),
    "search": ("search", "hosts"),
    "count": ("search", "count"),
    "scan": ("scan", "submit"),
    "alert_list": ("alert", "list"),
    "alert_create": ("alert", "create"),
    "alert_info": ("alert", "info"),
    "dns_domain": ("dns", "domain"),
    "dns_resolve": ("dns", "resolve"),
    "profile": ("account", "profile"),
    "api_info": ("account", "api-info"),
    "myip": ("tools", "myip"),
    "ports": ("scan", "ports"),
    "protocols": ("scan", "protocols"),
    "query_search": ("query", "search"),
    "query_tags": ("query", "tags"),
    "notifier_list": ("notifier", "list"),
    "exploit_search": ("exploits", "search"),
    "trends": ("trends", "search"),
    "filters": ("reference", "filters"),
    "datapedia": ("reference", "datapedia"),
}
GROUP_ACTIONS: dict[str, set[str]] = {
    "host": {"info"},
    "search": {"hosts", "count", "facets", "filters", "tokens"},
    "scan": {"submit", "ports", "protocols", "internet", "list", "status"},
    "trends": {"search", "filters", "facets"},
    "data": {"list", "files", "download"},
    "org": {"info", "member"},
}
RAW_SENSITIVE_OPTION = re.compile(
    (
        r"^--(?:api[_-]?key|shodan[_-]?key|key|authorization|auth|bearer|credential|password|passwd|secret"
        r"|token|cookie|signature|sig|routing[_-]?key|webhook[_-]?url|proxy|url)(?:=|$)"
    ),
    re.IGNORECASE,
)
RAW_NOTIFIER_SECRET_ASSIGNMENT = re.compile(
    (
        r"(?:^|[=,;&\s])(?:api[_-]?key|authorization|bearer|credential|password|passwd|secret|token|cookie"
        r"|signature|routing[_-]?key|webhook[_-]?url|url)\s*="
    ),
    re.IGNORECASE,
)
RAW_URL = re.compile(r"https?://\S+", re.IGNORECASE)


class ArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> NoReturn:
        raise UsageError(message)


def _leaf(subparsers: Any, name: str, **kwargs: Any) -> argparse.ArgumentParser:
    return cast(argparse.ArgumentParser, subparsers.add_parser(name, **kwargs))


def _confirmation(parser: argparse.ArgumentParser, *, authorization: bool = False) -> None:
    parser.add_argument("--confirm", action="store_true", help="Satisfy the strict-mode confirmation gate")
    parser.add_argument("--yes", action="store_true", help="Noninteractive strict-mode alias for --confirm")
    if authorization:
        parser.add_argument(
            "--acknowledge-authorization",
            action="store_true",
            help="Satisfy the strict-mode scan or monitoring authorization gate",
        )


def _stream_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--limit", type=int, default=10, help="Stop after this many non-debug records")
    parser.add_argument("--stream-format", choices=("jsonl", "sse"), default="jsonl")
    parser.add_argument("--debug", action="store_true", help="Request server discard diagnostics")
    parser.add_argument("--reconnect", action="store_true", help="Reconnect after a timeout, disconnect, or EOF")
    parser.add_argument("--max-reconnects", type=int, default=3, help="Bound reconnect attempts (maximum 10)")


def _runtime_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--connect-timeout", type=float, help="Override SHODAN_CONNECT_TIMEOUT in seconds")
    parser.add_argument("--read-timeout", type=float, help="Override SHODAN_READ_TIMEOUT in seconds")
    parser.add_argument("--write-timeout", type=float, help="Override SHODAN_WRITE_TIMEOUT in seconds")
    parser.add_argument("--pool-timeout", type=float, help="Override SHODAN_POOL_TIMEOUT in seconds")
    parser.add_argument("--stream-timeout", type=float, help="Override SHODAN_STREAM_TIMEOUT in seconds")
    parser.add_argument("--retries", type=int, help="Override SHODAN_RETRIES (0-5)")
    parser.add_argument(
        "--proxy",
        help="Explicit http(s) proxy; environment proxy variables are ignored",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = ArgumentParser(prog="shodan-skill", description="Portable CLI for the documented Shodan APIs")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--output", choices=("json", "jsonl", "human"), default="json")
    parser.add_argument(
        "--safety-mode",
        choices=("direct", "strict"),
        help="Execution policy; defaults to direct or SHODAN_SAFETY_MODE",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and display an operation preview without sending a request",
    )
    _runtime_options(parser)
    groups = parser.add_subparsers(dest="group", required=True)

    host = _leaf(groups, "host", help="Host intelligence")
    host_commands = host.add_subparsers(dest="action", required=True)
    host_info = _leaf(host_commands, "info", help="Read host services/history; does not consume query credits")
    host_info.add_argument("ip")
    host_info.add_argument("--history", action="store_true")
    host_info.add_argument("--minify", action="store_true")

    search = _leaf(groups, "search", help="Search and count")
    search_commands = search.add_subparsers(dest="action", required=True)
    search_hosts = _leaf(
        search_commands,
        "hosts",
        help="Search hosts; filters or pages after the first can consume query credits",
    )
    search_hosts.add_argument("query")
    search_hosts.add_argument("--page", type=int, default=1)
    search_hosts.add_argument("--facets")
    search_hosts.add_argument("--minify", action=argparse.BooleanOptionalAction, default=True)
    search_hosts.add_argument("--fields")
    search_hosts.add_argument("--limit", type=int)
    _confirmation(search_hosts)
    search_count = _leaf(search_commands, "count", help="Count matching hosts without consuming query credits")
    search_count.add_argument("query")
    search_count.add_argument("--facets")
    _leaf(search_commands, "facets", help="List current search facets")
    _leaf(search_commands, "filters", help="List current search filters")
    search_tokens = _leaf(search_commands, "tokens", help="Parse a query into filters and tokens")
    search_tokens.add_argument("query")

    scan = _leaf(groups, "scan", help="Scan operations and reference data")
    scan_commands = scan.add_subparsers(dest="action", required=True)
    scan_submit = _leaf(scan_commands, "submit")
    scan_submit.add_argument("ips")
    scan_submit.add_argument("--service", action="append", default=[], metavar="PORT:PROTOCOL")
    scan_submit.add_argument("--force", action="store_true", help="Force an Enterprise re-scan")
    _confirmation(scan_submit, authorization=True)
    _leaf(scan_commands, "ports", help="List ports crawled by Shodan; read-only")
    _leaf(scan_commands, "protocols", help="List on-demand scan protocols; read-only")
    scan_internet = _leaf(scan_commands, "internet", help="Enterprise Internet-wide scan")
    scan_internet.add_argument("port", type=int)
    scan_internet.add_argument("protocol")
    _confirmation(scan_internet, authorization=True)
    scan_list = _leaf(scan_commands, "list", help="List submitted scans")
    scan_list.add_argument("--page", type=int, default=1)
    scan_status = _leaf(scan_commands, "status", help="Read scan status")
    scan_status.add_argument("id")

    alert = _leaf(groups, "alert", help="Network alerts")
    alert_commands = alert.add_subparsers(dest="action", required=True)
    alert_list = _leaf(alert_commands, "list")
    alert_list.add_argument("--include-expired", action=argparse.BooleanOptionalAction, default=None)
    _leaf(alert_commands, "triggers")
    alert_info = _leaf(alert_commands, "info")
    alert_info.add_argument("id")
    alert_info.add_argument("--include-expired", action=argparse.BooleanOptionalAction, default=None)
    alert_create = _leaf(alert_commands, "create")
    alert_create.add_argument("name")
    alert_create.add_argument("networks")
    alert_create.add_argument("--expires", type=int, default=0)
    _confirmation(alert_create, authorization=True)
    alert_delete = _leaf(alert_commands, "delete")
    alert_delete.add_argument("id")
    _confirmation(alert_delete)
    alert_edit = _leaf(alert_commands, "edit")
    alert_edit.add_argument("id")
    alert_edit.add_argument("networks")
    _confirmation(alert_edit, authorization=True)

    alert_trigger = _leaf(alert_commands, "trigger")
    trigger_commands = alert_trigger.add_subparsers(dest="detail", required=True)
    for action in ("enable", "disable", "ignore", "unignore"):
        trigger = _leaf(trigger_commands, action)
        trigger.add_argument("id")
        trigger.add_argument("trigger")
        if action in {"ignore", "unignore"}:
            trigger.add_argument("service")
        _confirmation(trigger)

    alert_notifier = _leaf(alert_commands, "notifier")
    alert_notifier_commands = alert_notifier.add_subparsers(dest="detail", required=True)
    for action in ("add", "remove"):
        alert_notifier_action = _leaf(alert_notifier_commands, action)
        alert_notifier_action.add_argument("id")
        alert_notifier_action.add_argument("notifier_id")
        _confirmation(alert_notifier_action)

    dns = _leaf(groups, "dns", help="DNS operations")
    dns_commands = dns.add_subparsers(dest="action", required=True)
    dns_domain = _leaf(dns_commands, "domain", help="Read domain records/history; consumes one query credit")
    dns_domain.add_argument("domain")
    dns_domain.add_argument("--history", action="store_true")
    dns_domain.add_argument("--type", choices=("A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT"))
    dns_domain.add_argument("--page", type=int, default=1)
    _confirmation(dns_domain)
    dns_resolve = _leaf(dns_commands, "resolve", help="Resolve comma-separated domains; read-only")
    dns_resolve.add_argument("hostnames")
    dns_reverse = _leaf(dns_commands, "reverse", help="Reverse-resolve comma-separated IPs; read-only")
    dns_reverse.add_argument("ips")

    account = _leaf(groups, "account", help="Account and plan")
    account_commands = account.add_subparsers(dest="action", required=True)
    _leaf(account_commands, "profile", help="Read account membership/profile details")
    _leaf(account_commands, "api-info", help="Read API plan and remaining credit information")

    tools = _leaf(groups, "tools", help="Utility operations")
    tools_commands = tools.add_subparsers(dest="action", required=True)
    _leaf(tools_commands, "myip", help="Show the caller's public IP as seen by Shodan")
    _leaf(tools_commands, "httpheaders", help="Show HTTP headers received by Shodan")

    query = _leaf(groups, "query", help="Saved-query directory")
    query_commands = query.add_subparsers(dest="action", required=True)
    query_list = _leaf(query_commands, "list", help="List community saved queries")
    query_list.add_argument("--page", type=int, default=1)
    query_list.add_argument("--sort", choices=("votes", "timestamp"), default="timestamp")
    query_list.add_argument("--order", choices=("asc", "desc"), default="desc")
    query_search = _leaf(query_commands, "search", help="Search community saved queries")
    query_search.add_argument("query")
    query_search.add_argument("--page", type=int, default=1)
    query_tags = _leaf(query_commands, "tags", help="List popular saved-query tags")
    query_tags.add_argument("--limit", type=int, default=10)

    notifier = _leaf(groups, "notifier", help="Notification services")
    notifier_commands = notifier.add_subparsers(dest="action", required=True)
    _leaf(notifier_commands, "list")
    notifier_info = _leaf(notifier_commands, "info")
    notifier_info.add_argument("id")
    _leaf(notifier_commands, "providers")
    notifier_create = _leaf(notifier_commands, "create")
    notifier_create.add_argument("provider")
    notifier_create.add_argument("--arg", action="append", default=[], metavar="NAME=VALUE")
    notifier_create.add_argument("--description", required=True)
    _confirmation(notifier_create)
    notifier_edit = _leaf(notifier_commands, "edit")
    notifier_edit.add_argument("id")
    notifier_edit.add_argument("--arg", action="append", default=[], metavar="NAME=VALUE")
    _confirmation(notifier_edit)
    notifier_delete = _leaf(notifier_commands, "delete")
    notifier_delete.add_argument("id")
    _confirmation(notifier_delete)

    data = _leaf(groups, "data", help="Enterprise bulk datasets")
    data_commands = data.add_subparsers(dest="action", required=True)
    _leaf(data_commands, "list", help="List datasets available to the Enterprise account")
    data_files = _leaf(data_commands, "files", help="List files and integrity metadata in a dataset")
    data_files.add_argument("dataset")
    data_download = _leaf(data_commands, "download", help="Download one dataset file from its signed URL")
    data_download.add_argument("dataset")
    data_download.add_argument("name")
    data_download.add_argument("--output-file", type=Path)
    data_download.add_argument("--resume", action="store_true")
    data_download.add_argument("--overwrite", action="store_true")
    data_download.add_argument("--verify", action=argparse.BooleanOptionalAction, default=True)
    data_download.add_argument("--chunk-size", type=int, default=65536)
    _confirmation(data_download)

    org = _leaf(groups, "org", help="Enterprise organization membership")
    org_commands = org.add_subparsers(dest="action", required=True)
    _leaf(org_commands, "info", help="Read organization details")
    org_member = _leaf(org_commands, "member")
    org_member_commands = org_member.add_subparsers(dest="detail", required=True)
    for action in ("add", "remove"):
        member = _leaf(org_member_commands, action)
        member.add_argument("user")
        if action == "add":
            member.add_argument("--notify", action=argparse.BooleanOptionalAction, default=None)
        _confirmation(member)

    exploits = _leaf(groups, "exploits", help="Exploit database")
    exploits_commands = exploits.add_subparsers(dest="action", required=True)
    exploits_search = _leaf(exploits_commands, "search")
    exploits_search.add_argument("query")
    exploits_search.add_argument("--page", type=int, default=1)
    exploits_search.add_argument("--facets")
    exploits_search.add_argument("--limit", type=int)
    exploit_code = exploits_search.add_mutually_exclusive_group()
    exploit_code.add_argument("--omit-code", action="store_true")
    exploit_code.add_argument("--truncate-code", type=int, metavar="CHARS")
    exploits_count = _leaf(exploits_commands, "count")
    exploits_count.add_argument("query")
    exploits_count.add_argument("--facets")

    trends = _leaf(groups, "trends", help="Historical Trends service")
    trends_commands = trends.add_subparsers(dest="action", required=True)
    trends_search = _leaf(trends_commands, "search")
    trends_search.add_argument("query")
    trends_search.add_argument("--facets")
    _leaf(trends_commands, "filters")
    _leaf(trends_commands, "facets")

    streams = _leaf(groups, "stream", help="Real-time streams")
    stream_commands = streams.add_subparsers(dest="action", required=True)
    for action in ("banners", "asn", "countries", "ports", "vulns", "alerts", "alert", "custom"):
        stream = _leaf(stream_commands, action)
        if action in {"asn", "countries", "ports", "vulns"}:
            stream.add_argument(action)
        elif action == "alert":
            stream.add_argument("id")
        elif action == "custom":
            stream.add_argument("query")
        _stream_options(stream)

    reference = _leaf(groups, "reference", help="Local official references")
    reference_commands = reference.add_subparsers(dest="action", required=True)
    _leaf(reference_commands, "filters")
    _leaf(reference_commands, "datapedia")
    return parser


def normalize_legacy(argv: Sequence[str]) -> tuple[list[str], str | None]:
    args = list(argv)
    if not args:
        return args, None
    first = args[0]
    if len(args) > 1 and args[1] in {"-h", "--help"} and (first in GROUP_ACTIONS or first == "stream"):
        return args, None
    if len(args) > 1 and args[1] in GROUP_ACTIONS.get(first, set()):
        return args, None
    if first == "stream":
        if "--ports" in args:
            index = args.index("--ports")
            if index + 1 >= len(args) or args[index + 1].startswith("-"):
                raise UsageError("--ports requires a comma-separated port list")
            value = args[index + 1]
            args[index : index + 2] = []
            return ["stream", "ports", value, *args[1:]], first
        if "--alert" in args:
            index = args.index("--alert")
            if index + 1 >= len(args) or args[index + 1].startswith("-"):
                raise UsageError("--alert requires an alert identifier")
            value = args[index + 1]
            args[index : index + 2] = []
            return ["stream", "alert", value, *args[1:]], first
        if len(args) == 1 or args[1].startswith("-"):
            return ["stream", "banners", *args[1:]], first
        return args, None
    replacement = LEGACY_PREFIXES.get(first)
    if replacement:
        normalized = [*replacement, *args[1:]]
        if first in {"alert_list", "alert_info"} and not any(
            option in args for option in ("--include-expired", "--no-include-expired")
        ):
            normalized.append("--include-expired")
        return normalized, first
    return args, None


def _command(args: argparse.Namespace) -> str:
    parts = [args.group, args.action]
    detail = getattr(args, "detail", None)
    if detail:
        parts.append(detail)
    return "-".join(parts)


def _credit_metadata(
    args: argparse.Namespace,
    preview: OperationPreview | None = None,
) -> tuple[str, int | None]:
    command = _command(args)
    impact = {
        "search-hosts": "conditional",
        "scan-submit": "scan",
        "scan-internet": "unknown",
        "dns-domain": "query",
    }.get(command, "none")
    if command == "dns-domain":
        return impact, 1
    if command == "scan-submit" and preview is not None:
        return impact, preview.target_count
    return impact, None


def _notifier_secret_values(args: argparse.Namespace) -> tuple[str, ...]:
    if args.group != "notifier" or args.action not in {"create", "edit"}:
        return ()
    secrets: list[str] = []
    for value in args.arg:
        if "=" in value:
            _name, item = value.split("=", 1)
            if item:
                secrets.append(item)
    return tuple(secrets)


def _raw_argument_secrets(argv: Sequence[str]) -> tuple[str, ...]:
    """Capture notifier values early enough to redact argument-parser errors."""
    secrets: list[str] = []
    notifier_command = any(
        argv[index] == "notifier" and argv[index + 1] in {"create", "edit"} for index in range(len(argv) - 1)
    )
    for index, raw_argument in enumerate(argv):
        if RAW_SENSITIVE_OPTION.match(raw_argument):
            if "=" in raw_argument:
                option_secret = raw_argument.split("=", 1)[1]
                if option_secret:
                    secrets.append(option_secret)
            elif index + 1 < len(argv):
                secrets.append(argv[index + 1])
        value: str | None = None
        if raw_argument == "--arg" and index + 1 < len(argv):
            value = argv[index + 1]
        elif raw_argument.startswith("--arg="):
            value = raw_argument.removeprefix("--arg=")
        elif notifier_command and raw_argument.startswith("--arg"):
            if "=" in raw_argument:
                value = raw_argument.split("=", 1)[1]
            elif index + 1 < len(argv):
                value = argv[index + 1]
        if value and "=" in value:
            _name, item = value.split("=", 1)
            if item:
                secrets.append(item)
        elif value:
            secrets.append(value)
        if notifier_command:
            assignment = RAW_NOTIFIER_SECRET_ASSIGNMENT.search(raw_argument)
            if assignment and assignment.end() < len(raw_argument):
                secrets.append(raw_argument[assignment.end() :])
            secrets.extend(match.group(0) for match in RAW_URL.finditer(raw_argument))
    return tuple(dict.fromkeys(secrets))


def _validate_arguments(args: argparse.Namespace) -> None:
    group, action = args.group, args.action
    if group == "host" and action == "info":
        _ip(args.ip)
    elif group == "search":
        if action in {"hosts", "count", "tokens"}:
            _query(args.query)
        if action == "hosts":
            _positive(args.page, "page")
            _positive(args.limit, "limit")
    elif group == "scan" and action == "status":
        _path_token(args.id, "scan identifier")
    elif group == "scan" and action == "list":
        _positive(args.page, "page")
    elif group == "alert":
        if action in {"info", "edit", "delete", "trigger", "notifier"}:
            _path_token(args.id, "alert identifier")
        if action == "trigger":
            _trigger_path_token(args.trigger, allow_multiple=args.detail in {"enable", "disable"})
            if hasattr(args, "service"):
                _service_path_token(args.service)
        elif action == "notifier":
            _path_token(args.notifier_id, "notifier identifier")
    elif group == "notifier" and action in {"info", "edit", "delete"}:
        _path_token(args.id, "notifier identifier")
    elif group == "dns":
        if action == "domain":
            _domain(args.domain)
            _positive(args.page, "page")
        elif action == "resolve":
            _domains(args.hostnames)
        else:
            _ips(args.ips)
    elif group == "query":
        if action == "list":
            _positive(args.page, "page")
        elif action == "search":
            _query(args.query)
            _positive(args.page, "page")
        else:
            _positive(args.limit, "limit")
    elif group == "data" and action != "list":
        _path_token(args.dataset, "dataset")
    elif group == "exploits":
        _query(args.query)
        if action == "search":
            _positive(args.page, "page")
            _positive(args.limit, "limit")
            _positive(args.truncate_code, "truncate-code")
    elif group == "trends" and action == "search":
        _query(args.query)
    elif group == "stream":
        _positive(args.limit, "limit")
        if args.max_reconnects < 0 or args.max_reconnects > 10:
            raise UsageError("max-reconnects must be between 0 and 10")
        if action == "asn":
            _stream_selector(args.asn, "ASN")
        elif action == "countries":
            _stream_selector(args.countries, "country")
        elif action == "ports":
            _stream_selector(args.ports, "port")
        elif action == "vulns":
            _stream_selector(args.vulns, "CVE")
        elif action == "alert":
            _path_token(args.id, "alert identifier")
        elif action == "custom":
            _query(args.query)


def _preview(args: argparse.Namespace) -> tuple[OperationPreview, bool] | None:
    group, action = args.group, args.action
    operation = _command(args)
    if group == "search" and action == "hosts":
        search_identifiers = [_query(args.query), f"page={args.page}"]
        if args.limit is not None:
            search_identifiers.append(f"client-limit={args.limit}")
        return (
            OperationPreview(
                operation,
                tuple(search_identifiers),
                None,
                "conditional query credits for filtered searches and result pages after the first",
                False,
            ),
            False,
        )
    if group == "dns" and action == "domain":
        return (
            OperationPreview(
                operation,
                (_domain(args.domain),),
                1,
                "one query credit",
                False,
            ),
            False,
        )
    if group == "scan" and action == "submit":
        networks, count = _networks(args.ips)
        services = _services(args.service)
        service_identifiers = tuple(f"service={port}:{protocol}" for port, protocol in services)
        scan_identifiers = (*networks, *service_identifiers, *(("force=true",) if args.force else ()))
        impact = (
            "Enterprise forced re-scan; one scan credit per target when applicable"
            if args.force
            else ("one scan credit per target when applicable")
        )
        return OperationPreview(operation, scan_identifiers, count, impact, False), True
    if group == "scan" and action == "internet":
        if not 1 <= args.port <= 65535:
            raise UsageError("Internet scan port must be 1-65535 and protocol is required.")
        protocol = _protocol(args.protocol)
        return OperationPreview(operation, (f"{args.port}:{protocol}",), None, "Enterprise plan-dependent", False), True
    if group == "alert" and action in {"create", "edit"}:
        if action == "create" and not args.name.strip():
            raise UsageError("Alert name must not be blank.")
        if action == "create" and args.expires < 0:
            raise UsageError("Alert expiration must be zero or greater.")
        networks, count = _networks(args.networks)
        alert_identifiers = (
            (args.name, *networks)
            if action == "create"
            else (
                _path_token(args.id, "alert identifier"),
                *networks,
            )
        )
        return OperationPreview(operation, alert_identifiers, count, "none", action == "create"), True
    if group == "alert" and action == "delete":
        alert_id = _path_token(args.id, "alert identifier")
        return OperationPreview(operation, (alert_id,), None, "none", False), False
    if group == "alert" and action == "trigger":
        alert_id = _path_token(args.id, "alert identifier")
        trigger = _trigger_path_token(args.trigger, allow_multiple=args.detail in {"enable", "disable"})
        service = () if not hasattr(args, "service") else (_service_path_token(args.service),)
        trigger_identifiers = (alert_id, trigger, *service)
        return OperationPreview(operation, trigger_identifiers, None, "none", True), False
    if group == "alert" and action == "notifier":
        alert_id = _path_token(args.id, "alert identifier")
        notifier_id = _path_token(args.notifier_id, "notifier identifier")
        return OperationPreview(operation, (alert_id, notifier_id), None, "none", True), False
    if group == "notifier" and action in {"create", "edit", "delete"}:
        if action in {"create", "edit"}:
            _key_values(args.arg)
        if action == "create":
            if not args.provider.strip():
                raise UsageError("Notifier provider must not be blank.")
            if not args.description.strip():
                raise UsageError("Notifier description must not be blank.")
        identifier = args.provider if action == "create" else _path_token(args.id, "notifier identifier")
        return OperationPreview(operation, (identifier,), None, "none", action == "create"), False
    if group == "data" and action == "download":
        dataset = _path_token(args.dataset, "dataset")
        name = _path_token(args.name, "dataset file")
        _download_chunk_size(args.chunk_size)
        if args.resume and args.overwrite:
            raise UsageError("--resume and --overwrite cannot be used together.")
        destination = args.output_file or Path(f"{dataset}-{name}")
        _validate_download_destination(destination, resume=args.resume, overwrite=args.overwrite)
        return OperationPreview(
            operation,
            (dataset, name, str(destination)),
            1,
            "none",
            not (args.overwrite or args.resume),
        ), False
    if group == "org" and action == "member":
        user = _path_token(args.user, "organization user", allow_at=True)
        notification = getattr(args, "notify", None)
        org_identifiers: tuple[str, ...] = (user,)
        if args.detail == "add":
            notification_mode = "service-default" if notification is None else str(notification).lower()
            org_identifiers = (user, f"email-notification={notification_mode}")
        return OperationPreview(operation, org_identifiers, 1, "none", True), False
    return None


def _local_reference(action: str) -> dict[str, str]:
    if action == "filters":
        return {"source": "https://www.shodan.io/search/filters"}
    return {
        "overview": "https://datapedia.shodan.io/",
        "banner_schema": "https://datapedia.shodan.io/banner.schema.json",
        "changelog": "https://datapedia.shodan.io/changelog.html",
    }


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
    transport_factory: TransportFactory = HttpTransport,
) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    command = "cli"
    settings: Settings | None = None
    credit_impact = "none"
    credits_estimated: int | None = None
    command_secrets = _raw_argument_secrets(raw_args)
    try:
        normalized, legacy = normalize_legacy(raw_args)
        args = parser.parse_args(normalized)
        command = _command(args)
        safety_mode = resolve_safety_mode(environ, override=args.safety_mode)
        credit_impact, credits_estimated = _credit_metadata(args)
        command_secrets = tuple(dict.fromkeys((*command_secrets, *_notifier_secret_values(args))))
        if legacy:
            stderr.write(f"warning: '{legacy}' is deprecated; use '{args.group} {args.action}'\n")
        if args.group == "reference":
            write_payload(
                success_envelope(
                    _local_reference(args.action),
                    command,
                    credit_impact=credit_impact,
                    credits_estimated=credits_estimated,
                ),
                stdout,
                args.output,
            )
            return 0
        _validate_arguments(args)
        preview_result = _preview(args)
        if preview_result:
            preview, authorization_required = preview_result
            credit_impact, credits_estimated = _credit_metadata(args, preview)
            confirmed = bool(getattr(args, "confirm", False) or getattr(args, "yes", False))
            authorized = not authorization_required or bool(getattr(args, "acknowledge_authorization", False))
            if not args.dry_run:
                require_confirmation(
                    preview,
                    mode=safety_mode,
                    confirmed=confirmed,
                    authorized=authorized,
                )
            write_payload(
                success_envelope(
                    {"preview": preview.to_dict()},
                    f"{command}-preview",
                    credit_impact=credit_impact,
                    credits_estimated=credits_estimated,
                ),
                stderr,
                "jsonl",
            )
            if args.dry_run:
                return 0
        elif args.dry_run:
            raise UsageError("--dry-run is only available for operations with a deterministic preview.")
        try:
            settings = Settings.load(
                environ,
                home=home,
                connect_timeout=args.connect_timeout,
                read_timeout=args.read_timeout,
                write_timeout=args.write_timeout,
                pool_timeout=args.pool_timeout,
                stream_timeout=args.stream_timeout,
                retries=args.retries,
                proxy=args.proxy,
            )
        except ValueError as exc:
            raise UsageError(str(exc)) from exc
        settings.require_api_key()
        with transport_factory(settings) as transport:
            output_secrets = (*settings.redaction_secrets(), *command_secrets)
            if args.group == "stream":
                run_stream(args, transport, stdout, stderr, output_secrets, command=command)
            else:
                result = execute(args, transport)
                write_payload(
                    success_envelope(
                        result,
                        command,
                        credit_impact=credit_impact,
                        credits_estimated=credits_estimated,
                        secrets=output_secrets,
                    ),
                    stdout,
                    args.output,
                )
        return 0
    except KeyboardInterrupt:
        error: ShodanSkillError = InterruptedError("Operation interrupted.")
    except ShodanSkillError as exc:
        error = exc
    except Exception as exc:
        error = InternalError("Unexpected internal error.", details={"type": exc.__class__.__name__})
    error_secrets = (
        *(settings.redaction_secrets() if settings else ()),
        *command_secrets,
    )
    write_payload(
        error_envelope(
            error,
            command,
            credit_impact=credit_impact,
            credits_estimated=credits_estimated,
            secrets=error_secrets,
        ),
        stderr,
        "json",
    )
    return int(error.exit_code)


def main() -> int:
    return run()
