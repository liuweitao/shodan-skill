"""Streaming command execution and bounded reconnect behavior."""

from __future__ import annotations

import argparse
from typing import TextIO

from shodan_skill.commands.validation import path_token, positive, query, stream_selector
from shodan_skill.errors import NetworkError, TimeoutError, UsageError
from shodan_skill.output import success_envelope, write_payload
from shodan_skill.transport import HttpTransport


def run_stream(
    args: argparse.Namespace,
    transport: HttpTransport,
    stdout: TextIO,
    stderr: TextIO,
    secrets: tuple[str, ...],
    *,
    command: str,
) -> None:
    """Consume one selected stream and emit bounded structured output."""
    paths = {
        "banners": "/shodan/banners",
        "alerts": "/shodan/alert",
        "alert": (
            f"/shodan/alert/{path_token(args.id, 'alert identifier')}" if args.action == "alert" else "/shodan/alert/"
        ),
        "custom": "/shodan/custom",
    }
    if args.action == "asn":
        paths["asn"] = f"/shodan/asn/{stream_selector(args.asn, 'ASN')}"
    elif args.action == "countries":
        paths["countries"] = f"/shodan/countries/{stream_selector(args.countries, 'country')}"
    elif args.action == "ports":
        paths["ports"] = f"/shodan/ports/{stream_selector(args.ports, 'port')}"
    elif args.action == "vulns":
        paths["vulns"] = f"/shodan/vulns/{stream_selector(args.vulns, 'CVE')}"
    path = paths[args.action]
    positive(args.limit, "limit")
    if args.max_reconnects < 0 or args.max_reconnects > 10:
        raise UsageError("max-reconnects must be between 0 and 10")
    params = {
        "t": "sse" if args.stream_format == "sse" else "json",
        "heartbeat": False,
    }
    if args.debug:
        params["debug"] = "1"
    if args.action == "custom":
        params["query"] = query(args.query)
    emitted = 0
    reconnects = 0
    stream_output = "sse" if args.stream_format == "sse" else "jsonl"
    while True:
        try:
            iterator = (
                transport.iter_sse("streaming", path, params=params)
                if args.stream_format == "sse"
                else transport.iter_jsonl("streaming", path, params=params)
            )
            for item in iterator:
                if isinstance(item, dict) and item.get("event") == "debug":
                    write_payload(
                        success_envelope(item, f"{command}-diagnostic", secrets=secrets),
                        stderr,
                        "jsonl",
                    )
                    continue
                write_payload(success_envelope(item, command, secrets=secrets), stdout, stream_output)
                emitted += 1
                if emitted >= args.limit:
                    return
        except (NetworkError, TimeoutError) as exc:
            if not args.reconnect or reconnects >= args.max_reconnects:
                raise
            diagnostic = {"event": "reconnect", "attempt": reconnects + 1, "reason": exc.code}
            write_payload(
                success_envelope(diagnostic, f"{command}-diagnostic", secrets=secrets),
                stderr,
                "jsonl",
            )
        else:
            if not args.reconnect or reconnects >= args.max_reconnects:
                raise NetworkError("Shodan stream ended before the requested record limit.")
            diagnostic = {"event": "reconnect", "attempt": reconnects + 1, "reason": "eof"}
            write_payload(
                success_envelope(diagnostic, f"{command}-diagnostic", secrets=secrets),
                stderr,
                "jsonl",
            )
        reconnects += 1
        transport.sleeper(min(0.25 * (2 ** (reconnects - 1)), 4.0))
