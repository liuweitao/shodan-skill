"""Stable output envelopes and renderers."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, TextIO

from shodan_skill.errors import ShodanSkillError
from shodan_skill.redaction import redact


@dataclass(frozen=True)
class Meta:
    command: str
    credits_used: int | None = None
    credit_impact: str = "none"
    credits_estimated: int | None = None


def success_envelope(
    data: Any,
    command: str,
    *,
    credit_impact: str = "none",
    credits_estimated: int | None = None,
    secrets: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "ok": True,
        "data": redact(data, secrets=secrets),
        "meta": asdict(
            Meta(
                command=command,
                credit_impact=credit_impact,
                credits_estimated=credits_estimated,
            )
        ),
        "error": None,
    }


def error_envelope(
    error: ShodanSkillError,
    command: str,
    *,
    credit_impact: str = "none",
    credits_estimated: int | None = None,
    secrets: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "ok": False,
        "data": None,
        "meta": asdict(
            Meta(
                command=command,
                credit_impact=credit_impact,
                credits_estimated=credits_estimated,
            )
        ),
        "error": redact(
            {"code": error.code, "message": error.message, "details": error.details},
            secrets=secrets,
        ),
    }


def write_json(payload: Any, stream: TextIO, *, compact: bool = False) -> None:
    kwargs: dict[str, Any] = {"ensure_ascii": False, "sort_keys": True, "allow_nan": False}
    if compact:
        kwargs["separators"] = (",", ":")
    else:
        kwargs["indent"] = 2
    stream.write(json.dumps(payload, **kwargs))
    stream.write("\n")


def write_human(payload: dict[str, Any], stream: TextIO) -> None:
    if payload["ok"]:
        data = payload["data"]
        stream.write(data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False))
    else:
        stream.write(f"{payload['error']['code']}: {payload['error']['message']}")
    stream.write("\n")


def write_sse(payload: Any, stream: TextIO) -> None:
    """Write one Server-Sent Events data frame containing compact JSON."""
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    for line in encoded.splitlines() or [""]:
        stream.write(f"data: {line}\n")
    stream.write("\n")


def write_payload(payload: dict[str, Any], stream: TextIO, output: str) -> None:
    if output == "human":
        write_human(payload, stream)
    elif output == "sse":
        write_sse(payload, stream)
    else:
        write_json(payload, stream, compact=output == "jsonl")
