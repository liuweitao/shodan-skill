"""Deterministic previews and configurable confirmation gates."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Literal

from shodan_skill.errors import UsageError

SafetyMode = Literal["direct", "strict"]


@dataclass(frozen=True)
class OperationPreview:
    operation: str
    identifiers: tuple[str, ...]
    target_count: int | None
    credit_impact: str
    reversible: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def resolve_safety_mode(
    environ: Mapping[str, str] | None = None,
    *,
    override: str | None = None,
) -> SafetyMode:
    """Resolve the CLI safety mode, defaulting to direct execution."""
    values = os.environ if environ is None else environ
    raw = override if override is not None else values.get("SHODAN_SAFETY_MODE", "")
    mode = raw.strip().lower() or "direct"
    if mode not in {"direct", "strict"}:
        raise UsageError("SHODAN_SAFETY_MODE must be 'direct' or 'strict'.")
    return "strict" if mode == "strict" else "direct"


def require_confirmation(
    preview: OperationPreview,
    *,
    mode: SafetyMode,
    confirmed: bool,
    authorized: bool = True,
) -> None:
    if mode == "direct":
        return
    if not authorized:
        raise UsageError("Authorization acknowledgement is required for this operation.", details=preview.to_dict())
    if not confirmed:
        raise UsageError("Confirmation is required for this operation.", details=preview.to_dict())
