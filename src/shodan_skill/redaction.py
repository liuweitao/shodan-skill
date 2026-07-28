"""Credential-safe recursive value redaction."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from contextlib import suppress
from typing import Any
from urllib.parse import quote, quote_plus

REDACTED = "[REDACTED]"
SENSITIVE_NAME = re.compile(
    (
        r"(?:api[_-]?key|authorization|bearer|credential|password|passwd|secret|token|cookie|signature"
        r"|access[_-]?key(?:[_-]?id)?|private[_-]?key|signed[_-]?url|routing[_-]?key|webhook[_-]?url)"
    ),
    re.IGNORECASE,
)
SENSITIVE_NAME_SOURCE = (
    r"api[_-]?key|authorization|bearer|credential|password|passwd|secret|token|cookie|signature"
    r"|access[_-]?key(?:[_-]?id)?|private[_-]?key|signed[_-]?url|routing[_-]?key|webhook[_-]?url"
)
NOTIFIER_SECRET_NAME = re.compile(r"^(?:url|routing[_-]?key|webhook[_-]?url)$", re.IGNORECASE)
BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
SHODAN_API_KEY_VALUE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])")
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----.*?-----END (?P=label)-----",
    re.DOTALL,
)
SIGNED_QUERY = re.compile(
    r"(?i)([?&](?:[^=&]*(?:api[_-]?key|token|signature|credential)[^=&]*"
    r"|sig|awsaccesskeyid|googleaccessid|access[_-]?key[_-]?id)=)[^&\s]+"
)
URL_USERINFO = re.compile(r"(?i)(https?://)[^/@\s]+@")
SENSITIVE_HEADER = re.compile(
    r"(?im)(?P<prefix>\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+"
)
QUOTED_CREDENTIAL_ASSIGNMENT = re.compile(
    rf"(?P<prefix>['\"]?(?:{SENSITIVE_NAME_SOURCE})['\"]?\s*[:=]\s*)"
    rf"(?P<quote>['\"])(?P<value>.*?)(?P=quote)",
    re.IGNORECASE,
)
UNQUOTED_CREDENTIAL_ASSIGNMENT = re.compile(
    rf"(?P<prefix>\b(?:{SENSITIVE_NAME_SOURCE})\b\s*[:=]\s*)(?P<value>[^\s,;&}}\]]+)",
    re.IGNORECASE,
)


def _secret_variants(secret: str) -> set[str]:
    variants = {secret}
    with suppress(UnicodeError):
        variants.update({quote(secret, safe=""), quote_plus(secret, safe="")})
    return variants


def redact(
    value: Any,
    *,
    secrets: Sequence[str] = (),
    key_name: str | None = None,
    _notifier_args: bool = False,
) -> Any:
    """Return a recursively redacted copy suitable for all output surfaces."""
    if key_name and (SENSITIVE_NAME.search(key_name) or (_notifier_args and NOTIFIER_SECRET_NAME.fullmatch(key_name))):
        return REDACTED
    if isinstance(value, Mapping):
        has_notifier_args = isinstance(value.get("provider"), str) and isinstance(value.get("args"), Mapping)
        has_dataset_download_url = (
            isinstance(value.get("name"), str)
            and isinstance(value.get("url"), str)
            and ("size" in value or "sha1" in value)
        )
        mapping_result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            safe_key = str(redact(key_text, secrets=secrets, _notifier_args=_notifier_args))
            mapping_result[safe_key] = (
                REDACTED
                if has_dataset_download_url and key_text.casefold() == "url"
                else redact(
                    item,
                    secrets=secrets,
                    key_name=key_text,
                    _notifier_args=_notifier_args or (has_notifier_args and key_text == "args"),
                )
            )
        return mapping_result
    if isinstance(value, tuple):
        return tuple(redact(item, secrets=secrets, _notifier_args=_notifier_args) for item in value)
    if isinstance(value, list):
        return [redact(item, secrets=secrets, _notifier_args=_notifier_args) for item in value]
    if isinstance(value, str):
        result = PRIVATE_KEY_BLOCK.sub(REDACTED, value)
        for secret in secrets:
            if secret:
                for encoded in sorted(_secret_variants(secret), key=len, reverse=True):
                    result = result.replace(encoded, REDACTED)
        result = SENSITIVE_HEADER.sub(rf"\g<prefix>{REDACTED}", result)
        result = BEARER_VALUE.sub(f"Bearer {REDACTED}", result)
        result = SHODAN_API_KEY_VALUE.sub(REDACTED, result)
        result = SIGNED_QUERY.sub(rf"\1{REDACTED}", result)
        result = URL_USERINFO.sub(rf"\1{REDACTED}@", result)
        result = QUOTED_CREDENTIAL_ASSIGNMENT.sub(
            rf"\g<prefix>\g<quote>{REDACTED}\g<quote>",
            result,
        )
        return UNQUOTED_CREDENTIAL_ASSIGNMENT.sub(rf"\g<prefix>{REDACTED}", result)
    return value
