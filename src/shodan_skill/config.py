"""Lazy, side-effect-free runtime configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from urllib.parse import unquote, urlsplit

from shodan_skill.errors import AuthenticationError


@dataclass(frozen=True)
class Settings:
    api_key: str | None
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    write_timeout: float = 30.0
    pool_timeout: float = 10.0
    stream_timeout: float = 60.0
    retries: int = 2
    proxy: str | None = None

    @classmethod
    def load(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        home: Path | None = None,
        connect_timeout: float | None = None,
        read_timeout: float | None = None,
        write_timeout: float | None = None,
        pool_timeout: float | None = None,
        stream_timeout: float | None = None,
        retries: int | None = None,
        proxy: str | None = None,
    ) -> Settings:
        values = os.environ if env is None else env
        key = _normalize_api_key(values.get("SHODAN_API_KEY", ""))
        root = Path.home() if home is None else home
        config_files = (
            root / ".shodan" / "api_key",
            root / ".config" / "shodan" / "api_key",
        )
        for config_file in config_files:
            if key is not None or not config_file.is_file():
                continue
            try:
                if config_file.stat().st_size > 4096:
                    raise AuthenticationError("Shodan CLI configuration is unexpectedly large.")
                key = _normalize_api_key(config_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeError) as exc:
                raise AuthenticationError("Unable to read Shodan CLI configuration.") from exc
        return cls(
            api_key=key,
            connect_timeout=_override_positive(
                connect_timeout,
                "--connect-timeout",
                _positive_float(values, "SHODAN_CONNECT_TIMEOUT", 10.0),
            ),
            read_timeout=_override_positive(
                read_timeout,
                "--read-timeout",
                _positive_float(values, "SHODAN_READ_TIMEOUT", 30.0),
            ),
            write_timeout=_override_positive(
                write_timeout,
                "--write-timeout",
                _positive_float(values, "SHODAN_WRITE_TIMEOUT", 30.0),
            ),
            pool_timeout=_override_positive(
                pool_timeout,
                "--pool-timeout",
                _positive_float(values, "SHODAN_POOL_TIMEOUT", 10.0),
            ),
            stream_timeout=_override_positive(
                stream_timeout,
                "--stream-timeout",
                _positive_float(values, "SHODAN_STREAM_TIMEOUT", 60.0),
            ),
            retries=_override_bounded_int(
                retries,
                "--retries",
                _bounded_int(values, "SHODAN_RETRIES", 2, minimum=0, maximum=5),
                minimum=0,
                maximum=5,
            ),
            proxy=_normalize_proxy(proxy if proxy is not None else values.get("SHODAN_PROXY", "")),
        )

    def require_api_key(self) -> str:
        if not self.api_key:
            raise AuthenticationError("Shodan API key not found. Set SHODAN_API_KEY or run 'shodan init <key>'.")
        return self.api_key

    def redaction_secrets(self) -> tuple[str, ...]:
        """Return configured credentials without treating a credential-free proxy host as secret."""
        values = [self.api_key] if self.api_key else []
        if self.proxy:
            parsed = urlsplit(self.proxy)
            credentials = tuple(value for value in (parsed.username, parsed.password) if value)
            if credentials:
                values.append(self.proxy)
                for credential in credentials:
                    values.extend((credential, unquote(credential)))
        return tuple(dict.fromkeys(value for value in values if value))


def _positive_float(values: Mapping[str, str], name: str, default: float) -> float:
    raw = values.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not isfinite(value):
        raise ValueError(f"{name} must be finite")
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def _override_positive(value: float | None, name: str, default: float) -> float:
    if value is None:
        return default
    if not isfinite(value):
        raise ValueError(f"{name} must be finite")
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def _normalize_api_key(value: str) -> str | None:
    key = value.strip()
    if not key:
        return None
    if len(key) > 256 or not key.isascii() or not key.isprintable() or any(character.isspace() for character in key):
        raise AuthenticationError("Shodan API key configuration is malformed.")
    return key


def _normalize_proxy(value: str) -> str | None:
    proxy = value.strip()
    if not proxy:
        return None
    if len(proxy) > 2048 or not proxy.isprintable() or any(character.isspace() for character in proxy):
        raise ValueError("SHODAN_PROXY must be a printable URL without whitespace")
    parsed = urlsplit(proxy)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("SHODAN_PROXY has an invalid port") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port == 0
    ):
        raise ValueError("SHODAN_PROXY must be an http(s) proxy URL without a path, query, or fragment")
    return proxy


def _bounded_int(values: Mapping[str, str], name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = values.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _override_bounded_int(
    value: int | None,
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if value is None:
        return default
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value
