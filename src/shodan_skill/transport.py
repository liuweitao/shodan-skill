"""Canonical bounded HTTP transport for every Shodan service."""

from __future__ import annotations

import json
import os
import re
import time
from codecs import getincrementaldecoder
from collections.abc import Callable, Iterator, Mapping
from contextlib import suppress
from datetime import timezone
from email.utils import parsedate_to_datetime
from hashlib import sha1
from math import isfinite
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from shodan_skill import __version__
from shodan_skill.config import Settings
from shodan_skill.errors import (
    ApiError,
    AuthenticationError,
    AuthorizationError,
    CreditsError,
    NetworkError,
    TimeoutError,
)

ApiFamily = Literal["rest", "streaming", "trends", "exploits"]
BASE_URLS: dict[ApiFamily, str] = {
    "rest": "https://api.shodan.io",
    "streaming": "https://stream.shodan.io",
    "trends": "https://trends.shodan.io",
    "exploits": "https://exploits.shodan.io/api",
}
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504, 524}
USER_AGENT = f"shodan-skill/{__version__} (+https://github.com/liuweitao/shodan-skill)"
CONTENT_RANGE = re.compile(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", re.IGNORECASE)
SHA1_PATTERN = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)
MAX_STREAM_FRAME_CHARS = 16 * 1024 * 1024
MAX_DOWNLOAD_CHUNK_SIZE = 16 * 1024 * 1024


class HttpTransport:
    """Send authenticated JSON and streaming requests with finite timeouts."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.Client | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self.api_key = settings.require_api_key()
        self._owned_client = client is None
        self.client = client or httpx.Client(
            headers={"User-Agent": USER_AGENT},
            proxy=settings.proxy,
            trust_env=False,
        )
        self.sleeper = sleeper

    def __enter__(self) -> HttpTransport:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owned_client:
            self.client.close()

    def request(
        self,
        api: ApiFamily,
        method: str,
        path: str,
        *,
        params: Mapping[str, object] | None = None,
        json_body: object | None = None,
        form_body: Mapping[str, object] | None = None,
        retry: bool = True,
    ) -> Any:
        """Send one request, retrying safe transient failures only."""
        method = method.upper()
        attempts = self.settings.retries + 1 if method == "GET" and retry else 1
        for attempt in range(attempts):
            try:
                response = self.client.request(
                    method,
                    BASE_URLS[api] + path,
                    params=self._authenticated_params(params),
                    json=json_body,
                    data=form_body,
                    headers={"User-Agent": USER_AGENT},
                    timeout=self._timeout(stream=False),
                )
            except httpx.TimeoutException as exc:
                if attempt + 1 < attempts:
                    self.sleeper(self._backoff(attempt, None))
                    continue
                raise TimeoutError("Shodan request timed out.") from exc
            except httpx.RequestError as exc:
                if attempt + 1 < attempts:
                    self.sleeper(self._backoff(attempt, None))
                    continue
                raise NetworkError("Unable to connect to Shodan.") from exc
            if response.status_code in RETRYABLE_STATUS and attempt + 1 < attempts:
                self.sleeper(self._backoff(attempt, response.headers.get("Retry-After")))
                continue
            self._raise_for_status(response)
            if response.status_code == 204:
                return None
            try:
                payload = response.json()
            except ValueError as exc:
                raise ApiError("Shodan returned a malformed JSON response.") from exc
            self._validate_json_numbers(payload)
            if isinstance(payload, dict) and "error" in payload and payload["error"] is not None:
                api_error = payload["error"]
                message = api_error if isinstance(api_error, str) and api_error else "Shodan returned an API error."
                raise ApiError(message)
            return payload
        raise NetworkError("Shodan request failed after bounded retries.")

    def iter_bytes(
        self,
        api: ApiFamily,
        path: str,
        *,
        params: Mapping[str, object] | None = None,
    ) -> Iterator[bytes]:
        """Yield raw streaming chunks while keeping the response context open."""
        try:
            with self.client.stream(
                "GET",
                BASE_URLS[api] + path,
                params=self._authenticated_params(params),
                headers={"User-Agent": USER_AGENT},
                timeout=self._timeout(stream=True),
            ) as response:
                if response.status_code in {500, 502, 503}:
                    with suppress(httpx.HTTPError):
                        response.read()
                    raise NetworkError("Shodan stream is temporarily unavailable.")
                self._raise_for_status(response)
                yield from response.iter_bytes()
        except httpx.TimeoutException as exc:
            raise TimeoutError("Shodan stream timed out.") from exc
        except httpx.RequestError as exc:
            raise NetworkError("Shodan stream disconnected.") from exc

    def download_file(
        self,
        url: str,
        destination: Path,
        *,
        expected_size: int | None = None,
        expected_sha1: str | None = None,
        resume: bool = False,
        overwrite: bool = False,
        chunk_size: int = 65536,
    ) -> dict[str, object]:
        """Download a signed HTTPS dataset URL to a resumable partial file."""
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ApiError("Shodan returned an invalid dataset download URL.")
        if expected_size is not None and (
            isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0
        ):
            raise ApiError("Shodan returned invalid dataset size metadata.")
        if expected_sha1 is not None and not SHA1_PATTERN.fullmatch(expected_sha1):
            raise ApiError("Shodan returned invalid dataset checksum metadata.")
        if (
            isinstance(chunk_size, bool)
            or not isinstance(chunk_size, int)
            or chunk_size < 1
            or chunk_size > MAX_DOWNLOAD_CHUNK_SIZE
        ):
            raise ApiError(f"Dataset download chunk size must be between 1 and {MAX_DOWNLOAD_CHUNK_SIZE} bytes.")
        partial = destination.with_name(f"{destination.name}.part")
        try:
            if partial.is_symlink():
                raise ApiError("Refusing to write through a symbolic partial-download path.")
            partial_exists = partial.exists()
            if partial_exists and not (resume or overwrite):
                raise ApiError("Dataset partial download already exists; resume or overwrite must be explicit.")
            offset = partial.stat().st_size if resume and partial_exists else 0
        except OSError as exc:
            raise ApiError("Unable to inspect the dataset partial download.") from exc
        if resume and partial_exists and expected_size is not None:
            if offset > expected_size:
                raise ApiError(
                    "Dataset download size mismatch.",
                    details={"expected": expected_size, "actual": offset},
                )
            if offset == expected_size:
                return self._finalize_download(
                    partial,
                    destination,
                    expected_size=expected_size,
                    expected_sha1=expected_sha1,
                    overwrite=overwrite,
                )
        headers = {"User-Agent": USER_AGENT}
        if offset:
            headers["Range"] = f"bytes={offset}-"
        try:
            with self.client.stream("GET", url, headers=headers, timeout=self._timeout(stream=True)) as response:
                self._raise_for_status(response)
                if response.status_code == 206:
                    self._validate_content_range(
                        response.headers.get("Content-Range"),
                        expected_start=offset,
                        expected_size=expected_size,
                    )
                append = offset > 0 and response.status_code == 206
                mode = "ab" if append else "wb"
                if not append:
                    offset = 0
                partial.parent.mkdir(parents=True, exist_ok=True)
                with partial.open(mode) as output:
                    written = offset
                    for chunk in response.iter_bytes(chunk_size=chunk_size):
                        if chunk:
                            if expected_size is not None and written + len(chunk) > expected_size:
                                raise ApiError("Dataset download exceeded the expected size.")
                            output.write(chunk)
                            written += len(chunk)
        except httpx.TimeoutException as exc:
            raise TimeoutError("Shodan dataset download timed out.") from exc
        except httpx.RequestError as exc:
            raise NetworkError("Shodan dataset download disconnected.") from exc
        except OSError as exc:
            raise ApiError("Unable to write the dataset download.") from exc
        return self._finalize_download(
            partial,
            destination,
            expected_size=expected_size,
            expected_sha1=expected_sha1,
            overwrite=overwrite,
        )

    def iter_jsonl(
        self,
        api: ApiFamily,
        path: str,
        *,
        params: Mapping[str, object] | None = None,
    ) -> Iterator[Any]:
        """Parse newline-delimited JSON across arbitrarily fragmented chunks."""
        buffer = ""
        decoder = getincrementaldecoder("utf-8")()
        for chunk in self.iter_bytes(api, path, params=params):
            try:
                buffer += decoder.decode(chunk)
            except UnicodeDecodeError as exc:
                raise ApiError("Shodan stream returned invalid UTF-8.") from exc
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if line.strip():
                    self._validate_stream_frame_size(line)
                    yield self._decode_stream_item(line)
            self._validate_stream_frame_size(buffer)
        try:
            buffer += decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise ApiError("Shodan stream returned invalid UTF-8.") from exc
        if buffer.strip():
            self._validate_stream_frame_size(buffer)
            yield self._decode_stream_item(buffer)

    def iter_sse(
        self,
        api: ApiFamily,
        path: str,
        *,
        params: Mapping[str, object] | None = None,
    ) -> Iterator[Any]:
        """Parse SSE data fields across fragmented chunks."""
        buffer = ""
        decoder = getincrementaldecoder("utf-8")()
        for chunk in self.iter_bytes(api, path, params=params):
            try:
                buffer += decoder.decode(chunk)
            except UnicodeDecodeError as exc:
                raise ApiError("Shodan stream returned invalid UTF-8.") from exc
            trailing_carriage_return = buffer.endswith("\r")
            normalizable = buffer[:-1] if trailing_carriage_return else buffer
            buffer = normalizable.replace("\r\n", "\n").replace("\r", "\n")
            if trailing_carriage_return:
                buffer += "\r"
            while "\n\n" in buffer:
                event, buffer = buffer.split("\n\n", 1)
                self._validate_stream_frame_size(event)
                item = self._decode_sse_event(event)
                if item is not None:
                    yield item
            self._validate_stream_frame_size(buffer)
        try:
            buffer += decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise ApiError("Shodan stream returned invalid UTF-8.") from exc
        buffer = buffer.replace("\r\n", "\n").replace("\r", "\n")
        if buffer.strip():
            self._validate_stream_frame_size(buffer)
            item = self._decode_sse_event(buffer)
            if item is not None:
                yield item

    def _authenticated_params(self, params: Mapping[str, object] | None) -> dict[str, str]:
        values = {
            key: str(value).lower() if isinstance(value, bool) else str(value)
            for key, value in (params or {}).items()
            if value is not None
        }
        values["key"] = self.api_key
        return values

    def _timeout(self, *, stream: bool) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.settings.connect_timeout,
            read=self.settings.stream_timeout if stream else self.settings.read_timeout,
            write=self.settings.write_timeout,
            pool=self.settings.pool_timeout,
        )

    @staticmethod
    def _decode_stream_item(value: str) -> Any:
        try:
            item = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ApiError("Shodan stream returned malformed JSON.", details={"fragment": value[:80]}) from exc
        HttpTransport._validate_json_numbers(item)
        return item

    @staticmethod
    def _validate_json_numbers(value: Any) -> None:
        if isinstance(value, float) and not isfinite(value):
            raise ApiError("Shodan returned a non-finite JSON number.")
        if isinstance(value, Mapping):
            for item in value.values():
                HttpTransport._validate_json_numbers(item)
        elif isinstance(value, list):
            for item in value:
                HttpTransport._validate_json_numbers(item)

    @staticmethod
    def _validate_stream_frame_size(value: str) -> None:
        if len(value) > MAX_STREAM_FRAME_CHARS:
            raise ApiError("Shodan stream exceeded the maximum frame size.")

    @classmethod
    def _decode_sse_event(cls, event: str) -> Any | None:
        data = "\n".join(line[5:].lstrip() for line in event.splitlines() if line.startswith("data:"))
        return cls._decode_stream_item(data) if data else None

    @staticmethod
    def _backoff(attempt: int, retry_after: str | None, *, now: float | None = None) -> float:
        if retry_after:
            try:
                delay = float(retry_after)
                if isfinite(delay):
                    return float(min(max(delay, 0.0), 30.0))
            except ValueError:
                try:
                    retry_at = parsedate_to_datetime(retry_after)
                    if retry_at.tzinfo is None:
                        retry_at = retry_at.replace(tzinfo=timezone.utc)
                    delay = retry_at.timestamp() - (time.time() if now is None else now)
                    if isfinite(delay):
                        return float(min(max(delay, 0.0), 30.0))
                except (OSError, OverflowError, TypeError, ValueError):
                    pass
        return float(min(0.25 * (2**attempt), 4.0))

    @staticmethod
    def _validate_content_range(value: str | None, *, expected_start: int, expected_size: int | None) -> None:
        match = CONTENT_RANGE.fullmatch(value.strip()) if value else None
        if match is None:
            raise ApiError("Dataset download range response is invalid.")
        start, end = int(match.group(1)), int(match.group(2))
        total_text = match.group(3)
        if start != expected_start or end < start:
            raise ApiError("Dataset download range response is invalid.")
        if total_text != "*":
            total = int(total_text)
            if end >= total or (expected_size is not None and total != expected_size):
                raise ApiError("Dataset download range response does not match metadata.")

    @staticmethod
    def _sha1_file(path: Path) -> str:
        digest = sha1(usedforsecurity=False)
        try:
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise ApiError("Unable to verify the dataset download.") from exc
        return digest.hexdigest()

    def _finalize_download(
        self,
        partial: Path,
        destination: Path,
        *,
        expected_size: int | None,
        expected_sha1: str | None,
        overwrite: bool,
    ) -> dict[str, object]:
        try:
            size = partial.stat().st_size
        except OSError as exc:
            raise ApiError("Unable to inspect the completed dataset download.") from exc
        if expected_size is not None and size != expected_size:
            raise ApiError("Dataset download size mismatch.", details={"expected": expected_size, "actual": size})
        digest = self._sha1_file(partial) if expected_sha1 is not None else None
        if expected_sha1 is not None and digest is not None and digest.lower() != expected_sha1.lower():
            raise ApiError("Dataset download checksum mismatch.")
        if overwrite:
            try:
                partial.replace(destination)
            except OSError as exc:
                raise ApiError("Unable to finalize the dataset download.") from exc
        else:
            try:
                os.link(partial, destination, follow_symlinks=False)
            except FileExistsError as exc:
                raise ApiError("Dataset output file already exists; it was not overwritten.") from exc
            except OSError as exc:
                raise ApiError("Unable to finalize the dataset download without overwriting a file.") from exc
            try:
                partial.unlink()
            except OSError as exc:
                raise ApiError(
                    "Dataset download was finalized, but its partial hard link could not be removed.",
                    details={"path": str(destination), "partial": str(partial)},
                ) from exc
        return {"path": str(destination), "bytes": size, "sha1": digest}

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if 200 <= response.status_code < 300:
            return
        message = "Shodan API request failed."
        with suppress(httpx.HTTPError):
            response.read()
        try:
            body = response.json()
            if isinstance(body, dict) and isinstance(body.get("error"), str):
                message = body["error"]
        except (ValueError, httpx.HTTPError):
            pass
        if response.status_code == 401:
            raise AuthenticationError(message)
        if response.status_code == 403:
            raise AuthorizationError(message)
        if response.status_code == 402 or (response.status_code == 429 and "credit" in message.lower()):
            raise CreditsError(message)
        if response.status_code in {408, 504, 524}:
            raise TimeoutError(message)
        raise ApiError(message, details={"status": response.status_code})
