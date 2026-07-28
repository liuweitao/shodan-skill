from __future__ import annotations

import io
import json
from urllib.parse import quote, quote_plus

import pytest

from shodan_skill.errors import ApiError, ExitCode, UsageError
from shodan_skill.output import error_envelope, success_envelope, write_payload
from shodan_skill.redaction import REDACTED, redact
from shodan_skill.safety import OperationPreview, require_confirmation, resolve_safety_mode


def test_recursive_redaction_covers_names_values_bearers_and_signed_urls() -> None:
    secret = "sensitive-value"
    # Synthetic 32-character fixture shaped like a Shodan API key; it is not a real credential.
    shodan_key = "abcdef0123456789" * 2
    value = {
        "api_key": secret,
        "nested": [
            {"authorization": "Bearer abc.def"},
            f"failure for {secret}",
            "https://example.invalid/file?signature=abcdef&safe=1",
            "https://example.invalid/file?X-Amz-Credential=account&X-Amz-Signature=secret",
            "https://storage.example.invalid/file?sv=1&sig=azure-secret",
            "https://storage.example.invalid/file?AWSAccessKeyId=access-id&Signature=aws-secret",
            "https://user:password@example.invalid/file",
            f"Shodan key {shodan_key} appeared",
        ],
        "tuple": ("ok", secret),
        f"dynamic-{secret}": "safe",
    }
    result = redact(value, secrets=(secret,))
    assert result["api_key"] == REDACTED
    assert result["nested"][0]["authorization"] == REDACTED
    assert result["nested"][1] == f"failure for {REDACTED}"
    assert "signature=[REDACTED]" in result["nested"][2]
    assert "X-Amz-Credential=[REDACTED]" in result["nested"][3]
    assert "X-Amz-Signature=[REDACTED]" in result["nested"][3]
    assert "azure-secret" not in result["nested"][4]
    assert "access-id" not in result["nested"][5]
    assert "aws-secret" not in result["nested"][5]
    assert "user:password" not in result["nested"][6]
    assert shodan_key not in result["nested"][7]
    assert result["tuple"] == ("ok", REDACTED)
    assert f"dynamic-{REDACTED}" in result
    assert all(secret not in key for key in result)


def test_explicit_secrets_are_redacted_in_percent_encoded_diagnostics() -> None:
    secret = "https://hooks.example.invalid/a path?opaque=value"
    diagnostic = f"raw={secret} encoded={quote(secret, safe='')} form={quote_plus(secret, safe='')}"

    result = redact(diagnostic, secrets=(secret,))

    assert secret not in result
    assert quote(secret, safe="") not in result
    assert quote_plus(secret, safe="") not in result


def test_notifier_credentials_are_redacted_recursively() -> None:
    value = {
        "id": "notifier-id",
        "provider": "webhook",
        "args": {
            "routing_key": "pagerduty-secret",
            "webhook_url": "https://hooks.slack.com/services/T/B/SECRET",
            "url": "https://example.invalid/hooks/SECRET",
            "room_id": "safe-room",
        },
    }
    result = redact(value)
    assert result["args"] == {
        "routing_key": REDACTED,
        "webhook_url": REDACTED,
        "url": REDACTED,
        "room_id": "safe-room",
    }
    assert REDACTED in redact("routing_key=pagerduty-secret")
    assert "pagerduty-secret" not in redact("routing_key=pagerduty-secret")


def test_dataset_metadata_redacts_the_entire_signed_download_url() -> None:
    value = {
        "name": "daily.json.gz",
        "size": 123,
        "sha1": "0" * 40,
        "url": "https://downloads.example.invalid/private/path-token",
    }

    assert redact(value)["url"] == REDACTED


def test_additional_credential_fields_and_private_key_blocks_are_redacted() -> None:
    private_key = "-----BEGIN PRIVATE KEY-----\nsynthetic-private-material\n-----END PRIVATE KEY-----"
    value = {
        "access_key_id": "synthetic-access-identifier",
        "private_key": private_key,
        "signed_url": "https://downloads.example.invalid/opaque-signed-path",
        "diagnostic": f"failed with {private_key}",
    }

    result = redact(value)

    assert result["access_key_id"] == REDACTED
    assert result["private_key"] == REDACTED
    assert result["signed_url"] == REDACTED
    assert "synthetic-private-material" not in result["diagnostic"]
    assert REDACTED in result["diagnostic"]


@pytest.mark.parametrize(
    "value",
    [
        "password=hunter2",
        "password: hunter2",
        'server rejected {"api_key": "abcdef"}',
        "server rejected {'secret'='abcdef'}",
        "Authorization: Basic dXNlcjpwYXNz",
        "Cookie: session=abcdef; safe=1",
    ],
)
def test_redaction_covers_embedded_credential_assignments(value: str) -> None:
    result = redact(value)
    assert "hunter2" not in result
    assert "abcdef" not in result
    assert "dXNlcjpwYXNz" not in result
    assert REDACTED in result


def test_error_envelope_redacts_malformed_stream_fragments() -> None:
    payload = error_envelope(ApiError("bad", details={"fragment": "password=hunter2"}), "stream")
    serialized = json.dumps(payload)
    assert "hunter2" not in serialized
    assert REDACTED in serialized


def test_stable_success_and_error_envelopes() -> None:
    success = success_envelope(
        {"token": "hidden", "value": 1},
        "host-info",
        credit_impact="conditional",
        credits_estimated=2,
    )
    assert success == {
        "ok": True,
        "data": {"token": REDACTED, "value": 1},
        "meta": {
            "command": "host-info",
            "credits_used": None,
            "credit_impact": "conditional",
            "credits_estimated": 2,
        },
        "error": None,
    }
    error = error_envelope(ApiError("bad", details={"cookie": "hidden"}), "host-info")
    assert error["ok"] is False
    assert error["meta"] == {
        "command": "host-info",
        "credits_used": None,
        "credit_impact": "none",
        "credits_estimated": None,
    }
    assert error["error"] == {"code": "api", "message": "bad", "details": {"cookie": REDACTED}}
    assert ApiError.exit_code == ExitCode.API


def test_output_renderers() -> None:
    payload = success_envelope({"value": 1}, "test")
    json_stream = io.StringIO()
    write_payload(payload, json_stream, "json")
    assert json.loads(json_stream.getvalue()) == payload
    jsonl_stream = io.StringIO()
    write_payload(payload, jsonl_stream, "jsonl")
    assert "\n" not in jsonl_stream.getvalue().rstrip("\n")
    sse_stream = io.StringIO()
    write_payload(payload, sse_stream, "sse")
    assert sse_stream.getvalue().startswith("data: {")
    assert sse_stream.getvalue().endswith("\n\n")
    assert json.loads(sse_stream.getvalue()[6:].strip()) == payload
    human_stream = io.StringIO()
    write_payload(payload, human_stream, "human")
    assert '"value": 1' in human_stream.getvalue()
    error_stream = io.StringIO()
    write_payload(error_envelope(ApiError("bad"), "test"), error_stream, "human")
    assert error_stream.getvalue() == "api: bad\n"


def test_renderers_refuse_non_standard_nonfinite_json() -> None:
    with pytest.raises(ValueError):
        write_payload(success_envelope({"value": float("nan")}, "test"), io.StringIO(), "json")


def test_confirmation_gate_exposes_deterministic_preview() -> None:
    preview = OperationPreview("scan-submit", ("192.0.2.0/24",), 256, "one scan credit per IP", False)
    with pytest.raises(UsageError) as missing:
        require_confirmation(preview, mode="strict", confirmed=False)
    assert missing.value.details == preview.to_dict()
    with pytest.raises(UsageError, match="Authorization acknowledgement"):
        require_confirmation(preview, mode="strict", confirmed=True, authorized=False)
    require_confirmation(preview, mode="strict", confirmed=True, authorized=True)
    require_confirmation(preview, mode="direct", confirmed=False, authorized=False)


def test_safety_mode_defaults_to_direct_and_can_be_made_strict() -> None:
    assert resolve_safety_mode({}) == "direct"
    assert resolve_safety_mode({"SHODAN_SAFETY_MODE": "strict"}) == "strict"
    assert resolve_safety_mode({"SHODAN_SAFETY_MODE": "strict"}, override="direct") == "direct"
    with pytest.raises(UsageError, match="SHODAN_SAFETY_MODE"):
        resolve_safety_mode({"SHODAN_SAFETY_MODE": "disabled"})
