from __future__ import annotations

from pathlib import Path

import pytest

from shodan_skill.config import Settings
from shodan_skill.errors import AuthenticationError


def test_settings_load_environment_and_timeouts(tmp_path: Path) -> None:
    settings = Settings.load(
        {
            "SHODAN_API_KEY": "env-key",
            "SHODAN_CONNECT_TIMEOUT": "2.5",
            "SHODAN_READ_TIMEOUT": "3",
            "SHODAN_WRITE_TIMEOUT": "4",
            "SHODAN_POOL_TIMEOUT": "5",
            "SHODAN_STREAM_TIMEOUT": "6",
            "SHODAN_RETRIES": "4",
            "SHODAN_PROXY": "https://user:password@proxy.example:8443",
        },
        home=tmp_path,
    )
    assert settings.require_api_key() == "env-key"
    assert settings.connect_timeout == 2.5
    assert settings.read_timeout == 3
    assert settings.write_timeout == 4
    assert settings.pool_timeout == 5
    assert settings.stream_timeout == 6
    assert settings.retries == 4
    assert settings.proxy == "https://user:password@proxy.example:8443"
    assert settings.redaction_secrets() == (
        "env-key",
        "https://user:password@proxy.example:8443",
        "user",
        "password",
    )


def test_explicit_runtime_options_override_environment(tmp_path: Path) -> None:
    settings = Settings.load(
        {
            "SHODAN_CONNECT_TIMEOUT": "20",
            "SHODAN_RETRIES": "1",
            "SHODAN_PROXY": "http://environment-proxy.example",
        },
        home=tmp_path,
        connect_timeout=2.5,
        retries=4,
        proxy="https://explicit-proxy.example:8443",
    )

    assert settings.connect_timeout == 2.5
    assert settings.retries == 4
    assert settings.proxy == "https://explicit-proxy.example:8443"
    assert settings.redaction_secrets() == ()


def test_percent_encoded_proxy_credentials_are_available_for_redaction() -> None:
    settings = Settings(api_key=None, proxy="https://agent:p%40ss@proxy.example")

    assert settings.redaction_secrets() == (
        "https://agent:p%40ss@proxy.example",
        "agent",
        "p%40ss",
        "p@ss",
    )


def test_settings_fall_back_to_official_cli_config(tmp_path: Path) -> None:
    config = tmp_path / ".config" / "shodan" / "api_key"
    config.parent.mkdir(parents=True)
    config.write_text("config-key\n", encoding="utf-8")
    assert Settings.load({}, home=tmp_path).require_api_key() == "config-key"


def test_settings_support_legacy_official_cli_config(tmp_path: Path) -> None:
    legacy = tmp_path / ".shodan" / "api_key"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy-key\n", encoding="utf-8")
    assert Settings.load({}, home=tmp_path).require_api_key() == "legacy-key"


def test_legacy_official_cli_config_precedes_xdg_config(tmp_path: Path) -> None:
    legacy = tmp_path / ".shodan" / "api_key"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy-key", encoding="utf-8")
    xdg = tmp_path / ".config" / "shodan" / "api_key"
    xdg.parent.mkdir(parents=True)
    xdg.write_text("xdg-key", encoding="utf-8")
    assert Settings.load({}, home=tmp_path).api_key == "legacy-key"


def test_environment_precedes_config(tmp_path: Path) -> None:
    config = tmp_path / ".config" / "shodan" / "api_key"
    config.parent.mkdir(parents=True)
    config.write_text("config-key", encoding="utf-8")
    assert Settings.load({"SHODAN_API_KEY": "env-key"}, home=tmp_path).api_key == "env-key"


@pytest.mark.parametrize("value", ["line-one\nline-two", "x" * 257, "密钥", "key\x00suffix"])
def test_malformed_environment_keys_are_rejected_without_echoing_them(tmp_path: Path, value: str) -> None:
    with pytest.raises(AuthenticationError) as failure:
        Settings.load({"SHODAN_API_KEY": value}, home=tmp_path)
    assert value not in str(failure.value)


def test_invalid_utf8_cli_configuration_is_an_authentication_error(tmp_path: Path) -> None:
    config = tmp_path / ".shodan" / "api_key"
    config.parent.mkdir(parents=True)
    config.write_bytes(b"\xff\xfe")

    with pytest.raises(AuthenticationError, match="Unable to read"):
        Settings.load({}, home=tmp_path)


def test_missing_key_is_lazy_error(tmp_path: Path) -> None:
    settings = Settings.load({}, home=tmp_path)
    assert settings.api_key is None
    with pytest.raises(AuthenticationError):
        settings.require_api_key()


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("SHODAN_READ_TIMEOUT", "zero", "must be a number"),
        ("SHODAN_READ_TIMEOUT", "0", "greater than zero"),
        ("SHODAN_READ_TIMEOUT", "nan", "finite"),
        ("SHODAN_STREAM_TIMEOUT", "inf", "finite"),
        ("SHODAN_RETRIES", "many", "must be an integer"),
        ("SHODAN_RETRIES", "9", "must be between"),
        ("SHODAN_PROXY", "socks5://proxy.example", "http\\(s\\) proxy"),
        ("SHODAN_PROXY", "https://proxy.example/path", "without a path"),
        ("SHODAN_PROXY", "https://proxy.example:invalid", "invalid port"),
    ],
)
def test_invalid_settings_are_rejected(tmp_path: Path, name: str, value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Settings.load({name: value}, home=tmp_path)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"read_timeout": float("nan")}, "finite"),
        ({"stream_timeout": 0.0}, "greater than zero"),
        ({"retries": 6}, "between"),
    ],
)
def test_invalid_explicit_runtime_overrides_are_rejected(
    tmp_path: Path,
    kwargs: dict[str, float | int],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        Settings.load({}, home=tmp_path, **kwargs)
