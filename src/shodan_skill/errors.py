"""Typed errors and stable process exit codes."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    USAGE = 2
    AUTHENTICATION = 3
    AUTHORIZATION = 4
    CREDITS = 5
    NETWORK = 6
    API = 7
    TIMEOUT = 8
    INTERRUPTED = 9
    INTERNAL = 10


class ShodanSkillError(Exception):
    """Base class for categorized user-facing failures."""

    code = "internal"
    exit_code = ExitCode.INTERNAL

    def __init__(self, message: str, *, details: object | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class UsageError(ShodanSkillError):
    code = "usage"
    exit_code = ExitCode.USAGE


class AuthenticationError(ShodanSkillError):
    code = "authentication"
    exit_code = ExitCode.AUTHENTICATION


class AuthorizationError(ShodanSkillError):
    code = "authorization"
    exit_code = ExitCode.AUTHORIZATION


class CreditsError(ShodanSkillError):
    code = "credits"
    exit_code = ExitCode.CREDITS


class NetworkError(ShodanSkillError):
    code = "network"
    exit_code = ExitCode.NETWORK


class ApiError(ShodanSkillError):
    code = "api"
    exit_code = ExitCode.API


class TimeoutError(ShodanSkillError):
    code = "timeout"
    exit_code = ExitCode.TIMEOUT


class InterruptedError(ShodanSkillError):
    code = "interrupted"
    exit_code = ExitCode.INTERRUPTED


class InternalError(ShodanSkillError):
    code = "internal"
    exit_code = ExitCode.INTERNAL
