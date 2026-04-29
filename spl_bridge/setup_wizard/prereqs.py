"""Prerequisite checks for the setup wizard.

Each check returns a small dataclass so callers can format them in a
table. We never raise out of a probe -- the wizard is responsible for
deciding whether a degraded result is fatal or just a warning.
"""

from __future__ import annotations

import importlib
import platform
import sys
from dataclasses import dataclass

MIN_PYTHON = (3, 10)


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


def check_python_version() -> CheckResult:
    cur = sys.version_info[:3]
    return CheckResult(
        name="Python version",
        passed=cur >= MIN_PYTHON,
        detail=(f"running {platform.python_version()} (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})"),
    )


def _can_import(module: str) -> tuple[bool, str]:
    try:
        importlib.import_module(module)
    except ImportError as exc:
        return False, f"missing: {exc}"
    return True, "importable"


def check_mcp_importable() -> CheckResult:
    ok, detail = _can_import("mcp")
    return CheckResult("mcp library", ok, detail)


def check_requests_importable() -> CheckResult:
    ok, detail = _can_import("requests")
    return CheckResult("requests library", ok, detail)


def check_keyring_backend() -> CheckResult:
    """Probe whether ``keyring`` is importable AND has a usable backend.

    On Linux a base install often lands the no-op ``fail.Keyring`` backend
    (no Secret Service). We treat that as "not usable" so the wizard can
    fall back to the dotfile store cleanly.
    """
    try:
        import keyring
    except ImportError:
        return CheckResult(
            "OS keychain (keyring)",
            False,
            # NOTE: single-quote the package spec so the suggestion is safe to
            # copy-paste into zsh (the macOS default shell), which otherwise
            # treats `[` and `]` as filename glob characters and rejects the
            # command with "no matches found". Quotes are harmless in bash,
            # fish, and PowerShell, so the quoted form works everywhere.
            "package not installed -- install with `pip install 'spl-bridge[keyring]'`",
        )
    backend = keyring.get_keyring()
    backend_name = type(backend).__module__ + "." + type(backend).__name__
    # ``keyring.backends.fail.Keyring`` is the sentinel "no real backend".
    if backend_name.endswith(".fail.Keyring"):
        return CheckResult(
            "OS keychain (keyring)",
            False,
            f"{backend_name} (no usable backend on this system)",
        )
    return CheckResult("OS keychain (keyring)", True, f"backend = {backend_name}")


def check_platformdirs_importable() -> CheckResult:
    ok, detail = _can_import("platformdirs")
    return CheckResult("platformdirs", ok, detail)


def run_all() -> list[CheckResult]:
    return [
        check_python_version(),
        check_mcp_importable(),
        check_requests_importable(),
        check_platformdirs_importable(),
        check_keyring_backend(),
    ]
