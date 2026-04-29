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
            # NOTE: this suggestion is intentionally the PEP 508 git-URL form
            # rather than `pip install 'spl-bridge[keyring]'` because the
            # project is not (yet) on PyPI -- the bare PyPI form would fail
            # with "Could not find a version that satisfies the requirement
            # spl-bridge". The whole argument is single-quoted to be safe in
            # zsh (which otherwise treats `[` `]` as glob characters and the
            # `@` plus `://` as shell-significant) while remaining harmless
            # in bash, fish, and PowerShell. When we publish to PyPI, drop
            # the ` @ git+...` suffix and revert to `pip install
            # 'spl-bridge[keyring]'`.
            "package not installed -- install with `pip install "
            "'spl-bridge[keyring] @ git+https://github.com/jagalliers/spl-bridge.git'`",
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
