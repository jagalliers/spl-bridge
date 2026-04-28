"""Shared scaffolding for PTY wizard scenarios.

A :class:`Scenario` is a small declarative bundle: a name, a
``run(env)`` callable that the runner invokes after preparing the
environment, and the helpers (snapshot/restore, keychain cleanup)
that every scenario needs.

Keeping the helpers here means each scenario file stays focused on
the wizard prompts + the scenario's specific verifications.
"""

from __future__ import annotations

import contextlib
import dataclasses
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

# ``scripts/`` is on sys.path when the runner invokes us; for direct
# imports during testing the parent package handles that.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.wizard_pty.driver import (  # noqa: E402
    PtyResult,
    assert_no_secret_leak,
    run_pty,
    strip_ansi,
)


@dataclasses.dataclass
class ScenarioReport:
    """What the runner prints / pytest asserts on."""

    name: str
    ok: bool
    pty: PtyResult
    notes: list[str] = dataclasses.field(default_factory=list)
    artefact_problems: list[str] = dataclasses.field(default_factory=list)

    def fail_summary(self) -> str:
        bits = [f"scenario={self.name}", f"exit={self.pty.exit_status}"]
        if self.pty.timed_out_on is not None:
            bits.append(f"timed_out_on={self.pty.timed_out_on!r}")
        if self.artefact_problems:
            bits.append("artefact_problems=" + repr(self.artefact_problems))
        return " ".join(bits)


@dataclasses.dataclass
class Scenario:
    name: str
    run: Callable[[], ScenarioReport]


# ---------------------------------------------------------------------------
# Required-env loader
# ---------------------------------------------------------------------------


def required_env(name: str) -> str:
    """Look up *name* or exit 2 with a clear message.

    Scenarios source Splunk credentials from env so no secret literal
    ever lives in the repo.
    """
    val = os.environ.get(name)
    if not val:
        sys.stderr.write(
            f"error: {name} env var is required for this scenario.\n"
            "       See scripts/run_wizard_pty.py --help.\n"
        )
        raise SystemExit(2)
    return val


def splunk_env() -> dict[str, str]:
    """The four shared SPLUNK_SMOKETEST_* knobs (password is required)."""
    return {
        "host": os.environ.get("SPLUNK_SMOKETEST_HOST", "localhost"),
        "port": os.environ.get("SPLUNK_SMOKETEST_PORT", "8089"),
        "username": os.environ.get("SPLUNK_SMOKETEST_USERNAME", "admin"),
        "password": required_env("SPLUNK_SMOKETEST_PASSWORD"),
    }


# ---------------------------------------------------------------------------
# Snapshot / restore -- protect real user files
# ---------------------------------------------------------------------------


def snapshot(path: str) -> str | None:
    """Copy *path* to a sibling ``.smoketest-bak-<ts>`` file or return None.

    The driver always restores the snapshot in a try/finally so we
    never leave a user's mcp.json / claude config in a wizard-modified
    state.
    """
    if not os.path.exists(path):
        return None
    ts = int(time.time() * 1000)
    backup = f"{path}.smoketest-bak-{ts}"
    shutil.copy2(path, backup)
    return backup


def restore(path: str, backup: str | None) -> None:
    """Restore the file (or remove it if it didn't exist before)."""
    if backup is None:
        if os.path.exists(path):
            os.unlink(path)
        return
    shutil.copy2(backup, path)


def cleanup_backup_chain(path: str) -> None:
    """Remove our snapshot plus any wizard-generated ``.bak.<ts>`` siblings."""
    for stale in glob.glob(f"{path}.smoketest-bak-*"):
        with contextlib.suppress(OSError):
            os.unlink(stale)
    for stale in glob.glob(f"{path}.bak.*"):
        with contextlib.suppress(OSError):
            os.unlink(stale)


# ---------------------------------------------------------------------------
# macOS Keychain helpers (no-op on other platforms)
# ---------------------------------------------------------------------------


def keychain_has(service: str, account: str) -> bool:
    if sys.platform != "darwin":
        return False
    try:
        proc = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0
    except FileNotFoundError:
        return False


def keychain_delete(service: str, account: str) -> bool:
    if sys.platform != "darwin":
        return False
    try:
        proc = subprocess.run(
            ["security", "delete-generic-password", "-s", service, "-a", account],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0
    except FileNotFoundError:
        return False


def cleanup_keychain_pair() -> None:
    """Delete both possible secret rows the wizard writes under spl-bridge."""
    keychain_delete("spl-bridge", "SPLUNK_USERNAME")
    keychain_delete("spl-bridge", "SPLUNK_PASSWORD")
    keychain_delete("spl-bridge", "SPLUNK_TOKEN")


# ---------------------------------------------------------------------------
# Convenience for "run, capture, clean up" pattern
# ---------------------------------------------------------------------------


def cursor_config_path() -> str:
    return os.path.expanduser("~/.cursor/mcp.json")


def claude_desktop_config_path() -> str:
    return os.path.expanduser("~/Library/Application Support/Claude/claude_desktop_config.json")


def write_pem_fixture(parent: Path) -> Path:
    """Write a syntactically-valid (self-signed) PEM into *parent* for
    the CA bundle scenario. The wizard only checks that the file
    exists -- the probe will then fail TLS verify against splunkd's
    self-signed cert, which is fine: the scenario's job is to verify
    the *config write* shape.
    """
    parent.mkdir(parents=True, exist_ok=True)
    pem = parent / "fake_ca.pem"
    pem.write_text(
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBhTCCASugAwIBAgIQ4n8z2Wlj0vT+HsS7bV+XTjAKBggqhkjOPQQDAjAcMRow\n"
        "GAYDVQQDExFXaXphcmQgUFRZIENBIFRlc3QwHhcNMjQwMTAxMDAwMDAwWhcNMzQw\n"
        "MTAxMDAwMDAwWjAcMRowGAYDVQQDExFXaXphcmQgUFRZIENBIFRlc3QwWTATBgcq\n"
        "hkjOPQIBBggqhkjOPQMBBwNCAARjB6m+5Ck7m7t8u5p9oGhTb9G5xWqB5R1H7zv5\n"
        "qX1F6m+w8vQAvAvJj3Jq1nQpV8u5p9oGhTb9G5xWqB5R1H7zv5qXo0IwQDAOBgNV\n"
        "HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUz8j+vQF7r9y4\n"
        "XOPa8ufqYj+xCMowCgYIKoZIzj0EAwIDSAAwRQIhAOIH5yXq0v3l9p2CnG2J7g2X\n"
        "1G4bPj3l4G5LMR5q4j5HAiB1Z8lSxCMowYjP7s7q5Yk2y8m7m2nBL5XzG5yWqB5R\n"
        "1H==\n"
        "-----END CERTIFICATE-----\n"
    )
    return pem


# ---------------------------------------------------------------------------
# Re-exports for scenario modules
# ---------------------------------------------------------------------------


__all__ = [
    "PtyResult",
    "Scenario",
    "ScenarioReport",
    "assert_no_secret_leak",
    "claude_desktop_config_path",
    "cleanup_backup_chain",
    "cleanup_keychain_pair",
    "cursor_config_path",
    "json",
    "keychain_delete",
    "keychain_has",
    "os",
    "required_env",
    "restore",
    "run_pty",
    "snapshot",
    "splunk_env",
    "strip_ansi",
    "subprocess",
    "sys",
    "tempfile",
    "write_pem_fixture",
]
