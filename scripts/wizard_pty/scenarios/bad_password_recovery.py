"""bad_password_recovery: probe fails on bad password, user declines.

Verifies that:
* The probe actually attempts auth and fails cleanly (no traceback).
* The "Continue anyway and persist these settings?" prompt appears.
* Answering "no" leaves Cursor mcp.json untouched and the keychain
  free of any new rows for our scenario.

This is the most important "user mistyped their password" guardrail.
"""

from __future__ import annotations

from . import _base
from ._base import (
    Scenario,
    ScenarioReport,
    cleanup_backup_chain,
    cleanup_keychain_pair,
    cursor_config_path,
    keychain_has,
    restore,
    run_pty,
    snapshot,
    splunk_env,
    strip_ansi,
)

WRONG_PASSWORD = "this-is-not-the-real-lab-password-xyzzy"  # noqa: S105 -- intentional


def _script(splunk: dict[str, str]) -> list[tuple[str, bytes]]:
    return [
        ("Splunk host (FQDN or IP) [localhost]:", f"{splunk['host']}\r".encode()),
        ("Splunk REST management port [8089]:", f"{splunk['port']}\r".encode()),
        ("Select [1-2]:", b"1\r"),  # https
        ("Select [1-3]:", b"3\r"),  # disable verify
        ("type 'I UNDERSTAND' to confirm", b"I UNDERSTAND\r"),
        ("Select [1-2]:", b"2\r"),  # username + password
        ("type 'I UNDERSTAND' to confirm", b"I UNDERSTAND\r"),
        ("Splunk username [admin]:", f"{splunk['username']}\r".encode()),
        ("Splunk password:", WRONG_PASSWORD.encode() + b"\r"),
        ("Continue anyway and persist these settings?", b"n\r"),
    ]


def run() -> ScenarioReport:
    splunk = splunk_env()
    cursor_cfg = cursor_config_path()
    cursor_backup = snapshot(cursor_cfg)

    notes: list[str] = []
    artefact_problems: list[str] = []
    try:
        result = run_pty(
            ["spl-bridge", "setup"],
            _script(splunk),
            extra_env={"NO_COLOR": ""},
        )

        if result.exit_status != 1:
            artefact_problems.append(
                f"expected exit 1 (probe-fail + decline), got {result.exit_status}"
            )

        cleaned = strip_ansi(result.transcript)
        if "Connection failed" not in cleaned:
            artefact_problems.append("expected 'Connection failed' in probe output")
        if "Continue anyway and persist these settings?" not in cleaned:
            artefact_problems.append("did not reach decline prompt")

        # Verify NOTHING was persisted past the decline.
        if keychain_has("spl-bridge", "SPLUNK_PASSWORD"):
            artefact_problems.append("Keychain row written despite user declining persistence")
        if cursor_backup is None and _base.os.path.exists(cursor_cfg):
            artefact_problems.append("Cursor mcp.json created despite decline")

        # Wrong password must not have been echoed to the PTY -- getpass
        # discipline still applies on the failure path.
        if WRONG_PASSWORD in cleaned:
            artefact_problems.append("wrong password echoed to PTY (getpass discipline broken)")

        return ScenarioReport(
            name="bad_password_recovery",
            ok=not artefact_problems,
            pty=result,
            notes=notes,
            artefact_problems=artefact_problems,
        )
    finally:
        cleanup_keychain_pair()
        restore(cursor_cfg, cursor_backup)
        cleanup_backup_chain(cursor_cfg)


SCENARIO = Scenario(name="bad_password_recovery", run=run)
