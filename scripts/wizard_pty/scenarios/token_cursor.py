"""token_cursor: Splunk auth token -> Cursor mcp.json.

Exercises the recommended-for-prod path: token-based auth. The token
is read from ``SPLUNK_SMOKETEST_TOKEN``. To produce one in the lab::

    /Applications/Splunk/bin/splunk login -auth admin:<lab-pw>
    /Applications/Splunk/bin/splunk \\
        _internal call /services/authorization/tokens \\
        -post:name admin -post:audience pty-smoketest \\
        -post:expires_on +30d

If the token env var is not set, the scenario logs a clear skip note
rather than failing -- token issuance requires admin and we don't
want to require it for every dev that runs the harness.
"""

from __future__ import annotations

import os

from . import _base
from ._base import (
    Scenario,
    ScenarioReport,
    assert_no_secret_leak,
    cleanup_backup_chain,
    cleanup_keychain_pair,
    cursor_config_path,
    keychain_has,
    restore,
    run_pty,
    snapshot,
    splunk_env,
)

SERVER_NAME = "splunk-pty-token-cursor"


def _script(splunk: dict[str, str], token: str) -> list[tuple[str, bytes]]:
    return [
        ("Splunk host (FQDN or IP) [localhost]:", f"{splunk['host']}\r".encode()),
        ("Splunk REST management port [8089]:", f"{splunk['port']}\r".encode()),
        ("Select [1-2]:", b"1\r"),  # https
        ("Select [1-3]:", b"3\r"),  # disable verify
        ("type 'I UNDERSTAND' to confirm", b"I UNDERSTAND\r"),
        ("Select [1-2]:", b"1\r"),  # token (recommended)
        ("Splunk auth token:", token.encode() + b"\r"),
        ("MCP server name [splunk]:", f"{SERVER_NAME}\r".encode()),
        ("Select [1-4]:", b"1\r"),  # Cursor
    ]


def run() -> ScenarioReport:
    splunk = splunk_env()
    token = os.environ.get("SPLUNK_SMOKETEST_TOKEN", "")
    cursor_cfg = cursor_config_path()
    cursor_backup = snapshot(cursor_cfg)

    notes: list[str] = []
    artefact_problems: list[str] = []

    if not token:
        # The wizard's getpass refuses empty input, so passing an
        # empty token would loop forever. Skip cleanly with a clear
        # note instead.
        notes.append(
            "skipped: SPLUNK_SMOKETEST_TOKEN not set "
            "(see scripts/wizard_pty/scenarios/token_cursor.py for "
            "instructions on minting a lab token)"
        )
        # Empty PtyResult so the runner can still report.
        return ScenarioReport(
            name="token_cursor",
            ok=True,
            pty=_base.PtyResult(exit_status=0, transcript=""),
            notes=notes,
            artefact_problems=[],
        )

    try:
        result = run_pty(
            ["spl-bridge", "setup"],
            _script(splunk, token),
            extra_env={"NO_COLOR": ""},
        )
        if result.exit_status != 0:
            artefact_problems.append(f"wizard exited {result.exit_status}")

        if not _base.os.path.exists(cursor_cfg):
            artefact_problems.append("Cursor mcp.json not written")
        else:
            with open(cursor_cfg, encoding="utf-8") as fh:
                cfg = _base.json.load(fh)
            entry = cfg.get("mcpServers", {}).get(SERVER_NAME)
            if entry is None:
                artefact_problems.append(f"missing {SERVER_NAME} entry in mcpServers")
            else:
                env = entry.get("env", {})
                if env.get("SPLUNK_HOST") != splunk["host"]:
                    artefact_problems.append("SPLUNK_HOST mismatch")
                if env.get("SPLUNK_SCHEME") != "https":
                    artefact_problems.append("SPLUNK_SCHEME mismatch")
                blob = _base.json.dumps(entry)
                for banned in ("SPLUNK_TOKEN", "SPLUNK_PASSWORD", token):
                    if banned in blob:
                        artefact_problems.append(f"forbidden {banned!r} appeared in Cursor config")

        # Token mode -> token row in keychain
        if not keychain_has("spl-bridge", "SPLUNK_TOKEN"):
            artefact_problems.append("Keychain missing SPLUNK_TOKEN")
        # And no password row should exist
        if keychain_has("spl-bridge", "SPLUNK_PASSWORD"):
            artefact_problems.append("Keychain unexpectedly has SPLUNK_PASSWORD in token mode")

        leaked = assert_no_secret_leak(result.transcript, [token])
        if leaked:
            artefact_problems.append("token leaked into PTY transcript (getpass should hide it)")

        notes.append(f"server name written: {SERVER_NAME}")
        return ScenarioReport(
            name="token_cursor",
            ok=not artefact_problems,
            pty=result,
            notes=notes,
            artefact_problems=artefact_problems,
        )
    finally:
        cleanup_keychain_pair()
        restore(cursor_cfg, cursor_backup)
        cleanup_backup_chain(cursor_cfg)


SCENARIO = Scenario(name="token_cursor", run=run)
