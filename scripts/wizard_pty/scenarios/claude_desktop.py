"""claude_desktop: writer #2 -- Claude Desktop config file.

Same flow as ``password_cursor`` except we pick option 2 at the
"where should we register" prompt. The Claude Desktop file lives at
``~/Library/Application Support/Claude/claude_desktop_config.json``
on macOS; we snapshot/restore it just like Cursor's mcp.json.

Note: Claude Desktop doesn't need to be installed for the writer to
succeed (the writer just creates the JSON the app reads at startup).
"""

from __future__ import annotations

import sys

from . import _base
from ._base import (
    Scenario,
    ScenarioReport,
    assert_no_secret_leak,
    claude_desktop_config_path,
    cleanup_backup_chain,
    cleanup_keychain_pair,
    keychain_has,
    restore,
    run_pty,
    snapshot,
    splunk_env,
)

SERVER_NAME = "splunk-pty-claude-desktop"


def _script(splunk: dict[str, str]) -> list[tuple[str, bytes]]:
    return [
        ("Splunk host (FQDN or IP) [localhost]:", f"{splunk['host']}\r".encode()),
        ("Splunk REST management port [8089]:", f"{splunk['port']}\r".encode()),
        ("Select [1-2]:", b"1\r"),
        ("Select [1-3]:", b"3\r"),
        ("Continue with TLS verification disabled?", b"y\r"),
        ("Select [1-2]:", b"2\r"),
        ("Continue and send the password to this endpoint?", b"y\r"),
        ("Splunk username [admin]:", f"{splunk['username']}\r".encode()),
        ("Splunk password:", splunk["password"].encode() + b"\r"),
        ("MCP server name [splunk]:", f"{SERVER_NAME}\r".encode()),
        ("Select [1-4]:", b"2\r"),  # Claude Desktop
    ]


def run() -> ScenarioReport:
    splunk = splunk_env()
    cd_cfg = claude_desktop_config_path()
    cd_backup = snapshot(cd_cfg)

    notes: list[str] = []
    artefact_problems: list[str] = []

    if sys.platform != "darwin":
        notes.append(
            f"skipped: Claude Desktop path is macOS-specific (current platform: {sys.platform})"
        )
        return ScenarioReport(
            name="claude_desktop",
            ok=True,
            pty=_base.PtyResult(exit_status=0, transcript=""),
            notes=notes,
        )

    try:
        result = run_pty(
            ["spl-bridge", "setup"],
            _script(splunk),
            extra_env={"NO_COLOR": ""},
        )
        if result.exit_status != 0:
            artefact_problems.append(f"wizard exited {result.exit_status}")

        if not _base.os.path.exists(cd_cfg):
            artefact_problems.append("Claude Desktop config not written")
        else:
            with open(cd_cfg, encoding="utf-8") as fh:
                cfg = _base.json.load(fh)
            entry = cfg.get("mcpServers", {}).get(SERVER_NAME)
            if entry is None:
                artefact_problems.append(f"missing {SERVER_NAME} entry in Claude Desktop config")
            else:
                env = entry.get("env", {})
                if env.get("SPLUNK_HOST") != splunk["host"]:
                    artefact_problems.append("SPLUNK_HOST mismatch")
                blob = _base.json.dumps(entry)
                for banned in (
                    "SPLUNK_PASSWORD",
                    "SPLUNK_TOKEN",
                    splunk["password"],
                ):
                    if banned in blob:
                        artefact_problems.append(
                            f"forbidden {banned!r} appeared in Claude Desktop config"
                        )

        if not keychain_has("spl-bridge", "SPLUNK_PASSWORD"):
            artefact_problems.append("Keychain missing SPLUNK_PASSWORD")

        leaked = assert_no_secret_leak(result.transcript, [splunk["password"]])
        if leaked:
            artefact_problems.append("password leaked into PTY transcript")

        return ScenarioReport(
            name="claude_desktop",
            ok=not artefact_problems,
            pty=result,
            notes=notes,
            artefact_problems=artefact_problems,
        )
    finally:
        cleanup_keychain_pair()
        restore(cd_cfg, cd_backup)
        cleanup_backup_chain(cd_cfg)


SCENARIO = Scenario(name="claude_desktop", run=run)
