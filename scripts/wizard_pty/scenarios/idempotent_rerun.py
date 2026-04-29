"""idempotent_rerun: running the wizard twice merges, never clobbers.

Two passes against Cursor mcp.json with two different MCP server
names. After the second run we assert:

* Both server names exist under ``mcpServers``.
* The wizard wrote a ``.bak.<timestamp>`` of the first run's file.
* No secrets ever leaked into the file.
"""

from __future__ import annotations

import glob

from . import _base
from ._base import (
    Scenario,
    ScenarioReport,
    cleanup_backup_chain,
    cleanup_keychain_pair,
    cursor_config_path,
    restore,
    run_pty,
    snapshot,
    splunk_env,
)


def _script(splunk: dict[str, str], server_name: str) -> list[tuple[str, bytes]]:
    return [
        ("Splunk host (FQDN or IP) [localhost]:", f"{splunk['host']}\r".encode()),
        ("Splunk REST management port [8089]:", f"{splunk['port']}\r".encode()),
        ("Select [1-2]:", b"1\r"),  # https
        ("Select [1-3]:", b"3\r"),  # disable verify
        ("Continue with TLS verification disabled?", b"y\r"),
        ("Select [1-2]:", b"2\r"),  # username + password
        ("Continue and send the password to this endpoint?", b"y\r"),
        ("Splunk username [admin]:", f"{splunk['username']}\r".encode()),
        ("Splunk password:", splunk["password"].encode() + b"\r"),
        ("MCP server name [splunk]:", f"{server_name}\r".encode()),
        ("Select [1-4]:", b"1\r"),  # Cursor
    ]


SERVER_A = "splunk-pty-rerun-a"
SERVER_B = "splunk-pty-rerun-b"


def run() -> ScenarioReport:
    splunk = splunk_env()
    cursor_cfg = cursor_config_path()
    cursor_backup = snapshot(cursor_cfg)

    notes: list[str] = []
    artefact_problems: list[str] = []
    last = None
    try:
        first = run_pty(
            ["spl-bridge", "setup"],
            _script(splunk, SERVER_A),
            extra_env={"NO_COLOR": ""},
        )
        if first.exit_status != 0:
            artefact_problems.append(f"first run exited {first.exit_status}")
            return ScenarioReport(
                name="idempotent_rerun",
                ok=False,
                pty=first,
                notes=notes,
                artefact_problems=artefact_problems,
            )

        second = run_pty(
            ["spl-bridge", "setup"],
            _script(splunk, SERVER_B),
            extra_env={"NO_COLOR": ""},
        )
        last = second
        if second.exit_status != 0:
            artefact_problems.append(f"second run exited {second.exit_status}")

        if not _base.os.path.exists(cursor_cfg):
            artefact_problems.append("Cursor mcp.json missing after rerun")
        else:
            with open(cursor_cfg, encoding="utf-8") as fh:
                cfg = _base.json.load(fh)
            servers = cfg.get("mcpServers", {})
            if SERVER_A not in servers:
                artefact_problems.append(f"first run server {SERVER_A!r} lost")
            if SERVER_B not in servers:
                artefact_problems.append(f"second run server {SERVER_B!r} missing")
            blob = _base.json.dumps(cfg)
            for banned in ("SPLUNK_PASSWORD", "SPLUNK_TOKEN", splunk["password"]):
                if banned in blob:
                    artefact_problems.append(
                        f"forbidden {banned!r} appeared in merged Cursor config"
                    )

        # The wizard's own backup file (.bak.<ts>) should exist after the
        # second run, since the first run produced a writable file.
        bak_files = glob.glob(f"{cursor_cfg}.bak.*")
        if not bak_files:
            artefact_problems.append("wizard did not back up Cursor mcp.json on rerun")
        else:
            notes.append(f"wizard backups: {len(bak_files)} file(s)")

        return ScenarioReport(
            name="idempotent_rerun",
            ok=not artefact_problems,
            pty=last or first,
            notes=notes,
            artefact_problems=artefact_problems,
        )
    finally:
        cleanup_keychain_pair()
        restore(cursor_cfg, cursor_backup)
        cleanup_backup_chain(cursor_cfg)


SCENARIO = Scenario(name="idempotent_rerun", run=run)
