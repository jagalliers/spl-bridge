"""password_cursor: lab user/password auth -> Cursor mcp.json.

This is the port of the original ``smoketest_wizard.py`` flow. It
exercises the username/password auth path with TLS verification
DISABLED (typical lab Splunk with self-signed cert), Cursor as the
MCP host writer, and OS keychain as the credstore.

Asserts:
* Wizard exits 0
* Cursor mcp.json contains the entry under our scenario-unique
  server name with the right env metadata and NO secret
* Keychain contains SPLUNK_USERNAME + SPLUNK_PASSWORD
* Password never appears in the PTY transcript (getpass discipline)

Cleanup leaves the user's machine exactly as it found it.
"""

from __future__ import annotations

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

SERVER_NAME = "splunk-pty-password-cursor"


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
        ("Splunk password:", splunk["password"].encode() + b"\r"),
        ("MCP server name [splunk]:", f"{SERVER_NAME}\r".encode()),
        ("Select [1-4]:", b"1\r"),  # Cursor
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

        if result.exit_status != 0:
            artefact_problems.append(f"wizard exited {result.exit_status}")

        # --- Cursor config write ---
        if not _base.os.path.exists(cursor_cfg):
            artefact_problems.append("Cursor mcp.json not written")
        else:
            with open(cursor_cfg, encoding="utf-8") as fh:
                cfg = _base.json.load(fh)
            servers = cfg.get("mcpServers", {})
            entry = servers.get(SERVER_NAME)
            if entry is None:
                artefact_problems.append(f"missing {SERVER_NAME} entry in mcpServers")
            else:
                env = entry.get("env", {})
                expected = {
                    "SPLUNK_HOST": splunk["host"],
                    "SPLUNK_PORT": splunk["port"],
                    "SPLUNK_SCHEME": "https",
                    "SPLUNK_VERIFY_SSL": "false",
                }
                for k, v in expected.items():
                    if env.get(k) != v:
                        artefact_problems.append(f"{k} expected {v!r}, got {env.get(k)!r}")
                # No secrets in the host config -- ever.
                blob = _base.json.dumps(entry)
                for banned in ("SPLUNK_PASSWORD", "SPLUNK_TOKEN", splunk["password"]):
                    if banned in blob:
                        artefact_problems.append(f"forbidden {banned!r} appeared in Cursor config")

        # --- Keychain ---
        if not keychain_has("spl-bridge", "SPLUNK_USERNAME"):
            artefact_problems.append("Keychain missing SPLUNK_USERNAME")
        if not keychain_has("spl-bridge", "SPLUNK_PASSWORD"):
            artefact_problems.append("Keychain missing SPLUNK_PASSWORD")

        # --- No secret echoed to the PTY ---
        leaked = assert_no_secret_leak(result.transcript, [splunk["password"]])
        if leaked:
            artefact_problems.append("password leaked into PTY transcript (getpass should hide it)")

        notes.append(f"server name written: {SERVER_NAME}")
        return ScenarioReport(
            name="password_cursor",
            ok=not artefact_problems,
            pty=result,
            notes=notes,
            artefact_problems=artefact_problems,
        )
    finally:
        cleanup_keychain_pair()
        restore(cursor_cfg, cursor_backup)
        cleanup_backup_chain(cursor_cfg)


SCENARIO = Scenario(name="password_cursor", run=run)
