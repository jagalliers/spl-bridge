"""claude_cli: writer #3 -- shells out to ``claude mcp add``.

Skipped automatically if the ``claude`` CLI is not on PATH; we don't
want to make this a hard requirement for everyone running the
harness. When present, exercises the wizard's subprocess writer
shape (which has its own argument-construction code path).

Cleanup: ``claude mcp remove --scope user <name>`` so the user's
real Claude config doesn't accumulate test entries.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess

from . import _base
from ._base import (
    Scenario,
    ScenarioReport,
    assert_no_secret_leak,
    cleanup_keychain_pair,
    keychain_has,
    run_pty,
    splunk_env,
)

SERVER_NAME = "splunk-pty-claude-cli"


def _script(splunk: dict[str, str]) -> list[tuple[str, bytes]]:
    return [
        ("Splunk host (FQDN or IP) [localhost]:", f"{splunk['host']}\r".encode()),
        ("Splunk REST management port [8089]:", f"{splunk['port']}\r".encode()),
        ("Select [1-2]:", b"1\r"),
        ("Select [1-3]:", b"3\r"),
        ("type 'I UNDERSTAND' to confirm", b"I UNDERSTAND\r"),
        ("Select [1-2]:", b"2\r"),
        ("type 'I UNDERSTAND' to confirm", b"I UNDERSTAND\r"),
        ("Splunk username [admin]:", f"{splunk['username']}\r".encode()),
        ("Splunk password:", splunk["password"].encode() + b"\r"),
        ("MCP server name [splunk]:", f"{SERVER_NAME}\r".encode()),
        ("Select [1-4]:", b"3\r"),  # Claude CLI
    ]


def _claude_remove() -> None:
    """Best-effort cleanup of the entry our run created."""
    if shutil.which("claude") is None:
        return
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(  # noqa: S603,S607 -- inputs are literals
            [
                "claude",
                "mcp",
                "remove",
                "--scope",
                "user",
                SERVER_NAME,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )


def run() -> ScenarioReport:
    splunk = splunk_env()
    notes: list[str] = []
    artefact_problems: list[str] = []

    if shutil.which("claude") is None:
        notes.append("skipped: `claude` CLI not on PATH")
        return ScenarioReport(
            name="claude_cli",
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

        # Verify the entry was actually registered with claude.
        proc = subprocess.run(  # noqa: S603,S607
            ["claude", "mcp", "list"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        if SERVER_NAME not in proc.stdout:
            artefact_problems.append(f"`claude mcp list` does not show {SERVER_NAME!r}")

        if not keychain_has("spl-bridge", "SPLUNK_PASSWORD"):
            artefact_problems.append("Keychain missing SPLUNK_PASSWORD")

        # The password must NOT appear in `claude mcp list` output --
        # we send connection metadata via --env, never the secret.
        if splunk["password"] in proc.stdout:
            artefact_problems.append("password appeared in `claude mcp list` output")

        leaked = assert_no_secret_leak(result.transcript, [splunk["password"]])
        if leaked:
            artefact_problems.append("password leaked into PTY transcript")

        return ScenarioReport(
            name="claude_cli",
            ok=not artefact_problems,
            pty=result,
            notes=notes,
            artefact_problems=artefact_problems,
        )
    finally:
        cleanup_keychain_pair()
        _claude_remove()


SCENARIO = Scenario(name="claude_cli", run=run)
