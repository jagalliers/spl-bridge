"""snippet_only: writer #4 -- print snippet, touch nothing.

This is the cheapest end-to-end scenario: it goes through prereqs +
config + probe + credstore but doesn't write any host config file.
Useful as a fast smoke for the wizard's main path.

The scenario asserts that the printed JSON snippet contains the
expected ``mcpServers.<name>`` shape with connection metadata in
``env`` and NO secrets.
"""

from __future__ import annotations

import re

from . import _base
from ._base import (
    Scenario,
    ScenarioReport,
    assert_no_secret_leak,
    cleanup_keychain_pair,
    keychain_has,
    run_pty,
    splunk_env,
    strip_ansi,
)

SERVER_NAME = "splunk-pty-snippet"


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
        ("Select [1-4]:", b"4\r"),  # Print snippet only
    ]


def run() -> ScenarioReport:
    splunk = splunk_env()
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

        cleaned = strip_ansi(result.transcript)

        # The snippet header should appear, then a JSON object.
        if "Add this to your MCP host config:" not in cleaned:
            artefact_problems.append("snippet header missing from transcript")

        # Pull the first JSON object after the header out of the
        # transcript and round-trip it.
        marker = "Add this to your MCP host config:"
        idx = cleaned.find(marker)
        if idx >= 0:
            tail = cleaned[idx + len(marker) :]
            # Greedy match of the first ``{...}`` block at column zero
            # (the wizard pretty-prints with indent=2).
            m = re.search(r"(\{[\s\S]*?\n\})", tail)
            if not m:
                artefact_problems.append("could not parse JSON snippet block")
            else:
                try:
                    snippet = _base.json.loads(m.group(1))
                except _base.json.JSONDecodeError as exc:
                    artefact_problems.append(f"snippet JSON invalid: {exc}")
                    snippet = None
                if isinstance(snippet, dict):
                    entry = snippet.get("mcpServers", {}).get(SERVER_NAME)
                    if entry is None:
                        artefact_problems.append(f"snippet missing mcpServers.{SERVER_NAME}")
                    else:
                        env = entry.get("env", {})
                        if env.get("SPLUNK_HOST") != splunk["host"]:
                            artefact_problems.append("SPLUNK_HOST mismatch in snippet")
                        blob = _base.json.dumps(entry)
                        for banned in (
                            "SPLUNK_PASSWORD",
                            "SPLUNK_TOKEN",
                            splunk["password"],
                        ):
                            if banned in blob:
                                artefact_problems.append(f"forbidden {banned!r} in printed snippet")

        if not keychain_has("spl-bridge", "SPLUNK_PASSWORD"):
            artefact_problems.append("Keychain missing SPLUNK_PASSWORD")

        leaked = assert_no_secret_leak(result.transcript, [splunk["password"]])
        if leaked:
            artefact_problems.append("password leaked into PTY transcript")

        return ScenarioReport(
            name="snippet_only",
            ok=not artefact_problems,
            pty=result,
            notes=notes,
            artefact_problems=artefact_problems,
        )
    finally:
        cleanup_keychain_pair()


SCENARIO = Scenario(name="snippet_only", run=run)
