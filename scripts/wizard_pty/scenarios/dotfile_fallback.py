"""dotfile_fallback: keyring forced unavailable -> 0600 dotfile path.

Forces the keyring backend to ``keyring.backends.fail.Keyring`` via
``PYTHON_KEYRING_BACKEND``. The wizard's prereq check then reports
the keychain as unusable and the credstore step falls back to the
0600 dotfile under ``platformdirs.user_config_dir("spl-bridge")``.

We override ``XDG_CONFIG_HOME`` (and on macOS, also send the
fallback dir into a temp tree via ``HOME``... no, on macOS
platformdirs uses ``Library/Application Support`` independent of
HOME, so we just check the wizard's printed location and assert the
file shape there). To keep the user's machine clean, we either:
* delete the file we wrote (preferred -- it's our own ``spl-bridge``
  config dir), OR
* if the dir already had files, we only delete what we created.

Asserts:
* Wizard exits 0.
* The dotfile exists, has mode 0600, and contains
  ``SPLUNK_PASSWORD=<secret>`` literally (this is the documented
  shape; the secret only lives on the user's local disk in this
  fallback mode).
* The mcp.json STILL has no secret (writer must not regress).
"""

from __future__ import annotations

import contextlib
import os
import platform
import stat
from pathlib import Path

from . import _base
from ._base import (
    Scenario,
    ScenarioReport,
    assert_no_secret_leak,
    cleanup_backup_chain,
    cursor_config_path,
    restore,
    run_pty,
    snapshot,
    splunk_env,
    strip_ansi,
)

SERVER_NAME = "splunk-pty-dotfile"


def _expected_dotfile_path() -> Path:
    """Mirror what platformdirs.user_config_dir('spl-bridge') resolves to."""
    import platformdirs

    return Path(platformdirs.user_config_dir("spl-bridge", ensure_exists=False)) / "credentials"


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
        ("Select [1-4]:", b"1\r"),  # Cursor
    ]


def run() -> ScenarioReport:
    splunk = splunk_env()
    cursor_cfg = cursor_config_path()
    cursor_backup = snapshot(cursor_cfg)

    notes: list[str] = []
    artefact_problems: list[str] = []

    # Snapshot the dotfile (if a previous run / real user already has one).
    dotfile = _expected_dotfile_path()
    dotfile_backup = snapshot(str(dotfile))

    extra_env = {
        "NO_COLOR": "",
        # Documented escape hatch in the keyring library: pin a backend
        # by import path. ``fail.Keyring`` returns False from
        # ``is_available`` so the wizard takes the dotfile branch.
        "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
    }

    try:
        result = run_pty(
            ["spl-bridge", "setup"],
            _script(splunk),
            extra_env=extra_env,
        )
        if result.exit_status != 0:
            artefact_problems.append(f"wizard exited {result.exit_status}")

        cleaned = strip_ansi(result.transcript)
        # The wizard should explicitly inform the user.
        if "OS keychain unavailable; using 0600 dotfile fallback." not in cleaned:
            artefact_problems.append("wizard did not announce the dotfile fallback path")
        if "Backend: dotfile" not in cleaned:
            artefact_problems.append("credstore backend was not 'dotfile'")

        # Verify the dotfile.
        if not dotfile.exists():
            artefact_problems.append(f"expected dotfile at {dotfile} was not created")
        else:
            if platform.system() != "Windows":
                mode = stat.S_IMODE(dotfile.stat().st_mode)
                if mode != 0o600:
                    artefact_problems.append(f"dotfile mode is 0{mode:o}, expected 0600")
            body = dotfile.read_text(encoding="utf-8")
            if f"SPLUNK_PASSWORD={splunk['password']}" not in body:
                artefact_problems.append(
                    "dotfile did not contain SPLUNK_PASSWORD=<expected secret>"
                )
            if f"SPLUNK_USERNAME={splunk['username']}" not in body:
                artefact_problems.append("dotfile did not contain SPLUNK_USERNAME")

        # Cursor mcp.json must STILL have no secret -- writer regression test.
        if _base.os.path.exists(cursor_cfg):
            with open(cursor_cfg, encoding="utf-8") as fh:
                cfg_blob = fh.read()
            if splunk["password"] in cfg_blob:
                artefact_problems.append("password leaked into Cursor config (writer regression)")

        leaked = assert_no_secret_leak(result.transcript, [splunk["password"]])
        if leaked:
            artefact_problems.append("password leaked into PTY transcript")

        notes.append(f"dotfile path: {dotfile}")
        return ScenarioReport(
            name="dotfile_fallback",
            ok=not artefact_problems,
            pty=result,
            notes=notes,
            artefact_problems=artefact_problems,
        )
    finally:
        # Restore (or remove) the dotfile -- we are not going to leave
        # a credential file on the user's disk.
        if dotfile_backup is None:
            if dotfile.exists():
                with contextlib.suppress(OSError):
                    os.unlink(dotfile)
        else:
            restore(str(dotfile), dotfile_backup)
        cleanup_backup_chain(str(dotfile))
        restore(cursor_cfg, cursor_backup)
        cleanup_backup_chain(cursor_cfg)


SCENARIO = Scenario(name="dotfile_fallback", run=run)
