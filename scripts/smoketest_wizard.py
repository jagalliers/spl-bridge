#!/usr/bin/env python3
"""PTY-driven smoke test of `spl-bridge setup`.

This is not a unit test. It spawns the real wizard attached to a real
pseudo-terminal (via :mod:`pty`) and replays the exact keystrokes an
interactive user would type. Because the wizard runs under a real PTY,
``sys.stdin.isatty()`` is True, :func:`getpass.getpass` disables
terminal echo via real ``termios``, ANSI colors are emitted, and line
discipline translates CR -> NL on input. The wizard cannot tell the
difference between this harness and a human at the keyboard.

Target environment (lab only):
  * Splunk Enterprise on localhost:8089 (https, self-signed)
  * A Splunk user whose password you supply via ``SPLUNK_SMOKETEST_PASSWORD``.

Run with::

    SPLUNK_SMOKETEST_PASSWORD='lab-only-password' \
    python scripts/smoketest_wizard.py

Optional env knobs:
  * ``SPLUNK_SMOKETEST_HOST``     -- default ``localhost``
  * ``SPLUNK_SMOKETEST_PORT``     -- default ``8089``
  * ``SPLUNK_SMOKETEST_USERNAME`` -- default ``admin``

The script:
  1. Snapshots the real ``~/.cursor/mcp.json`` (if any) and restores it
     at the end -- we use the real HOME because stripping HOME / the env
     breaks macOS ``Security.framework``'s XPC handshake with securityd
     and the Keychain success path cannot be exercised.
  2. Drives the wizard through the username/password path with TLS
     verification explicitly disabled (matching a typical self-signed
     lab).
  3. Selects the Cursor writer (which will land in ``~/.cursor/mcp.json``).
  4. Validates post-run artefacts: the ``mcp.json`` merge, Keychain
     entries for ``SPLUNK_USERNAME`` / ``SPLUNK_PASSWORD`` under service
     ``spl-bridge``.
  5. Cleans up Keychain entries it created and restores the original
     Cursor config.

Nothing about the wizard code path is mocked.
"""

from __future__ import annotations

import contextlib
import glob
import json
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
PROMPT_TIMEOUT = 30.0  # per step
OVERALL_TIMEOUT = 120.0


def _build_script() -> list[tuple[str, bytes]]:
    """Markers + responses, driven by env so the password is never in source.

    Markers are substring matches against the PTY output with ANSI
    stripped. They are chosen to be unique in order (e.g. ``Select
    [1-3]`` only appears after the TLS verification prompt).
    """
    password = os.environ.get("SPLUNK_SMOKETEST_PASSWORD")
    if not password:
        sys.stderr.write(
            "error: SPLUNK_SMOKETEST_PASSWORD env var is required.\n"
            "       Set it to the lab Splunk password before running this harness.\n"
        )
        sys.exit(2)
    username = os.environ.get("SPLUNK_SMOKETEST_USERNAME", "admin")
    host = os.environ.get("SPLUNK_SMOKETEST_HOST", "localhost")
    port = os.environ.get("SPLUNK_SMOKETEST_PORT", "8089")

    return [
        # Step 2: Splunk connection
        ("Splunk host (FQDN or IP) [localhost]:", f"{host}\r".encode()),
        ("Splunk REST management port [8089]:", f"{port}\r".encode()),
        ("Select [1-2]:", b"1\r"),  # https (recommended)
        ("Select [1-3]:", b"3\r"),  # DISABLE verification
        ("Continue with TLS verification disabled?", b"y\r"),
        ("Select [1-2]:", b"2\r"),  # username + password
        ("Continue and send the password to this endpoint?", b"y\r"),
        ("Splunk username [admin]:", f"{username}\r".encode()),
        ("Splunk password:", password.encode() + b"\r"),  # secret (no echo)
        # Step 3: probe runs here, no input
        # Step 4: credstore (keyring is automatic, no prompt)
        # Step 5: MCP host
        ("MCP server name [splunk]:", b"splunk-wizard-smoketest\r"),
        ("Select [1-4]:", b"1\r"),  # Cursor
    ]


@dataclass
class PtyResult:
    exit_status: int
    transcript: str


def _strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def _drain_until(fd: int, marker: str, buf: bytearray, log: bytearray, deadline: float) -> bool:
    """Read from master fd until ``marker`` appears in the cleaned buffer.

    Returns True if found, False on timeout / EOF.
    """
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return False
        r, _, _ = select.select([fd], [], [], min(remaining, 1.0))
        if fd in r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                return False
            if not chunk:
                return False
            buf.extend(chunk)
            log.extend(chunk)
            cleaned = _strip_ansi(buf.decode("utf-8", errors="replace"))
            if marker in cleaned:
                return True


def run_wizard_under_pty(extra_env: dict[str, str]) -> PtyResult:
    """Fork a child running ``spl-bridge setup`` on a real PTY.

    The child inherits the parent environment verbatim (required on
    macOS so ``Security.framework`` can reach ``securityd`` via XPC and
    resolve the login keychain). ``extra_env`` is overlaid on top.
    """
    pid, fd = pty.fork()
    if pid == 0:
        # child -- inherit env, overlay only what the caller asked for.
        for k, v in extra_env.items():
            os.environ[k] = v
        try:
            os.execvp("spl-bridge", ["spl-bridge", "setup"])
        except OSError as exc:
            # Write failure to the TTY so the parent sees it.
            sys.stderr.write(f"execvp failed: {exc}\n")
            os._exit(127)

    # parent
    log = bytearray()
    buf = bytearray()
    overall_deadline = time.time() + OVERALL_TIMEOUT
    script = _build_script()
    try:
        for marker, response in script:
            step_deadline = min(time.time() + PROMPT_TIMEOUT, overall_deadline)
            found = _drain_until(fd, marker, buf, log, step_deadline)
            if not found:
                sys.stderr.write(
                    f"\n--- TIMEOUT waiting for: {marker!r} ---\n"
                    f"--- Transcript so far ---\n{_strip_ansi(log.decode('utf-8', errors='replace'))}\n"
                )
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, 9)
                os.waitpid(pid, 0)
                return PtyResult(exit_status=-1, transcript=log.decode("utf-8", errors="replace"))
            # Consume the prompt line so it cannot re-match later.
            buf.clear()
            os.write(fd, response)

        # Drain any trailing output until the process exits.
        while time.time() < overall_deadline:
            r, _, _ = select.select([fd], [], [], 1.0)
            if fd in r:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                log.extend(chunk)
            else:
                # No output; check if child exited.
                wpid, status = os.waitpid(pid, os.WNOHANG)
                if wpid != 0:
                    return PtyResult(
                        exit_status=os.waitstatus_to_exitcode(status),
                        transcript=log.decode("utf-8", errors="replace"),
                    )
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)

    # Final reap.
    try:
        _, status = os.waitpid(pid, 0)
        exit_code = os.waitstatus_to_exitcode(status)
    except ChildProcessError:
        exit_code = -1
    return PtyResult(exit_status=exit_code, transcript=log.decode("utf-8", errors="replace"))


def _keychain_has(service: str, account: str) -> bool:
    """Best-effort check that a macOS generic-password entry exists."""
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


def _keychain_delete(service: str, account: str) -> bool:
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


def _snapshot(path: str) -> str | None:
    """Copy ``path`` to a sibling ``.smoketest-bak-<ts>`` file.

    Returns the backup path if the original existed, else None.
    """
    if not os.path.exists(path):
        return None
    ts = int(time.time())
    backup = f"{path}.smoketest-bak-{ts}"
    shutil.copy2(path, backup)
    return backup


def _restore(original: str, backup: str | None) -> None:
    """Put back the snapshot we took with :func:`_snapshot`."""
    if backup is None:
        # Nothing existed before; remove anything the wizard created.
        if os.path.exists(original):
            os.unlink(original)
        return
    shutil.copy2(backup, original)


def main() -> int:
    if sys.platform != "darwin":
        print("This smoke test is tuned for macOS (login Keychain + security CLI).")
        print("On other platforms the keyring backend and CLI will differ.")

    # Back up the real Cursor config so we can verify the wizard's own
    # backup+merge behaviour and still leave the user's machine clean.
    cursor_cfg = os.path.expanduser("~/.cursor/mcp.json")
    cursor_backup = _snapshot(cursor_cfg)
    if cursor_backup:
        print(f"Snapshotted existing Cursor config -> {cursor_backup}")
    else:
        print("No existing Cursor config; wizard will create one.")

    # We inherit the real env so Security.framework can reach securityd
    # via XPC. Only overlay NO_COLOR so our ANSI matcher is a nice-to-have
    # clean stream (the matcher strips ANSI anyway).
    extra_env = {"NO_COLOR": ""}

    print("Spawning `spl-bridge setup` on a real PTY (real HOME, real env)...")
    result = run_wizard_under_pty(extra_env)

    print()
    print("=" * 72)
    print("WIZARD TRANSCRIPT (ANSI stripped)")
    print("=" * 72)
    print(_strip_ansi(result.transcript))
    print("=" * 72)
    print(f"Wizard exit code: {result.exit_status}")
    print()

    # -------- Artefact validation --------
    artefact_problems: list[str] = []

    if not os.path.exists(cursor_cfg):
        artefact_problems.append(f"Cursor config not written at {cursor_cfg}")
    else:
        with open(cursor_cfg, encoding="utf-8") as fh:
            cfg = json.load(fh)
        servers = cfg.get("mcpServers", {})
        # Print only the entry the wizard was supposed to create. The
        # surrounding `mcpServers` map may already contain unrelated
        # entries from other MCP servers the user has configured, and
        # those entries can carry secrets in their args/env (bearer
        # tokens, URLs with credentials). The harness has no business
        # echoing those to the operator's terminal.
        entry = servers.get("splunk-wizard-smoketest")
        print(f"Cursor config at {cursor_cfg} (showing splunk-wizard-smoketest entry only):")
        if entry is not None:
            print(json.dumps({"mcpServers": {"splunk-wizard-smoketest": entry}}, indent=2))
        else:
            print("  (entry missing -- see validation below)")
        if "splunk-wizard-smoketest" not in servers:
            artefact_problems.append("Cursor config missing `splunk-wizard-smoketest` entry")
        else:
            entry = servers["splunk-wizard-smoketest"]
            env_out = entry.get("env", {})
            if env_out.get("SPLUNK_HOST") != "localhost":
                artefact_problems.append(f"SPLUNK_HOST wrong: {env_out.get('SPLUNK_HOST')}")
            if env_out.get("SPLUNK_PORT") != "8089":
                artefact_problems.append(f"SPLUNK_PORT wrong: {env_out.get('SPLUNK_PORT')}")
            if env_out.get("SPLUNK_SCHEME") != "https":
                artefact_problems.append(f"SPLUNK_SCHEME wrong: {env_out.get('SPLUNK_SCHEME')}")
            if env_out.get("SPLUNK_VERIFY_SSL") != "false":
                artefact_problems.append(
                    f"SPLUNK_VERIFY_SSL wrong: {env_out.get('SPLUNK_VERIFY_SSL')}"
                )
            # Critical: secrets must NOT appear in the client config.
            secret_needles = ["SPLUNK_PASSWORD", "SPLUNK_TOKEN"]
            pw = os.environ.get("SPLUNK_SMOKETEST_PASSWORD")
            if pw:
                secret_needles.append(pw)
            for banned in secret_needles:
                blob = json.dumps(entry)
                if banned in blob:
                    artefact_problems.append("Secret leaked into Cursor config")

    print()
    print("Checking Keychain entries (service=spl-bridge)...")
    has_user = _keychain_has("spl-bridge", "SPLUNK_USERNAME")
    has_pass = _keychain_has("spl-bridge", "SPLUNK_PASSWORD")
    print(f"  SPLUNK_USERNAME present: {has_user}")
    print(f"  SPLUNK_PASSWORD present: {has_pass}")
    if not has_user:
        artefact_problems.append("Keychain missing SPLUNK_USERNAME")
    if not has_pass:
        artefact_problems.append("Keychain missing SPLUNK_PASSWORD")

    # Secret redaction sanity: the password must never appear in the
    # transcript the wizard prints, even with color codes stripped.
    pw = os.environ.get("SPLUNK_SMOKETEST_PASSWORD")
    if pw and pw in _strip_ansi(result.transcript):
        artefact_problems.append("Password echoed to PTY (should be invisible under getpass)")

    # -------- Cleanup --------
    print()
    print("Cleaning up Keychain entries we created...")
    _keychain_delete("spl-bridge", "SPLUNK_USERNAME")
    _keychain_delete("spl-bridge", "SPLUNK_PASSWORD")
    print("Restoring original Cursor config...")
    _restore(cursor_cfg, cursor_backup)
    if cursor_backup:
        # Remove the .smoketest-bak-<ts> copy now that we've restored.
        with contextlib.suppress(OSError):
            os.unlink(cursor_backup)
    # Also sweep the wizard's own .bak.<timestamp> file -- otherwise
    # every run leaves a stale copy next to the restored config.
    for stale in glob.glob(f"{cursor_cfg}.bak.*"):
        with contextlib.suppress(OSError):
            os.unlink(stale)

    print()
    if result.exit_status != 0:
        print(f"FAIL: wizard exited {result.exit_status}")
        return 1
    if artefact_problems:
        print("FAIL: artefact problems:")
        for p in artefact_problems:
            print(f"  - {p}")
        return 1
    print("PASS: wizard completed, artefacts look correct, no secret leakage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
