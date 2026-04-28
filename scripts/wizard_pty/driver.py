"""PtyDriver -- spawn the wizard on a real pseudo-terminal.

The driver fork+execvp's ``spl-bridge setup`` (or any provided argv)
on a master/slave PTY pair, then runs the standard "wait for marker,
write response" loop until the script is exhausted or the child
exits. ANSI escape sequences are stripped from the matching buffer
so wizard color output doesn't interfere with the markers.

Why a PTY: the wizard checks ``sys.stdin.isatty()`` and refuses to
run on a pipe (deliberate -- secrets must not flow through
redirection). Running under :mod:`pty` makes the wizard see a
genuine controlling terminal, which means
:func:`getpass.getpass` disables echo via real ``termios``,
:func:`input` uses readline, and the ANSI color path runs.

The driver inherits the parent environment verbatim (overlaying
only the caller's ``extra_env``). On macOS this is mandatory for
``Security.framework`` to reach ``securityd`` over XPC, which is in
turn required for the keyring write path.
"""

from __future__ import annotations

import contextlib
import os
import pty
import re
import select
import sys
import time
from dataclasses import dataclass

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Per-prompt and overall timeouts. Each scenario can override via
# its driver kwargs if it expects a longer probe.
DEFAULT_PROMPT_TIMEOUT_S = 30.0
DEFAULT_OVERALL_TIMEOUT_S = 120.0


def strip_ansi(s: str) -> str:
    """Drop ANSI CSI sequences so prompt matching is text-only."""
    return ANSI_RE.sub("", s)


@dataclass
class PtyResult:
    """Outcome of a single wizard run under the PTY harness."""

    exit_status: int
    transcript: str
    timed_out_on: str | None = None  # marker that timed out, if any


def _drain_until(
    fd: int,
    marker: str,
    buf: bytearray,
    log: bytearray,
    deadline: float,
) -> bool:
    """Read from *fd* until the (ANSI-stripped) buffer contains *marker*.

    Returns True when found, False on timeout or EOF.
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
            cleaned = strip_ansi(buf.decode("utf-8", errors="replace"))
            if marker in cleaned:
                return True


def run_pty(
    argv: list[str],
    script: list[tuple[str, bytes]],
    *,
    extra_env: dict[str, str] | None = None,
    prompt_timeout_s: float = DEFAULT_PROMPT_TIMEOUT_S,
    overall_timeout_s: float = DEFAULT_OVERALL_TIMEOUT_S,
) -> PtyResult:
    """Run *argv* on a real PTY and replay *script*.

    Each script entry is ``(marker, response_bytes)`` -- the driver
    waits for ``marker`` to appear in the transcript (ANSI stripped),
    then writes ``response_bytes`` to the master fd.

    Markers must be unique in their wait window; the driver clears
    the rolling buffer after each successful match so a marker like
    ``"Select [1-2]:"`` (which appears multiple times) still works
    in order.
    """
    extra_env = extra_env or {}
    pid, fd = pty.fork()
    if pid == 0:
        # CHILD: inherit env, overlay only what the caller asked for.
        # We deliberately do NOT clear os.environ -- on macOS that
        # would break Security.framework's XPC handshake with
        # securityd and prevent any keyring write from succeeding.
        for k, v in extra_env.items():
            os.environ[k] = v
        try:
            # noqa: S606 -- starting a process without a shell is
            # the correct primitive for this PTY harness; the
            # binary is on PATH by design.
            os.execvp(argv[0], argv)
        except OSError as exc:
            sys.stderr.write(f"execvp failed: {exc}\n")
            os._exit(127)

    # PARENT
    log = bytearray()
    buf = bytearray()
    overall_deadline = time.time() + overall_timeout_s
    timed_out_on: str | None = None
    try:
        for marker, response in script:
            step_deadline = min(time.time() + prompt_timeout_s, overall_deadline)
            found = _drain_until(fd, marker, buf, log, step_deadline)
            if not found:
                timed_out_on = marker
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, 9)
                os.waitpid(pid, 0)
                return PtyResult(
                    exit_status=-1,
                    transcript=log.decode("utf-8", errors="replace"),
                    timed_out_on=timed_out_on,
                )
            # Consume the prompt line so it cannot re-match later.
            buf.clear()
            os.write(fd, response)

        # Drain trailing output until the child exits or we run out of
        # overall time.
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
                wpid, status = os.waitpid(pid, os.WNOHANG)
                if wpid != 0:
                    return PtyResult(
                        exit_status=os.waitstatus_to_exitcode(status),
                        transcript=log.decode("utf-8", errors="replace"),
                    )
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)

    try:
        _, status = os.waitpid(pid, 0)
        exit_code = os.waitstatus_to_exitcode(status)
    except ChildProcessError:
        exit_code = -1
    return PtyResult(
        exit_status=exit_code,
        transcript=log.decode("utf-8", errors="replace"),
        timed_out_on=timed_out_on,
    )


def assert_no_secret_leak(transcript: str, secrets: list[str]) -> list[str]:
    """Check that none of *secrets* appear in the (ANSI-stripped) transcript.

    Returns a list of secrets that DID leak. Empty list = OK. The
    caller decides whether to treat a non-empty list as fatal.
    """
    cleaned = strip_ansi(transcript)
    return [s for s in secrets if s and s in cleaned]
