"""Tiny TTY UI helpers for the setup wizard.

All output goes to stderr (stdout is reserved for MCP JSON-RPC framing in
the rest of the package -- the wizard never runs concurrently with the
server, but the convention keeps writes out of any pipe a parent might
attach by accident).

Refuses to run when stdin is not a TTY: the wizard must never be driven
by an unattended pipe because that would mean someone is trying to feed
secrets through redirection.
"""

from __future__ import annotations

import getpass
import os
import sys
from collections.abc import Iterable, Sequence

# ANSI escapes only when stderr is a TTY and the user hasn't opted out.
_USE_COLOR = sys.stderr.isatty() and os.environ.get("NO_COLOR", "") == ""


def _wrap(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def bold(text: str) -> str:
    return _wrap("1", text)


def dim(text: str) -> str:
    return _wrap("2", text)


def green(text: str) -> str:
    return _wrap("32", text)


def yellow(text: str) -> str:
    return _wrap("33", text)


def red(text: str) -> str:
    return _wrap("31", text)


def cyan(text: str) -> str:
    return _wrap("36", text)


def heading(text: str) -> None:
    print(file=sys.stderr)
    print(bold(cyan(f"== {text} ==")), file=sys.stderr)


def ok(text: str) -> None:
    print(f"  {green('✓')} {text}", file=sys.stderr)


def warn(text: str) -> None:
    print(f"  {yellow('!')} {text}", file=sys.stderr)


def fail(text: str) -> None:
    print(f"  {red('✗')} {text}", file=sys.stderr)


def info(text: str) -> None:
    print(f"  {dim('·')} {text}", file=sys.stderr)


class WizardAbortError(RuntimeError):
    """Raised when the wizard cannot continue (non-TTY, user abort, etc)."""


def require_tty() -> None:
    """Hard fail if stdin is not a TTY.

    Setup must be interactive: secrets are not allowed to flow through
    a pipe (no shell history, no log capture, no scripted misuse).
    """
    if not sys.stdin.isatty():
        raise WizardAbortError(
            "spl-bridge setup must run on an interactive terminal. "
            "Stdin is not a TTY -- refusing to read secrets from a pipe."
        )


def ask(prompt: str, default: str | None = None) -> str:
    """Prompt for free-form input. Empty input -> default if provided."""
    suffix = f" [{default}]" if default else ""
    line = input(f"{prompt}{suffix}: ").strip()
    if not line and default is not None:
        return default
    return line


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        line = input(f"{prompt} ({hint}): ").strip().lower()
        if not line:
            return default
        if line in ("y", "yes"):
            return True
        if line in ("n", "no"):
            return False
        warn("Please answer yes or no.")


def ask_choice(prompt: str, choices: Sequence[str], default: int = 0) -> str:
    """Numbered choice prompt. Returns the chosen string."""
    if not choices:
        raise ValueError("ask_choice requires at least one choice")
    print(f"{prompt}", file=sys.stderr)
    for idx, choice in enumerate(choices, 1):
        marker = " (default)" if idx - 1 == default else ""
        print(f"    {idx}) {choice}{marker}", file=sys.stderr)
    while True:
        raw = input(f"  Select [1-{len(choices)}]: ").strip()
        if not raw:
            return choices[default]
        try:
            idx = int(raw)
        except ValueError:
            warn(f"Enter a number between 1 and {len(choices)}.")
            continue
        if 1 <= idx <= len(choices):
            return choices[idx - 1]
        warn(f"Enter a number between 1 and {len(choices)}.")


def ask_secret(prompt: str, *, allow_empty: bool = False) -> str:
    """Prompt for a secret without echoing.

    Uses :func:`getpass.getpass` so the value is never printed back.
    """
    while True:
        value = getpass.getpass(f"{prompt}: ")
        if value or allow_empty:
            return value
        warn("Value cannot be empty.")


def ask_literal(prompt: str, expected: str) -> bool:
    """Require the user to type ``expected`` verbatim (case-sensitive)."""
    line = input(f"{prompt} (type {expected!r} to confirm): ")
    return line == expected


def list_steps(steps: Iterable[str]) -> None:
    """Print a numbered overview of the wizard steps."""
    info("Wizard steps:")
    for idx, step in enumerate(steps, 1):
        print(f"      {idx}. {step}", file=sys.stderr)
