"""Unit tests for ``spl_bridge.setup_wizard.ui``.

These cover every prompt and helper without spinning up a PTY.
The full PTY-driven wizard end-to-end coverage lives in
``tests/test_wizard_pty_scenarios.py`` (opt-in); this file is the
fast unit half.

Why both layers exist:

* The PTY scenarios prove the wizard *as a whole* behaves correctly
  on a real terminal -- they catch issues the unit tests can't see
  (Keychain interaction, ANSI handling, getpass behavior on a real
  tty).
* These unit tests pin the helper API: empty input + default,
  numeric out-of-range in ``ask_choice``, secret retry on empty,
  ``ask_literal`` exact-match semantics, ``WizardAbortError`` on
  non-tty stdin.

If a future refactor changes a UI helper signature, these tests
fail in milliseconds instead of waiting on the PTY suite.
"""

from __future__ import annotations

import io
import sys
from collections.abc import Iterator

import pytest

from spl_bridge.setup_wizard import ui

# ---------------------------------------------------------------------------
# Color wrapping
# ---------------------------------------------------------------------------


def test_wrap_no_color_when_module_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """When _USE_COLOR is False the wrapper returns the text unchanged.
    Exercising both branches matters because the ANSI escape path runs
    on developer terminals; the no-color path runs in CI logs."""
    monkeypatch.setattr(ui, "_USE_COLOR", False)
    assert ui._wrap("31", "hello") == "hello"
    # All semantic helpers must defer to the wrapper.
    assert ui.bold("x") == "x"
    assert ui.dim("x") == "x"
    assert ui.green("x") == "x"
    assert ui.yellow("x") == "x"
    assert ui.red("x") == "x"
    assert ui.cyan("x") == "x"


def test_wrap_emits_ansi_when_module_flag_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ui, "_USE_COLOR", True)
    out = ui._wrap("31", "danger")
    assert out.startswith("\x1b[31m")
    assert out.endswith("\x1b[0m")
    assert "danger" in out


# ---------------------------------------------------------------------------
# Stdout-vs-stderr discipline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fn,arg",
    [
        (ui.heading, "Section"),
        (ui.ok, "looks good"),
        (ui.warn, "be careful"),
        (ui.fail, "broke"),
        (ui.info, "fyi"),
    ],
)
def test_status_helpers_go_to_stderr(fn, arg: str, capsys: pytest.CaptureFixture[str]) -> None:
    """The wizard runs a non-MCP CLI but we keep the convention --
    stdout is reserved across the package, status output goes to
    stderr only. A regression here would let prompts leak into a
    pipe one day."""
    fn(arg)
    captured = capsys.readouterr()
    assert captured.out == "", f"{fn.__name__!r} wrote to stdout: {captured.out!r}"
    assert arg in captured.err


def test_list_steps_writes_numbered_list(capsys: pytest.CaptureFixture[str]) -> None:
    ui.list_steps(["alpha", "beta", "gamma"])
    err = capsys.readouterr().err
    # The header info() line + three numbered entries.
    assert "Wizard steps:" in err
    assert "1. alpha" in err
    assert "2. beta" in err
    assert "3. gamma" in err


# ---------------------------------------------------------------------------
# require_tty
# ---------------------------------------------------------------------------


class _FakeStdin:
    def __init__(self, isatty: bool) -> None:
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


def test_require_tty_passes_when_isatty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", _FakeStdin(True))
    ui.require_tty()  # must not raise


def test_require_tty_aborts_when_not_a_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", _FakeStdin(False))
    with pytest.raises(ui.WizardAbortError, match="not a TTY"):
        ui.require_tty()


# ---------------------------------------------------------------------------
# ask / ask_yes_no / ask_choice / ask_secret / ask_literal
# ---------------------------------------------------------------------------


def _patch_input(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> None:
    """Replace builtins.input with an iterator over ``answers``."""
    it: Iterator[str] = iter(answers)

    def fake_input(_prompt: str = "") -> str:
        try:
            return next(it)
        except StopIteration as e:
            raise AssertionError("input() called more times than scripted") from e

    monkeypatch.setattr("builtins.input", fake_input)


def test_ask_returns_default_on_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_input(monkeypatch, [""])
    assert ui.ask("Host", default="localhost") == "localhost"


def test_ask_returns_user_value_when_provided(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_input(monkeypatch, ["splunk.example.test"])
    assert ui.ask("Host", default="localhost") == "splunk.example.test"


def test_ask_no_default_returns_stripped_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_input(monkeypatch, ["  whitespace  "])
    assert ui.ask("Username") == "whitespace"


@pytest.mark.parametrize(
    "answers,default,expected",
    [
        (["y"], False, True),
        (["yes"], False, True),
        (["n"], True, False),
        (["no"], True, False),
        ([""], True, True),  # empty -> default
        ([""], False, False),
    ],
)
def test_ask_yes_no_happy_paths(
    monkeypatch: pytest.MonkeyPatch, answers: list[str], default: bool, expected: bool
) -> None:
    _patch_input(monkeypatch, answers)
    assert ui.ask_yes_no("Continue?", default=default) is expected


def test_ask_yes_no_rejects_garbage_then_accepts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_input(monkeypatch, ["maybe", "y"])
    assert ui.ask_yes_no("Continue?", default=False) is True
    err = capsys.readouterr().err
    assert "yes or no" in err


def test_ask_choice_default_on_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_input(monkeypatch, [""])
    assert ui.ask_choice("Pick one", ["alpha", "beta", "gamma"], default=1) == "beta"


def test_ask_choice_numeric_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_input(monkeypatch, ["3"])
    assert ui.ask_choice("Pick one", ["alpha", "beta", "gamma"]) == "gamma"


def test_ask_choice_rejects_non_numeric_then_accepts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_input(monkeypatch, ["nope", "1"])
    assert ui.ask_choice("Pick one", ["alpha", "beta"]) == "alpha"
    err = capsys.readouterr().err
    assert "between 1 and 2" in err


def test_ask_choice_rejects_out_of_range_then_accepts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_input(monkeypatch, ["99", "2"])
    assert ui.ask_choice("Pick one", ["alpha", "beta"]) == "beta"
    err = capsys.readouterr().err
    assert "between 1 and 2" in err


def test_ask_choice_empty_choices_raises() -> None:
    with pytest.raises(ValueError, match="at least one choice"):
        ui.ask_choice("Pick one", [])


def test_ask_secret_returns_value(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter(["s3cret"])
    monkeypatch.setattr(
        "spl_bridge.setup_wizard.ui.getpass.getpass",
        lambda _prompt: next(answers),
    )
    assert ui.ask_secret("Password") == "s3cret"


def test_ask_secret_rejects_empty_then_accepts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter(["", "secondtry"])
    monkeypatch.setattr(
        "spl_bridge.setup_wizard.ui.getpass.getpass",
        lambda _prompt: next(answers),
    )
    assert ui.ask_secret("Password") == "secondtry"
    err = capsys.readouterr().err
    assert "cannot be empty" in err


def test_ask_secret_allow_empty_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "spl_bridge.setup_wizard.ui.getpass.getpass",
        lambda _prompt: "",
    )
    assert ui.ask_secret("Password", allow_empty=True) == ""


def test_ask_literal_exact_match(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_input(monkeypatch, ["DELETE"])
    assert ui.ask_literal("Type DELETE to confirm", "DELETE") is True


def test_ask_literal_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_input(monkeypatch, ["delete"])  # case-sensitive
    assert ui.ask_literal("Type DELETE to confirm", "DELETE") is False


# ---------------------------------------------------------------------------
# Smoke: real stdout buffer never receives any UI bytes
# ---------------------------------------------------------------------------


def test_full_session_keeps_stdout_pristine(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Defense in depth -- run a sequence of typical wizard helpers
    and assert that stdout buffer is bytewise empty afterwards.
    Catches a regression where someone sneaks a ``print(...)`` (no
    file=) into a helper down the line."""
    _patch_input(monkeypatch, ["", "y"])
    monkeypatch.setattr("spl_bridge.setup_wizard.ui.getpass.getpass", lambda _p: "shh")
    # Replace stdout with a strict watcher so even a single byte
    # escapes us.
    fake_stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    ui.heading("Splunk")
    ui.info("starting")
    ui.ok("connected")
    ui.warn("token will expire soon")
    ui.fail("nope")
    ui.list_steps(["a", "b"])
    assert ui.ask("Host", default="localhost") == "localhost"
    assert ui.ask_yes_no("Proceed?") is True
    assert ui.ask_secret("Password") == "shh"

    assert fake_stdout.getvalue() == "", f"UI helpers wrote to stdout: {fake_stdout.getvalue()!r}"
