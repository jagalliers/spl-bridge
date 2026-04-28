"""Tests for ``spl-bridge doctor``.

The doctor command is the operator's first move when something goes
wrong, so it has to behave predictably:

* Emit only via the logger (never print to stdout, which would
  corrupt MCP framing if the caller piped both commands through the
  same process).
* Exit 0 when every check passes.
* Exit 1 when any check fails, with the failure surfaced in stderr.
* Use the curated SplunkClient (so 401s and connection errors get
  the same operator-friendly classification the MCP server uses).

These tests stub the network surface (``requests.get`` for the TLS
probe, ``SplunkClient.call_api`` for the four REST checks) so they
run in milliseconds against no real Splunk.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import MagicMock

import pytest

from spl_bridge import doctor


def _ok_response(payload: dict[str, Any] | str = "") -> MagicMock:
    """Build a fake ``requests.Response``-like object whose
    ``status_code`` is 200 and whose ``.text`` and ``.json()`` return
    the supplied payload.
    """
    resp = MagicMock()
    resp.status_code = 200
    if isinstance(payload, dict):
        resp.text = json.dumps(payload)
        resp.json.return_value = payload
    else:
        resp.text = payload or "non-empty"
        resp.json.return_value = {}
    return resp


def _patch_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide the minimum env doctor needs to load
    ``SplunkMCPConfig.from_env()`` cleanly. Token mode keeps the
    fixture small and avoids touching the real keychain.
    """
    monkeypatch.setenv("SPLUNK_HOST", "splunk.example.test")
    monkeypatch.setenv("SPLUNK_PORT", "8089")
    monkeypatch.setenv("SPLUNK_SCHEME", "https")
    monkeypatch.setenv("SPLUNK_VERIFY_SSL", "false")
    monkeypatch.setenv("SPLUNK_TOKEN", "fake-token-for-test")  # noqa: S105


def test_run_doctor_happy_path(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """All four checks succeed -> ``run_doctor`` returns normally
    (no SystemExit) and logs each step."""
    _patch_env(monkeypatch)

    fake_client = MagicMock()
    # current-context returns a username so the auth-OK log line
    # has something to format.
    fake_client.call_api.side_effect = [
        _ok_response({"entry": [{"content": {"username": "doctor-test"}}]}),
        _ok_response({}),
        _ok_response("a non-empty body"),
    ]
    monkeypatch.setattr(doctor, "SplunkClient", lambda _config: fake_client)
    # TLS probe -- just needs to not raise.
    monkeypatch.setattr(doctor.requests, "get", lambda *a, **kw: _ok_response({}))

    # Capture spl_bridge's logger output -- doctor goes through
    # ``configure_logging()`` which sets ``propagate=False`` on the
    # root spl_bridge logger, so we attach caplog's handler directly.
    splunk_logger = logging.getLogger("spl_bridge.doctor")
    splunk_logger.addHandler(caplog.handler)
    splunk_logger.setLevel(logging.INFO)
    try:
        with caplog.at_level(logging.INFO, logger="spl_bridge.doctor"):
            doctor.run_doctor()
    finally:
        splunk_logger.removeHandler(caplog.handler)

    messages = [r.getMessage() for r in caplog.records]
    # Must reach the final "All checks passed" line.
    assert any("All checks passed" in m for m in messages), messages
    # Must report the username from current-context.
    assert any("doctor-test" in m for m in messages), messages
    # Stdout must be untouched -- doctor must never write to it
    # because it's reserved for MCP framing if anything pipes the
    # process.
    captured = capsys.readouterr()
    assert captured.out == "", f"doctor leaked to stdout: {captured.out!r}"


def test_run_doctor_tls_failure_exits_1(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If the TLS probe raises, run_doctor catches and exits 1
    rather than propagating an uncaught exception. We assert the
    error is logged before exit."""
    _patch_env(monkeypatch)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise ConnectionError("could not connect")

    monkeypatch.setattr(doctor.requests, "get", boom)

    splunk_logger = logging.getLogger("spl_bridge.doctor")
    splunk_logger.addHandler(caplog.handler)
    splunk_logger.setLevel(logging.INFO)
    try:
        with (
            caplog.at_level(logging.ERROR, logger="spl_bridge.doctor"),
            pytest.raises(SystemExit) as excinfo,
        ):
            doctor.run_doctor()
    finally:
        splunk_logger.removeHandler(caplog.handler)

    assert excinfo.value.code == 1
    messages = [r.getMessage() for r in caplog.records]
    assert any("Doctor failed" in m for m in messages), messages


def test_check_current_context_non_200_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """The internal helper turns any non-200 into a RuntimeError so
    run_doctor's catch-all logs a specific message instead of an
    obscure ``json``/``KeyError`` traceback."""
    _patch_env(monkeypatch)
    fake_client = MagicMock()
    fake_client.call_api.return_value = MagicMock(status_code=403)
    with pytest.raises(RuntimeError, match="HTTP 403"):
        doctor._check_current_context(fake_client)


def test_check_export_empty_body_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """The export endpoint can return 200 with no body when there is
    a tenant/role misconfiguration. Doctor must surface that as a
    failure -- a 200/empty would otherwise silently pass."""
    _patch_env(monkeypatch)
    fake_client = MagicMock()
    fake_client.call_api.return_value = MagicMock(status_code=200, text="   \n")
    with pytest.raises(RuntimeError, match="empty body"):
        doctor._check_export(fake_client)


def test_check_parser_non_200_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_env(monkeypatch)
    fake_client = MagicMock()
    fake_client.call_api.return_value = MagicMock(status_code=500)
    with pytest.raises(RuntimeError, match="parser endpoint failed"):
        doctor._check_parser(fake_client)
