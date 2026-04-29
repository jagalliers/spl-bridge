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
from pathlib import Path
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


# ---------------------------------------------------------------------------
# `spl-bridge doctor --hosts` -- MCP host config audit
# ---------------------------------------------------------------------------
#
# Same logger-attachment dance as the Splunk-REST tests above: the
# spl_bridge logger is intentionally non-propagating, so we attach
# caplog's handler directly to the doctor logger to capture warning
# records.


def _attach_doctor_logger(caplog: pytest.LogCaptureFixture) -> logging.Logger:
    splunk_logger = logging.getLogger("spl_bridge.doctor")
    splunk_logger.addHandler(caplog.handler)
    splunk_logger.setLevel(logging.INFO)
    return splunk_logger


def _redirect_doctor_paths(
    monkeypatch: pytest.MonkeyPatch,
    cursor_path: Path,
    claude_path: Path,
    project_path: Path | None = None,
) -> None:
    """Point the doctor's host-config resolvers at tmp_path-rooted
    files so the scan never touches the real user's machine.

    ``project_path`` defaults to ``None`` -- in which case the
    project-scope walk in ``run_host_scan`` is forced to return
    ``None`` so existing tests (written before the scan grew
    project-scope awareness) keep their original behaviour. When a
    ``project_path`` is provided, the walk helper is stubbed to return
    that exact path so the test can drive the project-scope branch
    deterministically without depending on the test runner's cwd.
    """
    monkeypatch.setattr(doctor, "cursor_config_path", lambda: cursor_path)
    monkeypatch.setattr(doctor, "claude_desktop_config_path", lambda: claude_path)
    monkeypatch.setattr(doctor, "find_cursor_project_config", lambda: project_path)


class TestRunHostScan:
    """Coverage for the new ``--hosts`` flag.

    The scan must:
    * be silent-but-OK when no configs exist (user just hasn't
      configured any MCP host yet -- not an error);
    * recognize and approve absolute spl-bridge command paths;
    * warn (and exit 1) on bare spl-bridge basenames, since those
      will fail to launch from PATH-stripped GUI hosts;
    * leave third-party MCP entries (npx, python, anything not named
      spl-bridge) entirely alone -- we are not the npx-hygiene police;
    * tolerate malformed JSON / empty files / missing mcpServers
      sections without exploding.
    """

    def test_no_configs_present_is_clean(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "cursor" / "mcp.json"
        claude_path = tmp_path / "claude" / "claude_desktop_config.json"
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with caplog.at_level(logging.INFO, logger="spl_bridge.doctor"):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        messages = [r.getMessage() for r in caplog.records]
        assert any("All scanned MCP host configs look healthy" in m for m in messages)
        assert any("nothing to scan" in m for m in messages), messages

    def test_absolute_paths_in_both_configs_is_clean(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text(
            json.dumps(
                {"mcpServers": {"splunk": {"command": "/opt/homebrew/bin/spl-bridge", "args": []}}}
            )
        )
        claude_path = tmp_path / "claude.json"
        claude_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "splunk-prod": {
                            "command": "/Users/alice/.local/bin/spl-bridge",
                            "args": [],
                        }
                    }
                }
            )
        )
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with caplog.at_level(logging.INFO, logger="spl_bridge.doctor"):
                doctor.run_host_scan()  # must NOT raise SystemExit
        finally:
            wizard_logger.removeHandler(caplog.handler)
        messages = [r.getMessage() for r in caplog.records]
        # Both entries should be acknowledged as OK.
        assert any("absolute command /opt/homebrew/bin/spl-bridge" in m for m in messages), messages
        assert any("absolute command /Users/alice/.local/bin/spl-bridge" in m for m in messages), (
            messages
        )
        # No warning records at all.
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == [], f"unexpected warnings: {[r.getMessage() for r in warnings]}"

    def test_bare_command_in_cursor_warns_and_exits_1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text(
            json.dumps({"mcpServers": {"splunk": {"command": "spl-bridge", "args": []}}})
        )
        claude_path = tmp_path / "claude.json"  # missing -- should be silent
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with (
                caplog.at_level(logging.INFO, logger="spl_bridge.doctor"),
                pytest.raises(SystemExit) as excinfo,
            ):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        assert excinfo.value.code == 1
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("bare command 'spl-bridge'" in m for m in warning_msgs), warning_msgs
        assert any("Re-run `spl-bridge setup`" in m for m in warning_msgs), warning_msgs
        assert any("Cursor:" in m for m in warning_msgs), warning_msgs

    def test_bare_command_in_claude_desktop_warns_and_exits_1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "mcp.json"  # missing
        claude_path = tmp_path / "claude.json"
        claude_path.write_text(
            json.dumps({"mcpServers": {"splunk": {"command": "spl-bridge", "args": []}}})
        )
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with (
                caplog.at_level(logging.INFO, logger="spl_bridge.doctor"),
                pytest.raises(SystemExit) as excinfo,
            ):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        assert excinfo.value.code == 1
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("Claude Desktop:" in m for m in warning_msgs), warning_msgs

    def test_non_spl_bridge_entries_are_ignored(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """We are not the npx-hygiene police -- third-party MCP entries
        (npx, python, ./my-script) are silently skipped even when bare.
        """
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "filesystem": {"command": "npx", "args": ["-y", "fs-mcp"]},
                        "custom": {"command": "./my-mcp-server.py", "args": []},
                        "alsoCustom": {"command": "python", "args": ["server.py"]},
                    }
                }
            )
        )
        claude_path = tmp_path / "claude.json"
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with caplog.at_level(logging.INFO, logger="spl_bridge.doctor"):
                doctor.run_host_scan()  # no SystemExit
        finally:
            wizard_logger.removeHandler(caplog.handler)
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == [], (
            f"third-party entries triggered unexpected warnings: "
            f"{[r.getMessage() for r in warnings]}"
        )
        # Should explicitly note that no spl-bridge entries were found.
        infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
        assert any("no spl-bridge entries" in m for m in infos), infos

    def test_invalid_json_warns_and_exits_1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text("{not valid json")
        claude_path = tmp_path / "claude.json"
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with (
                caplog.at_level(logging.INFO, logger="spl_bridge.doctor"),
                pytest.raises(SystemExit) as excinfo,
            ):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        assert excinfo.value.code == 1
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("not valid JSON" in m for m in warning_msgs), warning_msgs

    def test_empty_file_is_treated_as_clean(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text("   \n")
        claude_path = tmp_path / "claude.json"
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with caplog.at_level(logging.INFO, logger="spl_bridge.doctor"):
                doctor.run_host_scan()  # no SystemExit
        finally:
            wizard_logger.removeHandler(caplog.handler)
        messages = [r.getMessage() for r in caplog.records]
        assert any("is empty" in m for m in messages), messages

    def test_no_mcpservers_section_is_treated_as_clean(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text(json.dumps({"someOtherKey": True}))
        claude_path = tmp_path / "claude.json"
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with caplog.at_level(logging.INFO, logger="spl_bridge.doctor"):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        messages = [r.getMessage() for r in caplog.records]
        assert any("no mcpServers section" in m for m in messages), messages

    def test_array_top_level_warns(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text(json.dumps([{"command": "spl-bridge"}]))
        claude_path = tmp_path / "claude.json"
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with (
                caplog.at_level(logging.INFO, logger="spl_bridge.doctor"),
                pytest.raises(SystemExit) as excinfo,
            ):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        assert excinfo.value.code == 1
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("not a JSON object" in m for m in warning_msgs), warning_msgs

    def test_both_hosts_bare_two_warnings(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text(json.dumps({"mcpServers": {"splunk": {"command": "spl-bridge"}}}))
        claude_path = tmp_path / "claude.json"
        claude_path.write_text(json.dumps({"mcpServers": {"splunk": {"command": "spl-bridge"}}}))
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with (
                caplog.at_level(logging.INFO, logger="spl_bridge.doctor"),
                pytest.raises(SystemExit) as excinfo,
            ):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        assert excinfo.value.code == 1
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        # One per host plus the rolled-up "Found 2" error.
        bare_warnings = [m for m in warning_msgs if "bare command 'spl-bridge'" in m]
        assert len(bare_warnings) == 2, bare_warnings
        assert any("Found 2 MCP host config issue(s)" in m for m in warning_msgs), warning_msgs

    def test_stdout_is_not_touched(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Same invariant as ``run_doctor``: never write to stdout, since
        a caller may be piping a follow-up ``serve`` invocation through
        the same process.
        """
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text(
            json.dumps({"mcpServers": {"splunk": {"command": "/opt/homebrew/bin/spl-bridge"}}})
        )
        claude_path = tmp_path / "claude.json"
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        doctor.run_host_scan()
        captured = capsys.readouterr()
        assert captured.out == "", f"host scan leaked to stdout: {captured.out!r}"


class TestRunHostScanProjectShadow:
    """Coverage for the project-scope ``.cursor/mcp.json`` arm of
    ``--hosts``. The doctor must:

    * Recognize a discovered project-scope config and run the same
      basenames-must-be-absolute audit on it that user-scope already
      gets, so a bare ``spl-bridge`` in a checked-in project config
      is reported.
    * Detect name shadowing -- any server name that appears in BOTH
      the user-scope file (which the wizard writes to) and the project
      file (which Cursor lets win on collision). This is the new
      diagnostic that converts "I ran setup but Cursor still uses the
      old server" support tickets into a one-line self-diagnosis.
    * Stay silent when there's no project file or when there's no
      collision -- false-positive warnings would just train operators
      to ignore the new line.
    """

    def test_no_project_config_keeps_old_behaviour(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Default project_path=None means find_cursor_project_config
        # returns None -- the doctor should not emit any new
        # project-scope log lines.
        cursor_path = tmp_path / "mcp.json"
        cursor_path.write_text(
            json.dumps({"mcpServers": {"splunk": {"command": "/opt/homebrew/bin/spl-bridge"}}})
        )
        claude_path = tmp_path / "claude.json"
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with caplog.at_level(logging.INFO, logger="spl_bridge.doctor"):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        messages = [r.getMessage() for r in caplog.records]
        # No project-scope log line at all.
        assert not any("Cursor (project)" in m for m in messages), messages
        assert not any("shadow" in m.lower() for m in messages), messages

    def test_project_config_with_collision_warns_shadow(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cursor_path = tmp_path / "user_mcp.json"
        cursor_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "splunk": {"command": "/opt/homebrew/bin/spl-bridge"},
                        "filesystem": {"command": "npx"},
                    }
                }
            )
        )
        claude_path = tmp_path / "claude.json"
        project_path = tmp_path / "proj_mcp.json"
        project_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        # Same name as user scope -> shadowing warning.
                        "splunk": {"command": "/opt/homebrew/bin/spl-bridge"},
                        # Different name -> no shadow warning for this one.
                        "another": {"command": "/usr/local/bin/another"},
                    }
                }
            )
        )
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path, project_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with (
                caplog.at_level(logging.INFO, logger="spl_bridge.doctor"),
                pytest.raises(SystemExit) as excinfo,
            ):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        # Exit 1 because there's at least one shadow warning.
        assert excinfo.value.code == 1
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        # Exactly the 'splunk' overlap is reported, not 'another' or
        # 'filesystem'. Anchor on both endpoint names so a future
        # log-line refactor can't drop the diagnostic value silently.
        shadow_msgs = [m for m in warning_msgs if "shadow" in m.lower()]
        assert len(shadow_msgs) == 1, shadow_msgs
        assert "'splunk'" in shadow_msgs[0]
        assert str(project_path) in shadow_msgs[0]
        assert str(cursor_path) in shadow_msgs[0]

    def test_project_config_no_collision_no_shadow_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Project-scope file exists but uses entirely different names.
        # Doctor should still scan it for bare-command issues, but emit
        # no shadow warnings.
        cursor_path = tmp_path / "user_mcp.json"
        cursor_path.write_text(
            json.dumps({"mcpServers": {"splunk": {"command": "/opt/homebrew/bin/spl-bridge"}}})
        )
        claude_path = tmp_path / "claude.json"
        project_path = tmp_path / "proj_mcp.json"
        project_path.write_text(
            json.dumps({"mcpServers": {"team-tool": {"command": "/usr/local/bin/team"}}})
        )
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path, project_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with caplog.at_level(logging.INFO, logger="spl_bridge.doctor"):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert not any("shadow" in m.lower() for m in warning_msgs), warning_msgs
        # The project file IS scanned by name -- assert the scan log
        # line appeared so a future regression that silently drops the
        # project arm gets caught.
        info_msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
        assert any("Cursor (project)" in m for m in info_msgs), info_msgs

    def test_project_config_bare_command_warning_fires(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Same bare-command audit that runs against user-scope must
        # also run against the discovered project-scope file.
        cursor_path = tmp_path / "user_mcp.json"
        claude_path = tmp_path / "claude.json"
        project_path = tmp_path / "proj_mcp.json"
        project_path.write_text(json.dumps({"mcpServers": {"splunk": {"command": "spl-bridge"}}}))
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path, project_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with (
                caplog.at_level(logging.INFO, logger="spl_bridge.doctor"),
                pytest.raises(SystemExit) as excinfo,
            ):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        assert excinfo.value.code == 1
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        bare_warnings = [m for m in warning_msgs if "bare command 'spl-bridge'" in m]
        assert any("Cursor (project):" in m for m in bare_warnings), warning_msgs

    def test_unreadable_project_config_skipped_silently(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # An unreadable / malformed project file shouldn't manufacture
        # a shadow warning out of thin air. The bare-command scan emits
        # its own diagnostic; the shadow check just returns 0.
        cursor_path = tmp_path / "user_mcp.json"
        cursor_path.write_text(
            json.dumps({"mcpServers": {"splunk": {"command": "/abs/spl-bridge"}}})
        )
        claude_path = tmp_path / "claude.json"
        project_path = tmp_path / "proj_mcp.json"
        project_path.write_text("{not json")
        _redirect_doctor_paths(monkeypatch, cursor_path, claude_path, project_path)
        wizard_logger = _attach_doctor_logger(caplog)
        try:
            with (
                caplog.at_level(logging.INFO, logger="spl_bridge.doctor"),
                pytest.raises(SystemExit) as excinfo,
            ):
                doctor.run_host_scan()
        finally:
            wizard_logger.removeHandler(caplog.handler)
        assert excinfo.value.code == 1
        # Malformed-JSON warning fires, but no shadow warning is
        # invented from the unreadable side.
        warning_msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("not valid JSON" in m for m in warning_msgs), warning_msgs
        assert not any("shadow" in m.lower() for m in warning_msgs), warning_msgs


class TestCliHostsFlag:
    """End-to-end test that ``spl-bridge doctor --hosts`` actually
    routes through the new code path (i.e. the argparse wiring in
    ``cli.main`` is correct).

    We patch ``run_host_scan`` rather than running it for real, since
    the routing is what's under test here -- the scan logic itself is
    covered exhaustively above.
    """

    def test_doctor_hosts_invokes_run_host_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from spl_bridge import cli

        called = MagicMock()
        monkeypatch.setattr("spl_bridge.doctor.run_host_scan", called)
        # Also stub run_doctor so a wiring regression that falls
        # through to the default branch surfaces as an assertion
        # failure (called.assert_called_once_with()) rather than a
        # hung test attempting to load real Splunk config.
        monkeypatch.setattr("spl_bridge.doctor.run_doctor", MagicMock())
        monkeypatch.setattr("sys.argv", ["spl-bridge", "doctor", "--hosts"])

        cli.main()

        called.assert_called_once_with()

    def test_doctor_no_flag_invokes_run_doctor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bare ``spl-bridge doctor`` (no flags) must still hit the
        existing Splunk-REST entry point unchanged.
        """
        from spl_bridge import cli

        called = MagicMock()
        monkeypatch.setattr("spl_bridge.doctor.run_doctor", called)
        monkeypatch.setattr("spl_bridge.doctor.run_host_scan", MagicMock())
        monkeypatch.setattr("sys.argv", ["spl-bridge", "doctor"])

        cli.main()

        called.assert_called_once_with()


def test_scan_one_config_unreadable_path_warns(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Direct unit test of :func:`doctor._scan_one_config` for the OSError
    branch (e.g. permissions stripped on the parent dir). Goes through
    the function directly because reproducing a real EACCES inside the
    sandbox is unreliable across CI runners.
    """
    fake_path = tmp_path / "mcp.json"
    fake_path.write_text("{}")  # exists, but we'll force read_text to raise

    def _boom(*_args: object, **_kwargs: object) -> str:
        raise PermissionError("permission denied")

    monkeypatch.setattr(Path, "read_text", _boom)

    splunk_logger = logging.getLogger("spl_bridge.doctor")
    splunk_logger.addHandler(caplog.handler)
    splunk_logger.setLevel(logging.INFO)
    try:
        with caplog.at_level(logging.WARNING, logger="spl_bridge.doctor"):
            warnings = doctor._scan_one_config("Cursor", fake_path)
    finally:
        splunk_logger.removeHandler(caplog.handler)
    assert warnings == 1
    msgs = [r.getMessage() for r in caplog.records]
    assert any("cannot read" in m for m in msgs), msgs
