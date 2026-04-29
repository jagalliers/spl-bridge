"""Tests for the spl-bridge setup wizard.

Coverage targets:

* Credstore -- both backends, perm enforcement, atomic write, allowlist.
* MCP client writers -- merge semantics, backup creation, JSON safety.
* Splunk probe -- success and error paths via mocked SplunkClient.
* End-to-end wizard happy paths and safety invariants (TTY, http+pw,
  https-no-verify+pw, secrets never printed).
* config._resolve_secret precedence (env > _FILE > keyring > dotfile)
  and 0600 perm enforcement on the dotfile reader.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from spl_bridge import config as cfg_mod
from spl_bridge.setup_wizard import __init__ as wizard_init  # noqa: F401
from spl_bridge.setup_wizard import (
    credstore,
    mcp_clients,
    splunk_probe,
    ui,
)
from spl_bridge.setup_wizard import main as wizard_main

# ---------------------------------------------------------------------------
# Credstore -- DotfileStore
# ---------------------------------------------------------------------------


class TestDotfileStore:
    def test_store_and_get_round_trip(self, tmp_path: Path) -> None:
        store = credstore.DotfileStore(path=tmp_path / "creds")
        store.store("SPLUNK_TOKEN", "abc123")
        assert store.get("SPLUNK_TOKEN") == "abc123"

    def test_writes_with_0600_mode(self, tmp_path: Path) -> None:
        if sys.platform == "win32":
            pytest.skip("POSIX perms only")
        store = credstore.DotfileStore(path=tmp_path / "creds")
        store.store("SPLUNK_TOKEN", "abc123")
        mode = stat.S_IMODE(store.path.stat().st_mode)
        assert mode == 0o600

    def test_atomic_replace_does_not_leak_temp(self, tmp_path: Path) -> None:
        store = credstore.DotfileStore(path=tmp_path / "creds")
        store.store("SPLUNK_TOKEN", "v1")
        store.store("SPLUNK_USERNAME", "alice")
        # No leftover temp files (mkstemp prefix is ".")
        leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".")]
        assert leftovers == [], f"Unexpected temp files: {leftovers}"

    def test_refuses_loose_perms_on_read(self, tmp_path: Path) -> None:
        if sys.platform == "win32":
            pytest.skip("POSIX perms only")
        path = tmp_path / "creds"
        path.write_text("SPLUNK_TOKEN=hunter2\n")
        os.chmod(path, 0o644)
        store = credstore.DotfileStore(path=path)
        # Loose perms -> read returns None and logs a warning.
        assert store.get("SPLUNK_TOKEN") is None

    def test_rejects_non_allowlisted_key(self, tmp_path: Path) -> None:
        store = credstore.DotfileStore(path=tmp_path / "creds")
        with pytest.raises(ValueError):
            store.store("ARBITRARY_KEY", "value")
        with pytest.raises(ValueError):
            store.get("ARBITRARY_KEY")

    def test_delete_removes_only_target_key(self, tmp_path: Path) -> None:
        store = credstore.DotfileStore(path=tmp_path / "creds")
        store.store("SPLUNK_TOKEN", "t")
        store.store("SPLUNK_USERNAME", "u")
        store.delete("SPLUNK_TOKEN")
        assert store.get("SPLUNK_TOKEN") is None
        assert store.get("SPLUNK_USERNAME") == "u"


# ---------------------------------------------------------------------------
# Credstore -- KeyringStore (mocked)
# ---------------------------------------------------------------------------


class _FakeKeyring:
    def __init__(self, fail_class: bool = False):
        self._store: dict[tuple[str, str], str] = {}
        # Use type() so the synthesised class actually has __name__ == "Keyring"
        # and a controllable __module__ -- mimicking real keyring backends.
        if fail_class:
            backend_cls = type("Keyring", (), {"__module__": "keyring.backends.fail"})
        else:
            backend_cls = type("Keyring", (), {"__module__": "keyring.backends.macOS"})
        self._backend = backend_cls()

    def get_keyring(self):
        return self._backend

    def set_password(self, service: str, key: str, value: str) -> None:
        self._store[(service, key)] = value

    def get_password(self, service: str, key: str) -> str | None:
        return self._store.get((service, key))

    def delete_password(self, service: str, key: str) -> None:
        self._store.pop((service, key), None)


class TestKeyringStore:
    def test_uses_keyring_when_backend_real(self, monkeypatch) -> None:
        fake = _FakeKeyring(fail_class=False)
        monkeypatch.setitem(sys.modules, "keyring", fake)
        # Provide errors submodule used by the import
        errors = MagicMock()
        errors.KeyringError = type("KeyringError", (Exception,), {})
        monkeypatch.setitem(sys.modules, "keyring.errors", errors)
        store = credstore.KeyringStore()
        assert store.is_available() is True
        store.store("SPLUNK_TOKEN", "tok")
        assert store.get("SPLUNK_TOKEN") == "tok"
        store.delete("SPLUNK_TOKEN")
        assert store.get("SPLUNK_TOKEN") is None

    def test_detects_fail_backend(self, monkeypatch) -> None:
        fake = _FakeKeyring(fail_class=True)
        monkeypatch.setitem(sys.modules, "keyring", fake)
        errors = MagicMock()
        errors.KeyringError = type("KeyringError", (Exception,), {})
        monkeypatch.setitem(sys.modules, "keyring.errors", errors)
        store = credstore.KeyringStore()
        assert store.is_available() is False

    def test_select_backend_falls_back_to_dotfile(self, monkeypatch, tmp_path: Path) -> None:
        fake = _FakeKeyring(fail_class=True)
        monkeypatch.setitem(sys.modules, "keyring", fake)
        errors = MagicMock()
        errors.KeyringError = type("KeyringError", (Exception,), {})
        monkeypatch.setitem(sys.modules, "keyring.errors", errors)
        # Force dotfile location into tmp.
        monkeypatch.setattr(
            credstore,
            "_user_config_dir",
            lambda: tmp_path,
        )
        store = credstore.select_backend(prefer_keyring=True)
        assert isinstance(store, credstore.DotfileStore)


# ---------------------------------------------------------------------------
# MCP client writers
# ---------------------------------------------------------------------------


class TestCursorWriter:
    def test_creates_new_config(self, tmp_path: Path) -> None:
        path = tmp_path / "mcp.json"
        writer = mcp_clients.CursorWriter(path=path)
        launch = mcp_clients.SplunkMcpLaunch(command="spl-bridge", env={"SPLUNK_HOST": "x"})
        result = writer.write("splunk", launch)
        loaded = json.loads(path.read_text())
        assert loaded == {
            "mcpServers": {
                "splunk": {
                    "command": "spl-bridge",
                    "args": [],
                    "env": {"SPLUNK_HOST": "x"},
                }
            }
        }
        assert result.backup_path is None

    def test_merges_with_existing_servers(self, tmp_path: Path) -> None:
        path = tmp_path / "mcp.json"
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "other": {"command": "other-tool"},
                        "splunk": {"command": "old-spl-bridge"},
                    },
                    "extraField": True,
                }
            )
        )
        writer = mcp_clients.CursorWriter(path=path)
        launch = mcp_clients.SplunkMcpLaunch(command="spl-bridge")
        result = writer.write("splunk", launch)
        loaded = json.loads(path.read_text())
        assert "other" in loaded["mcpServers"]
        assert loaded["mcpServers"]["splunk"] == {
            "command": "spl-bridge",
            "args": [],
        }
        assert loaded["extraField"] is True
        assert result.backup_path is not None
        # Backup contains the previous content
        backup = json.loads(Path(result.backup_path).read_text())
        assert backup["mcpServers"]["splunk"]["command"] == "old-spl-bridge"

    def test_never_writes_secrets(self, tmp_path: Path) -> None:
        path = tmp_path / "mcp.json"
        writer = mcp_clients.CursorWriter(path=path)
        launch = mcp_clients.SplunkMcpLaunch(
            command="spl-bridge",
            env={"SPLUNK_HOST": "x"},
        )
        writer.write("splunk", launch)
        body = path.read_text()
        assert "TOKEN" not in body
        assert "PASSWORD" not in body

    def test_refuses_invalid_existing_json(self, tmp_path: Path) -> None:
        path = tmp_path / "mcp.json"
        path.write_text("{not json")
        writer = mcp_clients.CursorWriter(path=path)
        launch = mcp_clients.SplunkMcpLaunch()
        with pytest.raises(mcp_clients.WriterError):
            writer.write("splunk", launch)


class TestClaudeDesktopWriter:
    def test_writes_to_provided_path(self, tmp_path: Path) -> None:
        path = tmp_path / "claude_desktop_config.json"
        writer = mcp_clients.ClaudeDesktopWriter(path=path)
        launch = mcp_clients.SplunkMcpLaunch(command="spl-bridge")
        writer.write("splunk", launch)
        assert path.exists()
        assert json.loads(path.read_text())["mcpServers"]["splunk"]["command"] == "spl-bridge"


class TestClaudeCLIWriter:
    def test_invokes_claude_mcp_add(self) -> None:
        writer = mcp_clients.ClaudeCLIWriter()
        launch = mcp_clients.SplunkMcpLaunch(
            command="spl-bridge",
            env={"SPLUNK_HOST": "x"},
        )
        with (
            patch(
                "spl_bridge.setup_wizard.mcp_clients.shutil.which",
                return_value="/usr/local/bin/claude",
            ),
            patch("spl_bridge.setup_wizard.mcp_clients.subprocess.run") as run,
        ):
            run.return_value = MagicMock(returncode=0, stderr="")
            result = writer.write("splunk", launch)
        argv = run.call_args[0][0]
        assert argv[0:5] == ["claude", "mcp", "add", "--scope", "user"]
        # M-5: end-of-options marker must precede the user-controlled name.
        assert argv[5] == "--"
        assert argv[6] == "splunk"
        assert "--env" in argv
        assert "SPLUNK_HOST=x" in argv
        assert result.target == "Claude CLI"

    def test_missing_binary_raises(self) -> None:
        writer = mcp_clients.ClaudeCLIWriter()
        with patch("spl_bridge.setup_wizard.mcp_clients.shutil.which", return_value=None):
            with pytest.raises(mcp_clients.WriterError):
                writer.write("splunk", mcp_clients.SplunkMcpLaunch())

    @pytest.mark.parametrize(
        "evil_name",
        [
            "--scope",
            "--scope=global",
            "-x",
            "spl unk",  # space
            "splunk;ls",  # shell metachar (validator rejects pre-shell)
            "x" * 65,  # too long
            "",  # empty
            "splunk\n",  # newline
        ],
    )
    def test_rejects_flag_or_invalid_server_name(self, evil_name: str) -> None:
        writer = mcp_clients.ClaudeCLIWriter()
        with patch(
            "spl_bridge.setup_wizard.mcp_clients.shutil.which", return_value="/usr/local/bin/claude"
        ):
            with pytest.raises(ValueError, match=r"server_name must match"):
                writer.write(evil_name, mcp_clients.SplunkMcpLaunch())


class TestServerNameValidationOnJSONWriters:
    """M-5: invalid server_name must also be rejected by JSON writers."""

    def test_cursor_writer_rejects_bad_name(self, tmp_path) -> None:
        path = tmp_path / "mcp.json"
        writer = mcp_clients.CursorWriter(path=path)
        with pytest.raises(ValueError, match="server_name must match"):
            writer.write("--scope", mcp_clients.SplunkMcpLaunch(command="x"))
        assert not path.exists()

    def test_snippet_printer_rejects_bad_name(self) -> None:
        writer = mcp_clients.SnippetPrinter()
        with pytest.raises(ValueError, match="server_name must match"):
            writer.write("--scope", mcp_clients.SplunkMcpLaunch(command="x"))


class TestSnippetPrinter:
    def test_returns_snippet_without_writing(self) -> None:
        writer = mcp_clients.SnippetPrinter()
        launch = mcp_clients.SplunkMcpLaunch(command="spl-bridge")
        result = writer.write("splunk", launch)
        assert result.target == "Print snippet only"
        assert result.snippet == {"mcpServers": {"splunk": {"command": "spl-bridge", "args": []}}}


# ---------------------------------------------------------------------------
# Splunk probe
# ---------------------------------------------------------------------------


class TestSplunkProbe:
    def test_success_extracts_server_name_and_version(self) -> None:
        from spl_bridge.config import SplunkMCPConfig

        config = SplunkMCPConfig(host="splunk", splunk_token="t")
        body = {"entry": [{"content": {"serverName": "lab01", "version": "9.2.0"}}]}
        with patch.object(splunk_probe, "SplunkClient") as SC:
            fake_resp = MagicMock()
            fake_resp.status_code = 200
            fake_resp.json.return_value = body
            SC.return_value.call_api.return_value = fake_resp
            result = splunk_probe.probe(config)
        assert result.ok is True
        assert result.server_name == "lab01"
        assert result.version == "9.2.0"

    def test_non_200_returns_failure(self) -> None:
        from spl_bridge.config import SplunkMCPConfig

        config = SplunkMCPConfig(host="splunk", splunk_token="t")
        with patch.object(splunk_probe, "SplunkClient") as SC:
            fake_resp = MagicMock()
            fake_resp.status_code = 401
            fake_resp.json.return_value = {}
            SC.return_value.call_api.return_value = fake_resp
            result = splunk_probe.probe(config)
        assert result.ok is False
        assert "401" in result.error

    def test_exception_caught_and_reported(self) -> None:
        from spl_bridge.config import SplunkMCPConfig

        config = SplunkMCPConfig(host="splunk", splunk_token="t")
        with patch.object(splunk_probe, "SplunkClient") as SC:
            SC.return_value.call_api.side_effect = RuntimeError("connection refused")
            result = splunk_probe.probe(config)
        assert result.ok is False
        assert "connection refused" in result.error


# ---------------------------------------------------------------------------
# UI safety -- TTY guard + no secret echoing
# ---------------------------------------------------------------------------


class TestUiGuards:
    def test_require_tty_raises_when_not_tty(self) -> None:
        with patch("sys.stdin.isatty", return_value=False):
            with pytest.raises(ui.WizardAbortError):
                ui.require_tty()

    def test_ask_secret_never_echoes(self, capsys, monkeypatch) -> None:
        called = {"prompts": []}

        def fake_getpass(prompt: str) -> str:
            called["prompts"].append(prompt)
            return "hunter2"

        monkeypatch.setattr("getpass.getpass", fake_getpass)
        value = ui.ask_secret("Splunk token")
        assert value == "hunter2"
        captured = capsys.readouterr()
        # ``getpass`` never echoes, so neither stdout nor stderr should
        # mention the value.
        assert "hunter2" not in captured.out
        assert "hunter2" not in captured.err


class TestAskChoiceDefaultMarker:
    """Regression: only one ``(default)`` should render per choice line.

    Originally the TLS verification prompt baked ``(default)`` into the
    first option's label *and* let ``ask_choice`` append its own marker,
    producing ``Verify with system CA bundle (default) (default)`` and
    misleading users on re-runs where the saved default was option 2 or 3.
    """

    TLS_CHOICES = [
        "Verify with system CA bundle",
        "Verify with a custom CA bundle path",
        "DISABLE verification (lab only)",
    ]

    def _choice_lines(self, captured_err: str) -> list[str]:
        return [line for line in captured_err.splitlines() if line.lstrip().startswith(("1)", "2)", "3)"))]

    def test_each_line_has_at_most_one_default_marker(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr("builtins.input", lambda _prompt="": "")
        for default_idx in range(len(self.TLS_CHOICES)):
            ui.ask_choice("TLS verification", self.TLS_CHOICES, default=default_idx)
            captured = capsys.readouterr()
            for line in self._choice_lines(captured.err):
                assert line.count("(default)") <= 1, (
                    f"Duplicate (default) marker on line: {line!r}"
                )

    def test_marker_on_first_option_when_default_is_zero(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr("builtins.input", lambda _prompt="": "")
        ui.ask_choice("TLS verification", self.TLS_CHOICES, default=0)
        captured = capsys.readouterr()
        lines = self._choice_lines(captured.err)
        assert lines[0].endswith("(default)")
        assert "(default)" not in lines[1]
        assert "(default)" not in lines[2]

    def test_marker_tracks_disabled_default(self, capsys, monkeypatch) -> None:
        # Mirrors a re-run where the saved config had ssl_verify=False, so
        # tls_default_idx == 2 and the marker must move to option 3 -- not
        # stay glued to option 1.
        monkeypatch.setattr("builtins.input", lambda _prompt="": "")
        ui.ask_choice("TLS verification", self.TLS_CHOICES, default=2)
        captured = capsys.readouterr()
        lines = self._choice_lines(captured.err)
        assert "(default)" not in lines[0]
        assert "(default)" not in lines[1]
        # Line 3 ends with the auto-marker; the literal "(lab only)" stays put.
        assert lines[2].endswith("(default)")
        assert "(lab only)" in lines[2]


# ---------------------------------------------------------------------------
# config._resolve_secret precedence
# ---------------------------------------------------------------------------


class TestResolveSecretPrecedence:
    def test_env_var_wins(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("SPLUNK_TOKEN", "from-env")
        # Even with keyring + dotfile set, env wins
        fake = _FakeKeyring(fail_class=False)
        fake.set_password("spl-bridge", "SPLUNK_TOKEN", "from-keyring")
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert cfg_mod._resolve_secret("SPLUNK_TOKEN") == "from-env"

    def test_file_var_then_keyring(self, monkeypatch, tmp_path: Path) -> None:
        secret_path = tmp_path / "tok"
        secret_path.write_text("from-file\n")
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
        monkeypatch.setenv("SPLUNK_TOKEN_FILE", str(secret_path))
        fake = _FakeKeyring(fail_class=False)
        fake.set_password("spl-bridge", "SPLUNK_TOKEN", "from-keyring")
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert cfg_mod._resolve_secret("SPLUNK_TOKEN") == "from-file"

    def test_keyring_then_dotfile(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
        monkeypatch.delenv("SPLUNK_TOKEN_FILE", raising=False)
        fake = _FakeKeyring(fail_class=False)
        fake.set_password("spl-bridge", "SPLUNK_TOKEN", "from-keyring")
        monkeypatch.setitem(sys.modules, "keyring", fake)
        # Even if we'd write a dotfile, keyring wins
        assert cfg_mod._resolve_secret("SPLUNK_TOKEN") == "from-keyring"

    def test_dotfile_wins_when_no_keyring(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
        monkeypatch.delenv("SPLUNK_TOKEN_FILE", raising=False)
        # Make sure keyring import returns the fail-backend
        fake = _FakeKeyring(fail_class=True)
        monkeypatch.setitem(sys.modules, "keyring", fake)

        dotfile = tmp_path / "credentials"
        dotfile.write_text("SPLUNK_TOKEN=from-dotfile\n")
        if sys.platform != "win32":
            os.chmod(dotfile, 0o600)
        # Patch user_config_dir lookup
        import platformdirs

        monkeypatch.setattr(platformdirs, "user_config_dir", lambda *_a, **_k: str(tmp_path))
        assert cfg_mod._resolve_secret("SPLUNK_TOKEN") == "from-dotfile"

    def test_dotfile_loose_perms_ignored(self, monkeypatch, tmp_path: Path) -> None:
        if sys.platform == "win32":
            pytest.skip("POSIX perms only")
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
        monkeypatch.delenv("SPLUNK_TOKEN_FILE", raising=False)
        # No keyring
        monkeypatch.setitem(sys.modules, "keyring", _FakeKeyring(fail_class=True))
        dotfile = tmp_path / "credentials"
        dotfile.write_text("SPLUNK_TOKEN=loose\n")
        os.chmod(dotfile, 0o644)
        import platformdirs

        monkeypatch.setattr(platformdirs, "user_config_dir", lambda *_a, **_k: str(tmp_path))
        assert cfg_mod._resolve_secret("SPLUNK_TOKEN") is None

    def test_returns_none_when_all_sources_absent(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
        monkeypatch.delenv("SPLUNK_TOKEN_FILE", raising=False)
        monkeypatch.setitem(sys.modules, "keyring", _FakeKeyring(fail_class=True))
        import platformdirs

        monkeypatch.setattr(platformdirs, "user_config_dir", lambda *_a, **_k: str(tmp_path))
        assert cfg_mod._resolve_secret("SPLUNK_TOKEN") is None


# ---------------------------------------------------------------------------
# End-to-end main() flow
# ---------------------------------------------------------------------------


def _drive_wizard(
    monkeypatch,
    tmp_path: Path,
    answers: list[str],
    secrets: list[str],
    *,
    keyring_works: bool = False,
    probe_ok: bool = True,
    probe_results: list[splunk_probe.ProbeResult] | None = None,
):
    """Helper: install scripted input/getpass/keyring and run main().

    ``probe_results``, when provided, overrides ``probe_ok`` and lets a
    test simulate a sequence of probe outcomes across the new
    edit-and-retry loop -- one entry is consumed per ``probe()`` call.
    The stub raises if the wizard asks for more probes than the test
    scripted, which catches off-by-one bugs in the retry budget.
    """
    answer_iter = iter(answers)
    secret_iter = iter(secrets)

    def fake_input(_prompt: str = "") -> str:
        try:
            return next(answer_iter)
        except StopIteration as exc:
            raise AssertionError(f"Wizard asked more questions than expected: {_prompt!r}") from exc

    def fake_getpass(_prompt: str = "") -> str:
        try:
            return next(secret_iter)
        except StopIteration as exc:
            raise AssertionError("Wizard asked for more secrets than expected") from exc

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr("getpass.getpass", fake_getpass)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    # Force credstore destination into tmp.
    monkeypatch.setattr(credstore, "_user_config_dir", lambda: tmp_path / "config")
    fake = _FakeKeyring(fail_class=not keyring_works)
    monkeypatch.setitem(sys.modules, "keyring", fake)
    errors = MagicMock()
    errors.KeyringError = type("KeyringError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "keyring.errors", errors)

    # Stub the probe so we don't need a Splunk instance.
    if probe_results is not None:
        results_iter = iter(probe_results)

        def _next_probe(_cfg):
            try:
                return next(results_iter)
            except StopIteration as exc:
                raise AssertionError(
                    "Wizard called probe() more times than the test scripted"
                ) from exc

        monkeypatch.setattr(splunk_probe, "probe", _next_probe)
    else:
        if probe_ok:
            result = splunk_probe.ProbeResult(
                ok=True, server_name="lab", version="9.2.0", auth_mode="token"
            )
        else:
            result = splunk_probe.ProbeResult(ok=False, error="connect refused", auth_mode="token")
        monkeypatch.setattr(splunk_probe, "probe", lambda _cfg: result)

    # Force MCP client writes into tmp.
    cursor_path = tmp_path / "cursor_mcp.json"

    def _writers():
        return [
            mcp_clients.CursorWriter(path=cursor_path),
            mcp_clients.SnippetPrinter(),
        ]

    monkeypatch.setattr("spl_bridge.setup_wizard.mcp_clients.all_writers", _writers)
    monkeypatch.setattr("spl_bridge.setup_wizard.all_writers", _writers)

    # Force the launch-command resolver to a stable, absolute, non-PATH-
    # dependent value so the test asserts the *behaviour* (an absolute
    # path is written) without depending on whether `spl-bridge` happens
    # to be on the test runner's PATH.
    monkeypatch.setattr(
        "spl_bridge.setup_wizard._resolve_spl_bridge_command",
        lambda: "/opt/test-prefix/bin/spl-bridge",
    )
    return cursor_path


class TestWizardMainFlow:
    def test_happy_path_token_dotfile_cursor(self, monkeypatch, tmp_path: Path, capsys) -> None:
        cursor_path = _drive_wizard(
            monkeypatch,
            tmp_path,
            answers=[
                "splunk.example.com",  # host
                "8089",  # port
                "1",  # scheme = https
                "1",  # TLS verify with system CA
                "1",  # auth mode = token
                "splunk",  # MCP server name
                "1",  # writer = Cursor (first in stub list)
            ],
            secrets=["super-secret-token"],
            keyring_works=False,
        )
        rc = wizard_main()
        assert rc == 0
        # Dotfile written under tmp/config/
        creds = (tmp_path / "config" / "credentials").read_text()
        assert "SPLUNK_TOKEN=super-secret-token" in creds
        # Cursor config written -- and the command is the resolved
        # absolute path, not a bare "spl-bridge" name (R-launchd-PATH:
        # macOS Claude Desktop and similar launchd-spawned MCP hosts
        # don't inherit the user's shell PATH, so a bare command name
        # would fail to resolve at spawn time).
        cursor = json.loads(cursor_path.read_text())
        assert cursor["mcpServers"]["splunk"]["command"] == "/opt/test-prefix/bin/spl-bridge"
        assert cursor["mcpServers"]["splunk"]["env"]["SPLUNK_HOST"] == "splunk.example.com"
        # Secret is NOT in any rendered output
        captured = capsys.readouterr()
        assert "super-secret-token" not in captured.out
        assert "super-secret-token" not in captured.err
        # And not in the Cursor file
        assert "super-secret-token" not in cursor_path.read_text()

    def test_keyring_path_persists_secrets_in_keyring(self, monkeypatch, tmp_path: Path) -> None:
        _drive_wizard(
            monkeypatch,
            tmp_path,
            answers=[
                "splunk.example.com",
                "8089",
                "1",  # scheme
                "1",  # TLS verify
                "1",  # token auth
                "splunk",
                "1",  # Cursor
            ],
            secrets=["k-secret"],
            keyring_works=True,
        )
        rc = wizard_main()
        assert rc == 0
        # The keyring fake holds the secret.
        kr = sys.modules["keyring"]
        assert kr.get_password("spl-bridge", "SPLUNK_TOKEN") == "k-secret"
        # Dotfile must NOT have been touched.
        assert not (tmp_path / "config" / "credentials").exists()

    def test_password_over_http_aborts(self, monkeypatch, tmp_path: Path) -> None:
        _drive_wizard(
            monkeypatch,
            tmp_path,
            answers=[
                "splunk.example.com",
                "8089",
                "2",  # scheme = http
                "2",  # auth mode = password
                "admin",  # username
            ],
            secrets=["pw"],
            keyring_works=False,
        )
        rc = wizard_main()
        # Wizard must hard-stop -- no creds written, no client config.
        assert rc == 2
        assert not (tmp_path / "config" / "credentials").exists()

    def test_disable_tls_verify_no_aborts(self, monkeypatch, tmp_path: Path) -> None:
        """The TLS-disabled risk gate is a y/N (default no). Empty / 'n'
        must abort cleanly without writing anything.
        """
        _drive_wizard(
            monkeypatch,
            tmp_path,
            answers=[
                "splunk.example.com",
                "8089",
                "1",  # scheme = https
                "3",  # TLS verification = DISABLED (lab only)
                "n",  # decline the risk -> abort
            ],
            secrets=[],
            keyring_works=False,
        )
        rc = wizard_main()
        assert rc == 2
        assert not (tmp_path / "config" / "credentials").exists()

    def test_disable_tls_verify_yes_proceeds(self, monkeypatch, tmp_path: Path) -> None:
        """Same gate, but accepted -- wizard continues and persists."""
        cursor_path = _drive_wizard(
            monkeypatch,
            tmp_path,
            answers=[
                "splunk.example.com",
                "8089",
                "1",  # scheme = https
                "3",  # TLS verification = DISABLED
                "y",  # accept the risk
                "1",  # auth mode = token
                "splunk",
                "1",  # writer = Cursor
            ],
            secrets=["tok"],
            keyring_works=False,
        )
        rc = wizard_main()
        assert rc == 0
        cursor = json.loads(cursor_path.read_text())
        # SPLUNK_VERIFY_SSL=false propagated into the launch env
        assert cursor["mcpServers"]["splunk"]["env"]["SPLUNK_VERIFY_SSL"] == "false"

    def test_password_over_unverified_tls_no_aborts(self, monkeypatch, tmp_path: Path) -> None:
        """Password + TLS-disabled -- the second risk gate must also be a
        y/N that aborts cleanly on 'n'.
        """
        _drive_wizard(
            monkeypatch,
            tmp_path,
            answers=[
                "splunk.example.com",
                "8089",
                "1",  # scheme = https
                "3",  # TLS verification = DISABLED
                "y",  # accept TLS-disabled risk
                "2",  # auth mode = password
                "n",  # decline the password+unverified risk -> abort
            ],
            secrets=[],
            keyring_works=False,
        )
        rc = wizard_main()
        assert rc == 2
        assert not (tmp_path / "config" / "credentials").exists()

    def test_probe_fail_edit_then_succeed(self, monkeypatch, tmp_path: Path) -> None:
        """Probe fails on attempt 1; user picks 'Edit', re-collects with
        defaults, probe succeeds on attempt 2; wizard persists.
        """
        cursor_path = _drive_wizard(
            monkeypatch,
            tmp_path,
            answers=[
                # Attempt 1 collection
                "splunk.example.com",  # host
                "8089",  # port
                "1",  # scheme = https
                "1",  # TLS = system CA
                "1",  # auth = token
                # Probe fails -> failure menu
                "1",  # Edit and try again
                # Attempt 2 collection (defaults pre-filled, just press Enter)
                "",  # host -> default (splunk.example.com)
                "",  # port -> default (8089)
                "",  # scheme -> default (https)
                "",  # TLS -> default (system CA)
                "",  # auth -> default (token)
                # Probe succeeds, continue to writer/server
                "splunk",  # MCP server name
                "1",  # writer = Cursor
            ],
            secrets=["bad-token", "good-token"],
            keyring_works=False,
            probe_results=[
                splunk_probe.ProbeResult(ok=False, error="HTTP 401", auth_mode="token"),
                splunk_probe.ProbeResult(
                    ok=True, server_name="lab", version="9.2.0", auth_mode="token"
                ),
            ],
        )
        rc = wizard_main()
        assert rc == 0
        # Only the second (successful) attempt's secret should be in the
        # credstore -- the bad-token from attempt 1 must have been
        # overwritten when the user re-prompted.
        creds = (tmp_path / "config" / "credentials").read_text()
        assert "SPLUNK_TOKEN=good-token" in creds
        assert "bad-token" not in creds
        # Cursor config written with the resolved absolute command path
        cursor = json.loads(cursor_path.read_text())
        assert cursor["mcpServers"]["splunk"]["env"]["SPLUNK_HOST"] == "splunk.example.com"

    def test_probe_fail_edit_then_save_anyway(self, monkeypatch, tmp_path: Path) -> None:
        """Two failed probes back-to-back; user picks Edit then Save-anyway.

        Verifies that Save-anyway after a failed re-attempt still
        persists -- the existing save-anyway escape hatch is preserved
        inside the loop.
        """
        cursor_path = _drive_wizard(
            monkeypatch,
            tmp_path,
            answers=[
                # Attempt 1 collection
                "splunk.example.com",
                "8089",
                "1",  # https
                "1",  # system CA
                "1",  # token
                # Probe fails -> menu
                "1",  # Edit
                # Attempt 2 collection -- accept all defaults
                "",
                "",
                "",
                "",
                "",
                # Probe fails again -> menu, pick Save anyway
                "2",  # Save anyway
                "splunk",  # MCP server name
                "1",  # writer = Cursor
            ],
            secrets=["t1", "t2"],
            keyring_works=False,
            probe_results=[
                splunk_probe.ProbeResult(ok=False, error="conn refused", auth_mode="token"),
                splunk_probe.ProbeResult(ok=False, error="conn refused", auth_mode="token"),
            ],
        )
        rc = wizard_main()
        assert rc == 0
        # Save-anyway path persists despite probe failure
        creds = (tmp_path / "config" / "credentials").read_text()
        assert "SPLUNK_TOKEN=t2" in creds
        cursor = json.loads(cursor_path.read_text())
        assert cursor["mcpServers"]["splunk"]["env"]["SPLUNK_HOST"] == "splunk.example.com"

    def test_probe_fail_retry_budget_exhausted(self, monkeypatch, tmp_path: Path) -> None:
        """After _PROBE_MAX_ATTEMPTS (3) failed probes the menu degrades to
        the historical 2-option (save / quit) prompt -- no Edit option.

        We script three failures, two Edit picks, then a Save-anyway
        from the degraded 2-option menu. The wizard must NOT call
        probe() a fourth time.
        """
        cursor_path = _drive_wizard(
            monkeypatch,
            tmp_path,
            answers=[
                # Attempt 1 collection
                "splunk.example.com",
                "8089",
                "1",
                "1",
                "1",
                # Probe fails -> 3-option menu, pick Edit
                "1",
                # Attempt 2 collection (defaults)
                "",
                "",
                "",
                "",
                "",
                # Probe fails -> 3-option menu, pick Edit
                "1",
                # Attempt 3 collection (defaults)
                "",
                "",
                "",
                "",
                "",
                # Probe fails -> degraded 2-option menu, pick Save (idx 1)
                "1",  # 2-option menu: 1=Save anyway, 2=Quit
                "splunk",
                "1",  # writer = Cursor
            ],
            secrets=["t1", "t2", "t3"],
            keyring_works=False,
            probe_results=[
                splunk_probe.ProbeResult(ok=False, error="boom", auth_mode="token"),
                splunk_probe.ProbeResult(ok=False, error="boom", auth_mode="token"),
                splunk_probe.ProbeResult(ok=False, error="boom", auth_mode="token"),
            ],
        )
        rc = wizard_main()
        assert rc == 0
        creds = (tmp_path / "config" / "credentials").read_text()
        # Latest re-prompted secret persists
        assert "SPLUNK_TOKEN=t3" in creds
        cursor = json.loads(cursor_path.read_text())
        assert "splunk" in cursor["mcpServers"]

    def test_non_tty_aborts(self, monkeypatch) -> None:
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        rc = wizard_main()
        assert rc == 2


# ---------------------------------------------------------------------------
# _collect_splunk_config -- previous-attempt pre-fill behaviour
# ---------------------------------------------------------------------------


class TestCollectSplunkConfigPrefill:
    """When the user picks 'Edit and try again' after a failed probe,
    the next collection round must pre-fill non-secret answers from
    the failed attempt as prompt defaults. Secrets (token / password)
    must always be re-prompted, never recalled.
    """

    def test_collect_splunk_config_prefills_from_previous(self, monkeypatch) -> None:
        from spl_bridge.config import SplunkMCPConfig
        from spl_bridge.setup_wizard import _collect_splunk_config

        previous = SplunkMCPConfig(
            host="splunk.lab.local",
            port=8443,
            scheme="https",
            ssl_verify="/etc/ssl/lab-ca.pem",  # custom CA bundle
            splunk_token=None,
            username="admin",
            password=None,
        )

        # Empty input on every prompt -> every answer accepts the
        # default, which (when `previous` is supplied) is the previous
        # attempt's value.
        empty_inputs = iter([""] * 32)
        monkeypatch.setattr("builtins.input", lambda _p="": next(empty_inputs))
        monkeypatch.setattr("getpass.getpass", lambda _p="": "fresh-password")

        collected = _collect_splunk_config(previous=previous)

        # Non-secret fields round-trip from previous
        assert collected.config.host == "splunk.lab.local"
        assert collected.config.port == 8443
        assert collected.config.scheme == "https"
        assert collected.config.ssl_verify == "/etc/ssl/lab-ca.pem"
        assert collected.config.username == "admin"
        # Secret was re-prompted (not recalled), came from getpass stub
        assert collected.config.password == "fresh-password"
        assert collected.secrets["SPLUNK_PASSWORD"] == "fresh-password"
        # Token mode wasn't used -- previous picked password mode and the
        # default carries that forward
        assert collected.config.splunk_token is None

    def test_collect_splunk_config_first_run_uses_factory_defaults(self, monkeypatch) -> None:
        """Sanity: passing previous=None keeps the original first-run
        defaults (localhost / 8089 / https / system CA / token) so the
        new parameter is fully back-compatible.
        """
        from spl_bridge.setup_wizard import _collect_splunk_config

        empty_inputs = iter([""] * 16)
        monkeypatch.setattr("builtins.input", lambda _p="": next(empty_inputs))
        monkeypatch.setattr("getpass.getpass", lambda _p="": "tok")

        collected = _collect_splunk_config(previous=None)
        assert collected.config.host == "localhost"
        assert collected.config.port == 8089
        assert collected.config.scheme == "https"
        assert collected.config.ssl_verify is True
        assert collected.config.splunk_token == "tok"


# ---------------------------------------------------------------------------
# spl-bridge command resolution (R-launchd-PATH)
# ---------------------------------------------------------------------------


class TestResolveSplBridgeCommand:
    """The wizard must write an absolute path so MCP hosts launched
    from launchd / Finder (e.g. Claude Desktop on macOS) -- which
    inherit a stripped-down PATH that omits pipx / venvs / Homebrew
    Python user-sites -- can spawn the server without a 'No such file
    or directory' error.
    """

    def test_uses_shutil_which_when_available(self, monkeypatch) -> None:
        from spl_bridge.setup_wizard import _resolve_spl_bridge_command

        monkeypatch.setattr(
            "spl_bridge.setup_wizard.shutil.which",
            lambda name: "/opt/homebrew/bin/spl-bridge" if name == "spl-bridge" else None,
        )
        assert _resolve_spl_bridge_command() == "/opt/homebrew/bin/spl-bridge"

    def test_falls_back_to_argv0_when_which_misses(self, monkeypatch) -> None:
        from spl_bridge.setup_wizard import _resolve_spl_bridge_command

        monkeypatch.setattr("spl_bridge.setup_wizard.shutil.which", lambda _name: None)
        monkeypatch.setattr(
            "spl_bridge.setup_wizard.sys.argv",
            ["/Users/alice/.local/pipx/venvs/spl-bridge/bin/spl-bridge", "setup"],
        )
        assert (
            _resolve_spl_bridge_command()
            == "/Users/alice/.local/pipx/venvs/spl-bridge/bin/spl-bridge"
        )

    def test_falls_back_to_bare_name_with_warning(self, monkeypatch) -> None:
        import logging

        from spl_bridge.setup_wizard import _resolve_spl_bridge_command

        monkeypatch.setattr("spl_bridge.setup_wizard.shutil.which", lambda _name: None)
        # argv[0] is something like "pytest" or "python -m pytest" --
        # not an absolute path that ends in "spl-bridge".
        monkeypatch.setattr(
            "spl_bridge.setup_wizard.sys.argv", ["/usr/bin/python3", "-m", "pytest"]
        )

        # The ``spl_bridge`` logger is intentionally non-propagating
        # (see spl_bridge/__init__.py) so pytest's root-level ``caplog``
        # fixture can't see records from it. Attach a temporary handler
        # to the wizard logger directly so we can assert the warning
        # actually fires.
        records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        wizard_logger = logging.getLogger("spl_bridge.setup_wizard")
        handler = _Capture(level=logging.WARNING)
        wizard_logger.addHandler(handler)
        try:
            assert _resolve_spl_bridge_command() == "spl-bridge"
        finally:
            wizard_logger.removeHandler(handler)

        assert any("stripped PATH" in r.getMessage() for r in records), (
            "Fallback path must surface a warning so the user can self-diagnose"
        )

    def test_argv0_must_be_absolute_to_be_used(self, monkeypatch) -> None:
        from spl_bridge.setup_wizard import _resolve_spl_bridge_command

        monkeypatch.setattr("spl_bridge.setup_wizard.shutil.which", lambda _name: None)
        # Relative ./spl-bridge invocation: don't trust it -- could
        # resolve to anything depending on the host's CWD at launch.
        monkeypatch.setattr("spl_bridge.setup_wizard.sys.argv", ["./spl-bridge", "setup"])
        assert _resolve_spl_bridge_command() == "spl-bridge"

    def test_argv0_windows_exe_basename(self, monkeypatch) -> None:
        from spl_bridge.setup_wizard import _resolve_spl_bridge_command

        monkeypatch.setattr("spl_bridge.setup_wizard.shutil.which", lambda _name: None)
        monkeypatch.setattr(
            "spl_bridge.setup_wizard.sys.argv",
            [
                r"C:\Users\alice\AppData\Local\Programs\Python\Python312\Scripts\spl-bridge.exe",
                "setup",
            ],
        )
        # On a non-Windows test host, Path() still treats the string as
        # a PosixPath and is_absolute() is False. Only assert the
        # behaviour is correct on Windows where the helper was designed
        # to handle the .exe suffix.
        if sys.platform == "win32":
            assert _resolve_spl_bridge_command().endswith("spl-bridge.exe")
        else:
            # On POSIX hosts, the backslash path is not absolute, so we
            # land in the bare-name fallback. The helper does not crash.
            assert _resolve_spl_bridge_command() == "spl-bridge"


class TestBuildLaunchPropagatesAbsolutePath:
    """The wizard resolves an absolute path inside ``_build_launch()`` and
    hands the resulting :class:`SplunkMcpLaunch` to whichever writer the
    user picked. Only :class:`CursorWriter` has end-to-end coverage in
    ``TestWizardMainFlow`` -- these tests assert the absolute path also
    lands in the per-target output for the other three writers, so a
    future refactor that splits launch construction per target (e.g. to
    let Claude CLI register a bare command for prettier ``claude mcp
    list`` output) would be caught.
    """

    _ABSOLUTE_PATH = "/opt/test-prefix/bin/spl-bridge"

    @pytest.fixture(autouse=True)
    def _stub_resolver(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "spl_bridge.setup_wizard._resolve_spl_bridge_command",
            lambda: self._ABSOLUTE_PATH,
        )

    def _make_config(self) -> cfg_mod.SplunkMCPConfig:
        # Token mode keeps the env payload minimal. The token never
        # leaves the credstore so it doesn't appear in any writer
        # output -- but the connection metadata does, and that's what
        # we want to verify rides alongside the absolute command.
        return cfg_mod.SplunkMCPConfig(
            host="splunk.example.com",
            port=8089,
            scheme="https",
            ssl_verify=True,
            splunk_token="test-token-not-persisted-by-build_launch",
        )

    def test_cursor_writer_receives_absolute_command(self, tmp_path: Path) -> None:
        from spl_bridge.setup_wizard import _build_launch

        path = tmp_path / "mcp.json"
        launch = _build_launch(self._make_config())
        mcp_clients.CursorWriter(path=path).write("splunk", launch)
        data = json.loads(path.read_text())
        assert data["mcpServers"]["splunk"]["command"] == self._ABSOLUTE_PATH

    def test_claude_desktop_writer_receives_absolute_command(self, tmp_path: Path) -> None:
        from spl_bridge.setup_wizard import _build_launch

        path = tmp_path / "claude_desktop_config.json"
        launch = _build_launch(self._make_config())
        mcp_clients.ClaudeDesktopWriter(path=path).write("splunk", launch)
        data = json.loads(path.read_text())
        assert data["mcpServers"]["splunk"]["command"] == self._ABSOLUTE_PATH

    def test_claude_cli_writer_receives_absolute_command(self) -> None:
        from spl_bridge.setup_wizard import _build_launch

        launch = _build_launch(self._make_config())
        with (
            patch(
                "spl_bridge.setup_wizard.mcp_clients.shutil.which",
                return_value="/usr/local/bin/claude",
            ),
            patch("spl_bridge.setup_wizard.mcp_clients.subprocess.run") as run,
        ):
            run.return_value = MagicMock(returncode=0, stderr="")
            mcp_clients.ClaudeCLIWriter().write("splunk", launch)
        argv = run.call_args[0][0]
        # argv layout (see ClaudeCLIWriter.write):
        #   [0..4] = ["claude","mcp","add","--scope","user"]
        #   [5]    = "--"  (end-of-options marker, M-5)
        #   [6]    = server_name ("splunk")
        #   [7]    = launch.command  <-- THIS is what we assert
        #   [8...] = launch.args + ["--env","K=V",...]
        assert argv[7] == self._ABSOLUTE_PATH

    def test_snippet_printer_receives_absolute_command(self) -> None:
        from spl_bridge.setup_wizard import _build_launch

        launch = _build_launch(self._make_config())
        result = mcp_clients.SnippetPrinter().write("splunk", launch)
        assert result.snippet["mcpServers"]["splunk"]["command"] == self._ABSOLUTE_PATH
