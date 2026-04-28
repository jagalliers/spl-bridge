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
):
    """Helper: install scripted input/getpass/keyring and run main()."""
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
        # Cursor config written
        cursor = json.loads(cursor_path.read_text())
        assert cursor["mcpServers"]["splunk"]["command"] == "spl-bridge"
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

    def test_non_tty_aborts(self, monkeypatch) -> None:
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        rc = wizard_main()
        assert rc == 2
