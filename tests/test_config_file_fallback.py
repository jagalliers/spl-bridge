"""G9: SPLUNK_TOKEN_FILE / SPLUNK_USERNAME_FILE / SPLUNK_PASSWORD_FILE
fallbacks - verify precedence (direct var beats file) and trailing
newline stripping."""

from __future__ import annotations

from pathlib import Path

import pytest

from spl_bridge.config import SplunkMCPConfig, _env_or_file, _read_secret_file

_SECRETS = (
    "SPLUNK_TOKEN",
    "SPLUNK_USERNAME",
    "SPLUNK_PASSWORD",
    "SPLUNK_TOKEN_FILE",
    "SPLUNK_USERNAME_FILE",
    "SPLUNK_PASSWORD_FILE",
    "SPLUNK_HOST",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in _SECRETS:
        monkeypatch.delenv(k, raising=False)


class TestReadSecretFile:
    def test_reads_and_strips_trailing_newline(self, tmp_path: Path) -> None:
        p = tmp_path / "tok"
        p.write_text("abc-token\n", encoding="utf-8")
        assert _read_secret_file(str(p)) == "abc-token"

    def test_keeps_internal_whitespace(self, tmp_path: Path) -> None:
        p = tmp_path / "tok"
        p.write_text("a b\nc", encoding="utf-8")
        assert _read_secret_file(str(p)) == "a b\nc"

    def test_empty_file_returns_none(self, tmp_path: Path) -> None:
        p = tmp_path / "empty"
        p.write_text("", encoding="utf-8")
        assert _read_secret_file(str(p)) is None

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert _read_secret_file(str(tmp_path / "nope")) is None


class TestEnvOrFile:
    def test_direct_env_takes_precedence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        f = tmp_path / "t"
        f.write_text("from-file", encoding="utf-8")
        monkeypatch.setenv("SPLUNK_TOKEN", "from-env")
        monkeypatch.setenv("SPLUNK_TOKEN_FILE", str(f))
        assert _env_or_file("SPLUNK_TOKEN") == "from-env"

    def test_file_used_when_env_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        f = tmp_path / "t"
        f.write_text("from-file\n", encoding="utf-8")
        monkeypatch.setenv("SPLUNK_TOKEN_FILE", str(f))
        assert _env_or_file("SPLUNK_TOKEN") == "from-file"

    def test_neither_returns_none(self) -> None:
        assert _env_or_file("SPLUNK_TOKEN") is None


class TestConfigFromEnvWithFiles:
    def test_token_file_loaded_via_from_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tok = tmp_path / "tok"
        tok.write_text("file-token\n", encoding="utf-8")
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN_FILE", str(tok))
        cfg = SplunkMCPConfig.from_env()
        assert cfg.splunk_token == "file-token"

    def test_password_file_pair_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        u = tmp_path / "u"
        u.write_text("admin", encoding="utf-8")
        p = tmp_path / "p"
        p.write_text("hunter2\n", encoding="utf-8")
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_USERNAME_FILE", str(u))
        monkeypatch.setenv("SPLUNK_PASSWORD_FILE", str(p))
        cfg = SplunkMCPConfig.from_env()
        assert cfg.username == "admin"
        assert cfg.password == "hunter2"
