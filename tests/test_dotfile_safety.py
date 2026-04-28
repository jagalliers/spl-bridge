"""M-2 / M-3 / L-6: TOCTOU-safe and size-bounded dotfile reads.

These tests exercise the shared ``open_secret_file`` helper and the
``DotfileStore`` newline-rejection invariants. Symlink rejection is
POSIX-only (Windows does not expose ``O_NOFOLLOW``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from spl_bridge.setup_wizard.credstore import (
    MAX_SECRET_FILE_BYTES,
    DotfileStore,
    SecretFileError,
    open_secret_file,
)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only")


def _write_dotfile(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# M-2: TOCTOU / symlink defense
# ---------------------------------------------------------------------------


@posix_only
def test_open_secret_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("SPLUNK_TOKEN=stolen\n", encoding="utf-8")
    os.chmod(target, 0o600)

    link = tmp_path / "credentials"
    os.symlink(target, link)

    with pytest.raises(OSError) as excinfo:
        open_secret_file(link)
    # ELOOP on Linux/macOS when O_NOFOLLOW hits a symlink.
    assert excinfo.value.errno is not None


@posix_only
def test_open_secret_file_rejects_loose_permissions(tmp_path: Path) -> None:
    path = tmp_path / "credentials"
    path.write_text("SPLUNK_TOKEN=ok\n", encoding="utf-8")
    os.chmod(path, 0o644)

    with pytest.raises(SecretFileError, match="0600"):
        open_secret_file(path)


def test_open_secret_file_returns_contents_when_safe(tmp_path: Path) -> None:
    path = tmp_path / "credentials"
    _write_dotfile(path, "SPLUNK_TOKEN=abc123\n")
    assert "SPLUNK_TOKEN=abc123" in open_secret_file(path)


def test_open_secret_file_raises_filenotfound(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        open_secret_file(tmp_path / "missing")


def test_dotfile_store_read_handles_symlink_gracefully(tmp_path: Path) -> None:
    """``DotfileStore._read_all`` swallows :class:`SecretFileError`."""
    if sys.platform == "win32":
        pytest.skip("symlink test is POSIX-only")
    target = tmp_path / "target.txt"
    target.write_text("SPLUNK_TOKEN=stolen\n", encoding="utf-8")
    os.chmod(target, 0o600)

    link = tmp_path / "credentials"
    os.symlink(target, link)

    store = DotfileStore(path=link)
    # Must NOT return the contents of the symlink target.
    assert store._read_all() == {}


# ---------------------------------------------------------------------------
# L-6: size cap
# ---------------------------------------------------------------------------


def test_open_secret_file_rejects_oversize(tmp_path: Path) -> None:
    path = tmp_path / "credentials"
    _write_dotfile(path, "X" * (MAX_SECRET_FILE_BYTES + 1024))

    with pytest.raises(SecretFileError, match="too large"):
        open_secret_file(path)


def test_dotfile_store_oversize_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "credentials"
    _write_dotfile(path, "X" * (MAX_SECRET_FILE_BYTES + 1024))

    store = DotfileStore(path=path)
    assert store._read_all() == {}


# ---------------------------------------------------------------------------
# M-3: newline-injection defense
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_value", ["abc\nSPLUNK_HOST=evil", "abc\rmore", "ab\x00c"])
def test_dotfile_store_rejects_newlines_in_value(tmp_path: Path, bad_value: str) -> None:
    store = DotfileStore(path=tmp_path / "credentials")
    with pytest.raises(ValueError, match="newlines or NULs"):
        store.store("SPLUNK_TOKEN", bad_value)


def test_dotfile_store_accepts_normal_value(tmp_path: Path) -> None:
    store = DotfileStore(path=tmp_path / "credentials")
    store.store("SPLUNK_TOKEN", "abc123-fine")
    assert store.get("SPLUNK_TOKEN") == "abc123-fine"


# ---------------------------------------------------------------------------
# config.py integration: TOCTOU helper is used by ``_try_user_dotfile``
# ---------------------------------------------------------------------------


def test_config_dotfile_lookup_uses_safe_helper(tmp_path: Path, monkeypatch) -> None:
    """``spl_bridge.config._try_user_dotfile`` must refuse a symlinked credfile."""
    if sys.platform == "win32":
        pytest.skip("symlink test is POSIX-only")
    import platformdirs

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    monkeypatch.setattr(platformdirs, "user_config_dir", lambda _: str(cfg_dir))

    target = tmp_path / "secret.txt"
    target.write_text("SPLUNK_TOKEN=stolen\n", encoding="utf-8")
    os.chmod(target, 0o600)

    link = cfg_dir / "credentials"
    os.symlink(target, link)

    from spl_bridge.config import _try_user_dotfile

    assert _try_user_dotfile("SPLUNK_TOKEN") is None
