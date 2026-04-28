"""Credential storage backends for the setup wizard.

Two backends, picked at wizard time and re-consulted at runtime via
``spl_bridge.config._resolve_secret``:

* :class:`KeyringStore` -- delegates to the OS keychain via the optional
  ``keyring`` library (macOS Keychain, Windows Credential Manager, Linux
  Secret Service / KWallet).
* :class:`DotfileStore` -- writes a ``key=value`` file under
  ``platformdirs.user_config_dir("spl-bridge")`` with mode ``0600``,
  atomic via ``os.replace``. Refuses to read files with looser perms.

Both backends know about a fixed allowlist of secret keys
(:data:`SECRET_KEYS`); writing anything else is rejected so we never
end up persisting a freeform value the user typed by mistake.
"""

from __future__ import annotations

import contextlib
import logging
import os
import stat
import sys
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

KEYRING_SERVICE = "spl-bridge"

# Only credentials live in the credstore. Connection metadata (host,
# port, scheme) goes into the MCP client config so the user can change
# environments without touching the keychain.
SECRET_KEYS = frozenset(
    {
        "SPLUNK_TOKEN",
        "SPLUNK_USERNAME",
        "SPLUNK_PASSWORD",
    }
)


def _validate_key(key: str) -> None:
    if key not in SECRET_KEYS:
        raise ValueError(
            f"Refusing to store unknown secret key {key!r} (allowed: {sorted(SECRET_KEYS)})"
        )


_BAD_VALUE_CHARS = ("\n", "\r", "\x00")


def _validate_value(value: str) -> None:
    """Reject values containing characters that would corrupt the dotfile.

    Newlines and carriage returns would split a value across lines and
    inject spurious ``KEY=VALUE`` pairs; NULs would terminate the C
    string interpretation in some downstream tools. Bandit / pasted
    secrets occasionally include a stray ``\\n`` from the clipboard.
    """
    if not isinstance(value, str):
        raise TypeError("secret value must be a string")
    for ch in _BAD_VALUE_CHARS:
        if ch in value:
            raise ValueError("secret value must not contain newlines or NULs")


@dataclass
class StoreResult:
    """Outcome reported back to the wizard for UI rendering."""

    backend: str
    location: str
    written_keys: list[str]


class CredStoreError(RuntimeError):
    """Raised when a backend cannot store a secret."""


class CredStore(ABC):
    """Abstract base for credential backends."""

    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """Cheap check that does not touch the user's keychain."""

    @abstractmethod
    def trial_write(self) -> bool:
        """Write + delete a sentinel value to confirm the backend works."""

    @abstractmethod
    def store(self, key: str, value: str) -> None:
        """Persist a single credential. Raises :class:`CredStoreError`."""

    @abstractmethod
    def get(self, key: str) -> str | None:
        """Read a credential, or ``None`` if not present."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Remove a credential if it exists. Idempotent."""

    @abstractmethod
    def location(self) -> str:
        """Human-readable location string for the wizard summary."""


# ---------------------------------------------------------------------------
# Keyring backend
# ---------------------------------------------------------------------------


class KeyringStore(CredStore):
    """Backed by the OS keychain via the optional ``keyring`` library."""

    name = "keyring"

    def __init__(self) -> None:
        self._keyring = None
        try:
            import keyring
            from keyring.errors import KeyringError  # noqa: F401
        except ImportError as exc:
            raise CredStoreError(
                "The optional `keyring` extra is not installed. "
                "Install with `pip install 'spl-bridge[keyring]'`."
            ) from exc
        self._keyring = keyring

    def is_available(self) -> bool:
        if self._keyring is None:
            return False
        backend = self._keyring.get_keyring()
        backend_name = type(backend).__module__ + "." + type(backend).__name__
        return bool(not backend_name.endswith(".fail.Keyring"))

    def trial_write(self) -> bool:
        if self._keyring is None:
            return False
        sentinel_key = "__spl_bridge_probe__"
        try:
            self._keyring.set_password(KEYRING_SERVICE, sentinel_key, "ok")
            value = self._keyring.get_password(KEYRING_SERVICE, sentinel_key)
            self._keyring.delete_password(KEYRING_SERVICE, sentinel_key)
            return bool(value == "ok")
        except Exception:
            logger.debug("Keyring trial write failed", exc_info=True)
            return False

    def store(self, key: str, value: str) -> None:
        _validate_key(key)
        _validate_value(value)
        assert self._keyring is not None
        try:
            self._keyring.set_password(KEYRING_SERVICE, key, value)
        except Exception as exc:  # noqa: BLE001 -- map to typed error
            raise CredStoreError(f"Keyring write for {key} failed: {exc}") from exc

    def get(self, key: str) -> str | None:
        _validate_key(key)
        if self._keyring is None:
            return None
        try:
            value = self._keyring.get_password(KEYRING_SERVICE, key)
            return str(value) if value is not None else None
        except Exception:
            logger.debug("Keyring read for %s failed", key, exc_info=True)
            return None

    def delete(self, key: str) -> None:
        _validate_key(key)
        if self._keyring is None:
            return
        try:
            self._keyring.delete_password(KEYRING_SERVICE, key)
        except Exception:  # noqa: BLE001 -- delete-of-missing is fine
            logger.debug("Keyring delete for %s skipped", key, exc_info=True)

    def location(self) -> str:
        if self._keyring is None:
            return "(keyring not installed)"
        backend = self._keyring.get_keyring()
        return f"{type(backend).__module__}.{type(backend).__name__}"


# ---------------------------------------------------------------------------
# Dotfile backend
# ---------------------------------------------------------------------------


def _user_config_dir() -> Path:
    """Per-OS user config directory (XDG / Library / AppData)."""
    import platformdirs

    return Path(platformdirs.user_config_dir(KEYRING_SERVICE, ensure_exists=False))


def _atomic_write(path: Path, body: str) -> None:
    """Write ``body`` to ``path`` atomically with mode 0600.

    Strategy:

    1. Create a temp file in the same directory with ``mkstemp`` so we
       inherit a private mode (0600 on POSIX, ACLs on Windows).
    2. Write the body, fsync, close.
    3. ``os.replace`` to the target; rename is atomic on the same FS.
    4. ``os.chmod`` afterwards as a belt-and-suspenders for non-POSIX.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except Exception:
        # Best-effort cleanup of the temp file if rename failed.
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    # Re-tighten perms after replace (umask may have widened them).
    if sys.platform != "win32":
        os.chmod(path, 0o600)


MAX_SECRET_FILE_BYTES = 64 * 1024


class SecretFileError(OSError):
    """Raised when a secret file cannot be safely opened or read.

    Distinct from a missing-file ``FileNotFoundError`` so callers can
    surface "exists but unsafe" cases differently (we currently fall
    back to "no value", but logging makes the cause auditable).
    """


def open_secret_file(path: Path) -> str:
    """Open ``path`` and return its contents, defending against TOCTOU.

    Closes the file descriptor before returning. The same descriptor is
    used for the permission check (via :func:`os.fstat`) and the read,
    so an attacker cannot swap a symlink between the two operations.

    On POSIX, ``O_NOFOLLOW`` rejects symlinks outright (a legitimate
    credentials file is owned and written by the user; symlinks are a
    smell). On Windows, ``O_NOFOLLOW`` is unavailable; ACL checks are
    delegated to the OS.

    Refuses files larger than :data:`MAX_SECRET_FILE_BYTES` (64 KiB) to
    cap the memory cost of an attacker-mounted file.

    Raises :class:`FileNotFoundError` if the path does not exist, and
    :class:`SecretFileError` for permission/symlink/size failures so the
    caller can return ``None`` and log without aborting startup.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if sys.platform != "win32":
            if not stat.S_ISREG(st.st_mode):
                raise SecretFileError(f"Refusing to read {path}: not a regular file")
            mode = stat.S_IMODE(st.st_mode)
            if mode != 0o600:
                raise SecretFileError(
                    f"Refusing to read {path} -- mode is 0{mode:o}, expected 0600. "
                    f"Run `chmod 600 {path}` to fix."
                )
        if st.st_size > MAX_SECRET_FILE_BYTES:
            raise SecretFileError(
                f"Refusing to read {path}: secret file too large "
                f"({st.st_size} bytes > {MAX_SECRET_FILE_BYTES})"
            )
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            fd = -1  # ownership transferred to the file object
            return fh.read(MAX_SECRET_FILE_BYTES + 1)[:MAX_SECRET_FILE_BYTES]
    finally:
        if fd != -1:
            with contextlib.suppress(OSError):
                os.close(fd)


def _check_perms(path: Path) -> bool:
    """Refuse to read a dotfile that isn't 0600 on POSIX systems.

    Retained for backwards compatibility with tests that exercise the
    permission-only path; production reads go through
    :func:`open_secret_file` which performs the same check on the open
    file descriptor (TOCTOU-safe).
    """
    if sys.platform == "win32":
        return True
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return False
    if mode != 0o600:
        logger.warning(
            "Refusing to read %s -- mode is 0%o, expected 0600. Run `chmod 600 %s` to fix.",
            path,
            mode,
            path,
        )
        return False
    return True


class DotfileStore(CredStore):
    """Plain ``KEY=VALUE\\n`` file under the user config dir, mode 0600."""

    name = "dotfile"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or (_user_config_dir() / "credentials")

    @property
    def path(self) -> Path:
        return self._path

    def is_available(self) -> bool:
        # Only constraint: we can write to (or create) the parent dir.
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            return os.access(self._path.parent, os.W_OK)
        except OSError:
            return False

    def trial_write(self) -> bool:
        try:
            sentinel = self._path.parent / ".write_probe"
            sentinel.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(sentinel, "ok\n")
            sentinel.unlink()
            return True
        except OSError:
            logger.debug("Dotfile trial write failed", exc_info=True)
            return False

    def _read_all(self) -> dict[str, str]:
        """Parse the dotfile or return ``{}`` if missing / unreadable."""
        try:
            text = open_secret_file(self._path)
        except FileNotFoundError:
            return {}
        except SecretFileError as exc:
            logger.warning("%s", exc)
            return {}
        except OSError:
            logger.warning("Could not read %s", self._path, exc_info=True)
            return {}
        out: dict[str, str] = {}
        for line in text.splitlines():
            line = line.rstrip("\r")
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key in SECRET_KEYS:
                out[key] = value
        return out

    def _write_all(self, payload: dict[str, str]) -> None:
        body_lines = [
            "# spl-bridge credentials -- DO NOT commit",
            "# Stored at user_config_dir, mode 0600.",
        ]
        for key in sorted(payload):
            body_lines.append(f"{key}={payload[key]}")
        body_lines.append("")
        _atomic_write(self._path, "\n".join(body_lines))

    def store(self, key: str, value: str) -> None:
        _validate_key(key)
        _validate_value(value)
        existing = self._read_all()
        existing[key] = value
        self._write_all(existing)

    def get(self, key: str) -> str | None:
        _validate_key(key)
        return self._read_all().get(key)

    def delete(self, key: str) -> None:
        _validate_key(key)
        existing = self._read_all()
        if existing.pop(key, None) is not None:
            self._write_all(existing)

    def location(self) -> str:
        return str(self._path)


# ---------------------------------------------------------------------------
# Backend selection helper
# ---------------------------------------------------------------------------


def select_backend(prefer_keyring: bool = True) -> CredStore:
    """Pick the best available backend for the host.

    Falls back to :class:`DotfileStore` if keyring is unavailable, not
    requested, or fails its trial write (Linux without Secret Service is
    the common case).
    """
    if prefer_keyring:
        try:
            store: CredStore = KeyringStore()
        except CredStoreError:
            store = DotfileStore()
        else:
            if store.is_available() and store.trial_write():
                return store
            logger.info("Keyring backend unusable, falling back to dotfile.")
            store = DotfileStore()
    else:
        store = DotfileStore()
    if not store.trial_write():
        raise CredStoreError(
            f"Cannot write to credential location {store.location()!r}. "
            "Check filesystem permissions."
        )
    return store


def all_secret_keys() -> Iterable[str]:
    """Public accessor for callers that don't want to import the frozenset."""
    return SECRET_KEYS
