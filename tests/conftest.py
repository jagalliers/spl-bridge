"""Shared fixtures for the spl-bridge test suite.

The suite must be hermetic against a developer's *real* spl-bridge
setup: ``config._resolve_secret()`` deliberately falls back to the OS
keychain and to a credentials dotfile under
``platformdirs.user_config_dir("spl-bridge")`` — both of which exist on
any machine where ``spl-bridge setup`` has been run. Without isolation,
tests like ``test_config.py::test_missing_auth_raises`` fail (the real
dotfile supplies credentials) and others silently depend on what the
real dotfile happens to contain.
"""

from __future__ import annotations

import sys

import pytest


class FakeKeyring:
    """In-memory stand-in for the ``keyring`` module.

    ``fail_class=True`` synthesises a backend whose qualified name ends
    in ``.fail.Keyring`` — the sentinel both ``config._try_keyring`` and
    ``credstore.KeyringStore`` treat as "no usable backend".
    """

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


@pytest.fixture(autouse=True)
def _isolate_user_secret_stores(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Keep every test away from the developer's real secret stores.

    - ``platformdirs.user_config_dir`` → per-test temp dir, so the
      dotfile layer never sees ``~/Library/Application Support/spl-bridge``
      (or the XDG/Windows equivalents). Covers both ``config.py`` and
      ``setup_wizard/credstore.py``, which import platformdirs lazily.
    - ``keyring`` → in-memory fake with a fail-class backend, so the
      keychain layer resolves nothing and never touches the real OS
      keychain. Tests that exercise keyring behaviour install their own
      fakes on top of this one.
    """
    import platformdirs

    monkeypatch.setattr(
        platformdirs,
        "user_config_dir",
        lambda *_a, **_k: str(tmp_path / "user-config"),
    )
    monkeypatch.setitem(sys.modules, "keyring", FakeKeyring(fail_class=True))
