"""H3 regression test: concurrent ``get_auth_header`` calls must POST to
``/services/auth/login`` exactly once even when many threads race.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest

from spl_bridge import auth
from spl_bridge.config import SplunkMCPConfig


def _make_config() -> SplunkMCPConfig:
    return SplunkMCPConfig(
        host="splunk.example.com",
        port=8089,
        scheme="https",
        ssl_verify=False,
        username="lab_user",
        password="lab_pw",
    )


class _FakeResponse:
    status_code = 200

    def json(self) -> dict[str, str]:
        return {"sessionKey": "k-from-login"}


@pytest.fixture(autouse=True)
def _reset_state():
    auth.reset_session()
    yield
    auth.reset_session()


def test_concurrent_get_auth_header_logs_in_exactly_once() -> None:
    """20 threads racing on the first call must produce one login POST."""

    call_count = 0
    call_lock = threading.Lock()

    def fake_post(*_args, **_kwargs):
        nonlocal call_count
        with call_lock:
            call_count += 1
        # Tiny sleep widens the race window so a missing lock would
        # almost certainly drop a duplicate POST.
        time.sleep(0.05)
        return _FakeResponse()

    config = _make_config()
    headers: list[str] = []
    headers_lock = threading.Lock()
    barrier = threading.Barrier(20)

    def worker() -> None:
        barrier.wait()
        h = auth.get_auth_header(config)
        with headers_lock:
            headers.append(h)

    with patch("spl_bridge.auth.requests.post", side_effect=fake_post):
        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    assert call_count == 1, f"Expected 1 login, saw {call_count}"
    assert len(headers) == 20
    assert all(h == "Splunk k-from-login" for h in headers)


def test_invalidate_session_then_concurrent_relogin() -> None:
    """After ``invalidate_session`` a new wave of callers re-logs in once."""

    call_count = 0
    call_lock = threading.Lock()

    def fake_post(*_args, **_kwargs):
        nonlocal call_count
        with call_lock:
            call_count += 1
        time.sleep(0.02)
        return _FakeResponse()

    config = _make_config()
    with patch("spl_bridge.auth.requests.post", side_effect=fake_post):
        # First wave caches the key.
        auth.get_auth_header(config)
        assert call_count == 1
        auth.invalidate_session()
        # Restore the password (login_with_password clears it after success).
        object.__setattr__(config, "password", "lab_pw")

        barrier = threading.Barrier(10)

        def worker() -> None:
            barrier.wait()
            auth.get_auth_header(config)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    assert call_count == 2, f"Expected 1 initial + 1 relogin, saw {call_count}"


def test_token_mode_skips_lock_path() -> None:
    """Token-mode auth header must not touch the session lock."""
    config = SplunkMCPConfig(
        host="splunk.example.com",
        splunk_token="abc123",
    )
    # Acquire the lock from a sibling thread; token-mode caller must not block.
    held = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with auth._session_lock:
            held.set()
            release.wait(timeout=2)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    held.wait(timeout=1)
    try:
        # Should return immediately even though the lock is held elsewhere.
        out = auth.get_auth_header(config)
        assert out == "Splunk abc123"
    finally:
        release.set()
        holder.join()
