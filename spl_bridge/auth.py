"""Splunk REST authentication helpers.

Secrets (tokens, passwords, session keys) are NEVER logged or written to disk.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

import requests

from spl_bridge.config import SplunkMCPConfig

logger = logging.getLogger(__name__)

# H3: ``_session_state`` is process-global mutable state. Callers can come from
# multiple FastMCP request handler threads, so every read-or-update sequence is
# guarded by ``_session_lock``. ``login_with_password`` itself does network
# I/O while holding the lock; that's intentional -- it serialises concurrent
# first-time-login races so we POST to ``/services/auth/login`` exactly once.
_session_state: dict[str, Any] = {
    "session_key": None,
    "username": None,
}
_session_lock = threading.Lock()


class SplunkLoginError(RuntimeError):
    """Raised when ``/services/auth/login`` does not return a sessionKey.

    The message intentionally does not interpolate the response body.
    """


def reset_session() -> None:
    """Clear cached password-auth session state (for tests and re-auth flow)."""
    with _session_lock:
        _session_state["session_key"] = None
        _session_state["username"] = None


def invalidate_session() -> None:
    """Drop any cached session key so the next call re-authenticates."""
    with _session_lock:
        _session_state["session_key"] = None


def login_with_password(config: SplunkMCPConfig) -> str:
    """POST /services/auth/login and return sessionKey (in-memory only).

    Never propagates the upstream response body in raised exceptions: only the
    HTTP status code and a generic message reach the caller.
    """
    if not config.password:
        # G5: password was cleared after the original successful login.
        # Re-authentication in this process is not possible -- the operator
        # must restart the server.
        raise SplunkLoginError(
            "Cannot re-authenticate: password no longer in memory"
            " (server restart required for lab password mode)"
        )

    url = f"{config.base_url}/services/auth/login"
    data = {
        "username": config.username,
        "password": config.password,
        "output_mode": "json",
    }
    logger.info("Authenticating to Splunk via /services/auth/login")
    try:
        response = requests.post(url, data=data, verify=config.ssl_verify, timeout=config.timeout)
    except requests.RequestException as exc:
        logger.error("Splunk login request failed: %s", exc)
        raise SplunkLoginError("Splunk login request failed") from None

    if response.status_code != 200:
        logger.error(
            "Splunk login HTTP %s (body redacted from exception)",
            response.status_code,
        )
        raise SplunkLoginError(f"Splunk login failed (HTTP {response.status_code})")

    try:
        payload = response.json()
        session_key = payload.get("sessionKey")
    except ValueError:
        raise SplunkLoginError("Splunk login returned invalid JSON") from None

    if not session_key:
        raise SplunkLoginError("Splunk login response missing sessionKey")

    logger.info("Splunk login succeeded")

    # Best-effort password zeroisation (G5).  Python cannot guarantee that
    # the underlying string buffer is wiped, but dropping the reference
    # narrows the window during which the password lives in memory and
    # prevents any later code path from re-reading it from the config.
    #
    # This intentionally means that if the session key later expires the
    # one-shot 401/403 retry in ``SplunkClient.call_api`` will fail and the
    # server must be restarted -- the right tradeoff for a "lab only"
    # password mode.  See README "Known limitations".
    try:
        object.__setattr__(config, "password", None)
    except Exception:  # pragma: no cover - frozen dataclass should accept this
        logger.debug("Unable to clear password reference on config")

    return str(session_key)


def _token_authorization_value(token: str) -> str:
    if token.startswith("eyJ"):
        return f"Bearer {token}"
    return f"Splunk {token}"


def get_auth_header(config: SplunkMCPConfig) -> str:
    """Return the Authorization header value (Bearer or Splunk prefix).

    Token mode: pure function, no shared state.

    Password mode: serialises concurrent first-time logins under
    ``_session_lock`` so ``/services/auth/login`` is hit exactly once even
    under concurrent FastMCP request handlers.
    """
    if config.splunk_token:
        return _token_authorization_value(config.splunk_token)

    with _session_lock:
        if config.username != _session_state.get("username"):
            _session_state["session_key"] = None
            _session_state["username"] = config.username

        session_key = _session_state.get("session_key")
        if not session_key:
            # Holding the lock across the network call is intentional --
            # the alternative (release-then-relogin) lets N callers each
            # POST to /services/auth/login. The login endpoint is fast
            # and rarely called.
            session_key = login_with_password(config)
            _session_state["session_key"] = session_key
            _session_state["username"] = config.username

        return f"Splunk {session_key}"
