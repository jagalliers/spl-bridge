"""Configuration for Splunk MCP server, loaded from environment variables.

Secrets (tokens, passwords) are NEVER logged. Token mode takes precedence
over password mode when both are set.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


_MAX_SECRET_FILE_BYTES = 64 * 1024
_MAX_RATE_LIMIT_VALUE = 1_000_000  # L-5: cap deque allocation per (window, limit).
_MAX_RESPONSE_BYTES_HARDCAP = 1 * 1024 * 1024 * 1024  # L-2: 1 GiB upper bound.


def _read_secret_file(path: str) -> str | None:
    """Read a secret from a file, stripping a single trailing newline.

    Errors are downgraded to a warning -- callers fall back to the
    plain ``*_TOKEN`` / ``*_USERNAME`` / ``*_PASSWORD`` env var.

    Refuses to read files larger than 64 KiB to bound memory exposure
    if an attacker can influence the path.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = fh.read(_MAX_SECRET_FILE_BYTES + 1)
    except OSError as exc:
        logger.warning("Could not read secret file %s: %s", path, exc)
        return None
    if len(data) > _MAX_SECRET_FILE_BYTES:
        logger.warning(
            "Refusing to use secret file %s: larger than %d bytes",
            path,
            _MAX_SECRET_FILE_BYTES,
        )
        return None
    if data.endswith("\n"):
        data = data[:-1]
    return data or None


def _env_or_file(env_key: str) -> str | None:
    """Return the value of ``env_key`` or, if absent, the contents of the
    file referenced by ``${env_key}_FILE``.

    The plain env var takes precedence so existing setups keep working.
    """
    direct = os.environ.get(env_key)
    if direct:
        return direct
    file_key = f"{env_key}_FILE"
    file_path = os.environ.get(file_key)
    if file_path:
        return _read_secret_file(file_path)
    return None


def _try_keyring(env_key: str) -> str | None:
    """Best-effort keyring lookup. Returns ``None`` on any failure.

    The keyring extra is optional: importing must not crash the server
    when the user installed the base distribution.
    """
    try:
        import keyring
    except ImportError:
        return None
    try:
        backend = keyring.get_keyring()
        backend_name = type(backend).__module__ + "." + type(backend).__name__
        if backend_name.endswith(".fail.Keyring"):
            return None
        result = keyring.get_password("spl-bridge", env_key)
        return str(result) if result is not None else None
    except Exception:
        logger.debug("Keyring read for %s failed", env_key, exc_info=True)
        return None


def _try_user_dotfile(env_key: str) -> str | None:
    """Best-effort dotfile lookup; refuses files with looser perms than 0600.

    Uses :func:`spl_bridge.setup_wizard.credstore.open_secret_file` so
    the permission check and read share a single file descriptor, which
    closes the TOCTOU window between ``stat`` and ``read``.
    """
    try:
        import platformdirs
    except ImportError:
        return None
    from pathlib import Path

    from spl_bridge.setup_wizard.credstore import (
        SecretFileError,
        open_secret_file,
    )

    path = Path(platformdirs.user_config_dir("spl-bridge")) / "credentials"
    try:
        text = open_secret_file(path)
    except FileNotFoundError:
        return None
    except SecretFileError as exc:
        logger.warning("%s", exc)
        return None
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
        return None
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == env_key:
            return value or None
    return None


def _resolve_secret(env_key: str) -> str | None:
    """Resolve a credential by trying, in order:

    1. ``$ENV_KEY`` direct env var
    2. ``$ENV_KEY_FILE`` env var pointing at a secret file
    3. OS keychain via the optional ``keyring`` extra
    4. ``$XDG_CONFIG_HOME/spl-bridge/credentials`` (mode 0600 only)

    Returns ``None`` if none of the four sources yields a non-empty
    value. Each source is tried in isolation so a misconfigured layer
    cannot prevent a later layer from succeeding.
    """
    value = _env_or_file(env_key)
    if value:
        return value
    value = _try_keyring(env_key)
    if value:
        return value
    return _try_user_dotfile(env_key)


def _parse_ssl_verify(raw: str) -> bool | str:
    lowered = raw.strip().lower()
    if lowered in ("true", "1", "yes"):
        return True
    if lowered in ("false", "0", "no"):
        return False
    return raw.strip()


@dataclass(frozen=True)
class SplunkMCPConfig:
    """Immutable connection and behavior settings for Splunk REST calls."""

    host: str
    port: int = 8089
    scheme: str = "https"
    ssl_verify: bool | str = True
    timeout: float = 60.0

    splunk_token: str | None = None
    username: str | None = None
    password: str | None = None

    app: str | None = None
    max_row_limit: int = 1000
    default_row_limit: int = 100
    require_capabilities: bool = False
    rate_limits: dict[str, int] | None = None
    max_response_bytes: int = 64 * 1024 * 1024  # 64 MiB; L-2 cap on Splunk responses.

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def auth_mode(self) -> str:
        if self.splunk_token:
            return "token"
        if self.username and self.password:
            return "password"
        return "none"

    def services_prefix(self) -> str:
        if self.app:
            return f"/servicesNS/-/{self.app}"
        return "/services"

    @classmethod
    def from_env(cls) -> SplunkMCPConfig:
        host = os.environ.get("SPLUNK_HOST", "")
        if not host:
            raise OSError("SPLUNK_HOST must be set (e.g. 'splunk.example.com')")

        port = int(os.environ.get("SPLUNK_PORT", "8089"))
        scheme = os.environ.get("SPLUNK_SCHEME", "https")
        ssl_verify = _parse_ssl_verify(os.environ.get("SPLUNK_VERIFY_SSL", "true"))
        timeout = float(os.environ.get("MCP_TIMEOUT", "60.0"))

        splunk_token = _resolve_secret("SPLUNK_TOKEN")
        username = _resolve_secret("SPLUNK_USERNAME")
        password = _resolve_secret("SPLUNK_PASSWORD")

        if splunk_token and (username or password):
            logger.warning(
                "Both SPLUNK_TOKEN and SPLUNK_USERNAME/PASSWORD set; token takes precedence"
            )

        if not splunk_token and not (username and password):
            raise OSError(
                "Set SPLUNK_TOKEN for token auth, or both "
                "SPLUNK_USERNAME and SPLUNK_PASSWORD for lab password auth"
            )

        app = os.environ.get("SPLUNK_APP") or None
        max_row_limit = int(os.environ.get("MCP_MAX_ROW_LIMIT", "1000"))
        default_row_limit = int(os.environ.get("MCP_DEFAULT_ROW_LIMIT", "100"))

        require_capabilities = os.environ.get("MCP_REQUIRE_CAPABILITIES", "").lower() in (
            "true",
            "1",
            "yes",
        )

        max_response_bytes_raw = os.environ.get("MCP_MAX_RESPONSE_BYTES", "")
        if max_response_bytes_raw.strip():
            try:
                max_response_bytes = int(max_response_bytes_raw)
            except ValueError as exc:
                raise ValueError("MCP_MAX_RESPONSE_BYTES must be a positive integer") from exc
            if max_response_bytes <= 0:
                raise ValueError("MCP_MAX_RESPONSE_BYTES must be a positive integer")
            if max_response_bytes > _MAX_RESPONSE_BYTES_HARDCAP:
                raise ValueError(
                    f"MCP_MAX_RESPONSE_BYTES {max_response_bytes} exceeds hard cap "
                    f"{_MAX_RESPONSE_BYTES_HARDCAP}"
                )
        else:
            max_response_bytes = SplunkMCPConfig.__dataclass_fields__["max_response_bytes"].default  # type: ignore[assignment]

        rate_limits_raw = os.environ.get("MCP_RATE_LIMITS", "")
        rate_limits: dict[str, int] | None = None
        if rate_limits_raw.strip():
            try:
                parsed = json.loads(rate_limits_raw)
            except json.JSONDecodeError as exc:
                logger.warning("MCP_RATE_LIMITS ignored (invalid JSON): %s", exc)
                parsed = None
            if isinstance(parsed, dict):
                coerced: dict[str, int] = {}
                for k, v in parsed.items():
                    try:
                        ivalue = int(v)
                    except (ValueError, TypeError) as exc:
                        raise ValueError(
                            f"MCP_RATE_LIMITS rate limit for {k!r} must be an integer"
                        ) from exc
                    if ivalue < 0 or ivalue > _MAX_RATE_LIMIT_VALUE:
                        raise ValueError(
                            f"MCP_RATE_LIMITS rate limit for {k!r} out of range "
                            f"[0, {_MAX_RATE_LIMIT_VALUE}]: {ivalue}"
                        )
                    coerced[str(k)] = ivalue
                rate_limits = coerced

        if ssl_verify is False:
            logger.warning("SPLUNK_VERIFY_SSL=false: TLS certificate verification disabled")

        # L-4: Refuse to ship a token over plaintext HTTP unless the operator
        # explicitly opted in. ``scheme=http`` is itself worth a WARNING in
        # any case (no transport encryption, no integrity).
        if scheme == "http":
            logger.warning(
                "SPLUNK_SCHEME=http: traffic to Splunk is unencrypted "
                "and unauthenticated at the transport layer"
            )
            if splunk_token and os.environ.get("SPLUNK_ALLOW_PLAINTEXT", "").lower() not in (
                "1",
                "true",
                "yes",
            ):
                raise ValueError(
                    "refusing to send Splunk token over HTTP; "
                    "set SPLUNK_ALLOW_PLAINTEXT=1 to override "
                    "(strongly discouraged outside a closed lab)"
                )

        return cls(
            host=host,
            port=port,
            scheme=scheme,
            ssl_verify=ssl_verify,
            timeout=timeout,
            splunk_token=splunk_token,
            username=username,
            password=password,
            app=app,
            max_row_limit=max_row_limit,
            default_row_limit=default_row_limit,
            require_capabilities=require_capabilities,
            rate_limits=rate_limits,
            max_response_bytes=max_response_bytes,
        )
