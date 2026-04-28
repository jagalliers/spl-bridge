"""Live Splunk REST connectivity probe used by the setup wizard.

Reuses the production :class:`SplunkClient` so what the wizard tests is
exactly what the runtime server will use (same TLS verification, same
auth header construction, same proxy semantics).
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass
from typing import Any

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.splunk_client import SplunkClient

logger = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    ok: bool
    server_name: str | None = None
    version: str | None = None
    error: str | None = None
    auth_mode: str | None = None


def probe(config: SplunkMCPConfig) -> ProbeResult:
    """Hit ``/services/server/info`` and return a structured outcome.

    Never raises -- the wizard wants to render the failure rather than
    crash mid-flow. We deliberately bypass the configured timeout for a
    snappier UX (5 s).
    """
    # Build a probe-only config with a tighter timeout.
    probe_config = SplunkMCPConfig(
        host=config.host,
        port=config.port,
        scheme=config.scheme,
        ssl_verify=config.ssl_verify,
        timeout=5.0,
        splunk_token=config.splunk_token,
        username=config.username,
        password=config.password,
        app=config.app,
        max_row_limit=config.max_row_limit,
        default_row_limit=config.default_row_limit,
        require_capabilities=False,
        rate_limits=None,
    )
    client = SplunkClient(probe_config)
    try:
        response = client.call_api(
            "GET",
            "/services/server/info",
            params={"output_mode": "json"},
        )
        status = response.status_code
        try:
            body = response.json()
        except ValueError:
            body = {}
        if status != 200:
            return ProbeResult(
                ok=False,
                error=f"Splunk returned HTTP {status}",
                auth_mode=probe_config.auth_mode,
            )
        info = _extract_server_info(body)
        return ProbeResult(
            ok=True,
            server_name=info.get("server_name"),
            version=info.get("version"),
            auth_mode=probe_config.auth_mode,
        )
    except Exception as exc:  # noqa: BLE001 -- wizard renders any error
        logger.debug("server/info probe failed", exc_info=True)
        return ProbeResult(
            ok=False,
            error=_short_error(exc),
            auth_mode=probe_config.auth_mode,
        )
    finally:
        # pragma: no cover -- best-effort cleanup
        with contextlib.suppress(Exception):
            client.close()


def _extract_server_info(body: Any) -> dict[str, str]:
    """Pull ``server_name`` and ``version`` out of ``server/info`` JSON.

    The endpoint returns one entry whose ``content`` carries the fields.
    Defensive against shape drift across Splunk versions.
    """
    out: dict[str, str] = {}
    if not isinstance(body, dict):
        return out
    entries = body.get("entry") or []
    if not entries or not isinstance(entries, list):
        return out
    content = entries[0].get("content") if isinstance(entries[0], dict) else None
    if not isinstance(content, dict):
        return out
    for key in ("serverName", "server_name", "host"):
        if key in content:
            out["server_name"] = str(content[key])
            break
    for key in ("version", "build"):
        if key in content:
            out["version"] = str(content[key])
            break
    return out


def _short_error(exc: BaseException) -> str:
    """Trim long upstream error messages to a single line for UI output."""
    text = str(exc).strip().replace("\n", " ")
    return text if len(text) <= 200 else text[:200] + "…"
