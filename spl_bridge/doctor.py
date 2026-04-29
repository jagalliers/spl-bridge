"""Connectivity checks for Splunk REST (all output via logging -> stderr).

Two operator entry points live here:

* :func:`run_doctor` -- the historical "is Splunk reachable?" probe.
  Loads ``SplunkMCPConfig`` from env / dotfile / keychain and walks
  TLS, auth, the search parser, and the search export endpoint.
* :func:`run_host_scan` -- new in the ``--hosts`` flag. Inspects the
  user's MCP host JSON configs (Cursor, Claude Desktop) for any
  ``spl-bridge`` entries whose ``command`` is a bare basename rather
  than an absolute path. PATH-stripped GUI hosts (notably Claude
  Desktop on macOS) cannot resolve a bare ``spl-bridge`` and fail to
  spawn the server. Setup wizards on or after the absolute-path fix
  always write the resolved path; this scan exists so users with
  pre-fix configs can self-diagnose.

Both entry points emit only via ``logging`` (never ``print``) so they
can be safely chained after ``serve`` without corrupting MCP framing.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import requests
import urllib3

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.logging_config import configure_logging
from spl_bridge.setup_wizard.mcp_clients import (
    claude_desktop_config_path,
    cursor_config_path,
)
from spl_bridge.splunk_client import SplunkClient

logger = logging.getLogger(__name__)


# Basenames we recognize as "this is one of our entries". Anything
# else in the user's mcpServers map (npx, python, other binaries) is
# left alone -- ``spl-bridge`` should not opine on third-party MCP
# server hygiene.
_SPL_BRIDGE_BASENAMES = frozenset({"spl-bridge", "spl-bridge.exe"})


def _check_tls_base(config: SplunkMCPConfig) -> None:
    url = f"{config.base_url}/"
    if config.ssl_verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    requests.get(url, verify=config.ssl_verify, timeout=config.timeout)


def _check_current_context(client: SplunkClient) -> None:
    resp = client.call_api(
        "GET", "services/authentication/current-context", params={"output_mode": "json"}
    )
    if resp.status_code != 200:
        raise RuntimeError(f"current-context failed: HTTP {resp.status_code}")
    logger.info(
        "Authenticated as: %s",
        resp.json().get("entry", [{}])[0].get("content", {}).get("username", "unknown"),
    )


def _check_parser(client: SplunkClient) -> None:
    resp = client.call_api(
        "POST",
        "services/search/parser",
        data={"q": "search *", "expand_macros": "0", "output_mode": "json", "parse_only": "1"},
    )
    if resp.status_code != 200:
        raise RuntimeError(f"parser endpoint failed: HTTP {resp.status_code}")


def _check_export(client: SplunkClient) -> None:
    resp = client.call_api(
        "POST",
        "services/search/jobs/export",
        data={"search": "| makeresults count=1", "output_mode": "json", "preview": "false"},
    )
    if resp.status_code != 200:
        raise RuntimeError(f"export endpoint failed: HTTP {resp.status_code}")
    if not resp.text.strip():
        raise RuntimeError("export endpoint returned empty body")


def run_doctor() -> None:
    """Run connectivity checks; log to stderr only; exit 1 on failure."""
    configure_logging()
    try:
        logger.info("Loading configuration from environment")
        config = SplunkMCPConfig.from_env()
        logger.info(
            "Config OK (host=%s, port=%s, auth_mode=%s)", config.host, config.port, config.auth_mode
        )

        logger.info("Testing TLS connection")
        _check_tls_base(config)
        logger.info("TLS OK")

        client = SplunkClient(config)

        logger.info("Testing auth via current-context")
        _check_current_context(client)
        logger.info("Auth OK")

        logger.info("Testing search parser endpoint")
        _check_parser(client)
        logger.info("Parser OK")

        logger.info("Testing search export endpoint")
        _check_export(client)
        logger.info("Export OK")

        logger.info("All checks passed")
    except Exception as exc:
        logger.error("Doctor failed: %s", exc)
        sys.exit(1)


# ---------------------------------------------------------------------------
# MCP host config scan (`spl-bridge doctor --hosts`)
# ---------------------------------------------------------------------------


def _scan_one_config(target_name: str, config_path: Path) -> int:
    """Scan a single MCP host JSON config for problematic spl-bridge entries.

    Returns the count of warnings emitted (0 == clean / nothing to scan).

    Defensive parsing: a missing file is informational (the user just
    hasn't configured that host); a malformed file is a warning that
    asks the operator to look at it. Entries whose ``command``
    basename isn't ours are silently ignored -- the scanner is not in
    the business of opining on third-party MCP server entries.
    """
    if not config_path.exists():
        logger.info("%s: no config at %s (nothing to scan)", target_name, config_path)
        return 0
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("%s: cannot read %s: %s", target_name, config_path, exc)
        return 1
    if not text.strip():
        logger.info("%s: config at %s is empty (nothing to scan)", target_name, config_path)
        return 0
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning(
            "%s: config at %s is not valid JSON: %s -- skipping scan",
            target_name,
            config_path,
            exc,
        )
        return 1
    if not isinstance(data, dict):
        logger.warning("%s: %s is not a JSON object -- skipping scan", target_name, config_path)
        return 1
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        logger.info("%s: no mcpServers section in %s (nothing to scan)", target_name, config_path)
        return 0

    warnings = 0
    spl_bridge_entries = 0
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        cmd = entry.get("command")
        if not isinstance(cmd, str) or not cmd:
            continue
        # Match by basename (case-insensitive on Windows, where the
        # `.exe` may or may not be capitalized).
        cmd_basename = Path(cmd).name.lower()
        if cmd_basename not in _SPL_BRIDGE_BASENAMES:
            continue
        spl_bridge_entries += 1
        if Path(cmd).is_absolute():
            logger.info(
                "%s: entry %r in %s uses absolute command %s (OK)",
                target_name,
                name,
                config_path,
                cmd,
            )
        else:
            warnings += 1
            logger.warning(
                "%s: entry %r in %s uses bare command %r; "
                "may fail to launch from MCP hosts with stripped PATH "
                "(notably Claude Desktop on macOS). Re-run "
                "`spl-bridge setup` to overwrite with an absolute path, "
                "or manually replace with the output of `command -v spl-bridge`.",
                target_name,
                name,
                config_path,
                cmd,
            )

    if spl_bridge_entries == 0:
        logger.info("%s: no spl-bridge entries in %s", target_name, config_path)
    return warnings


def run_host_scan() -> None:
    """Scan known MCP host configs for bare-command spl-bridge entries.

    Logs each finding to stderr (info for clean, warning for suspect)
    and exits 1 if any warnings were emitted. The Splunk REST surface
    is intentionally NOT touched -- this is a config-shape audit only,
    so it works even when the Splunk endpoint is unreachable.

    Targets scanned:

    * Cursor user-scope config (``~/.cursor/mcp.json``)
    * Claude Desktop per-OS config

    Claude Code (the ``claude`` CLI) is not scanned because its
    persistent registration lives in ``~/.claude.json`` under a schema
    that is the CLI's private API; reading it requires shelling out to
    ``claude mcp list --json`` and is left as a future enhancement.
    """
    configure_logging()
    targets: list[tuple[str, Path]] = [
        ("Cursor", cursor_config_path()),
        ("Claude Desktop", claude_desktop_config_path()),
    ]
    total_warnings = 0
    for name, path in targets:
        total_warnings += _scan_one_config(name, path)
    if total_warnings:
        logger.error(
            "Found %d MCP host config issue(s); see warnings above for remediation.",
            total_warnings,
        )
        sys.exit(1)
    logger.info("All scanned MCP host configs look healthy.")
