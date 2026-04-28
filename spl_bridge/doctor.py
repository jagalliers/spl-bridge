"""Connectivity checks for Splunk REST (all output via logging -> stderr)."""

from __future__ import annotations

import logging
import sys

import requests
import urllib3

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.logging_config import configure_logging
from spl_bridge.splunk_client import SplunkClient

logger = logging.getLogger(__name__)


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
