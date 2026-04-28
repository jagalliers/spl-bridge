"""Interactive setup wizard for spl-bridge.

Five steps:

1. Prereqs   -- Python version, ``mcp``/``requests`` importable, keyring backend.
2. Splunk    -- ask for connection metadata + auth mode, build a config.
3. Probe     -- live ``/services/server/info`` test before persisting anything.
4. Credstore -- store secrets in keyring (preferred) or 0600 dotfile.
5. MCP host  -- write/merge into Cursor / Claude Desktop / Claude CLI / snippet.

The wizard refuses to run if stdin is not a TTY and never prints a
secret to stderr/stdout. It also enforces hard-stops for unsafe
combinations (http + password, https-no-verify + password).
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass

from spl_bridge.config import SplunkMCPConfig

from . import credstore, prereqs, splunk_probe, ui
from .credstore import CredStore, CredStoreError
from .mcp_clients import (
    ClientWriter,
    SplunkMcpLaunch,
    WriterError,
    WriteResult,
    all_writers,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Splunk config gathering
# ---------------------------------------------------------------------------


@dataclass
class _CollectedConfig:
    config: SplunkMCPConfig
    secrets: dict[str, str]


def _collect_splunk_config() -> _CollectedConfig:
    """Walk the user through host/port/scheme/auth choices."""
    ui.heading("Splunk connection")

    host = ui.ask("Splunk host (FQDN or IP)", default="localhost")
    if not host:
        raise ui.WizardAbortError("Host is required")

    port_str = ui.ask("Splunk REST management port", default="8089")
    try:
        port = int(port_str)
    except ValueError as exc:
        raise ui.WizardAbortError(f"Port must be a number: {exc}") from exc
    if not (1 <= port <= 65535):
        raise ui.WizardAbortError(f"Port {port} out of range")

    scheme = ui.ask_choice("Connection scheme", ["https (recommended)", "http (lab only)"])
    scheme_value = "https" if scheme.startswith("https") else "http"

    ssl_verify: bool | str = True
    if scheme_value == "https":
        verify_choice = ui.ask_choice(
            "TLS verification",
            [
                "Verify with system CA bundle (default)",
                "Verify with a custom CA bundle path",
                "DISABLE verification (lab only)",
            ],
        )
        if verify_choice.startswith("Verify with system"):
            ssl_verify = True
        elif verify_choice.startswith("Verify with a custom"):
            ssl_verify = ui.ask("Path to CA bundle (.pem)", default="")
            if not ssl_verify:
                raise ui.WizardAbortError("CA bundle path is required")
        else:
            ui.warn("TLS verification disabled -- vulnerable to MITM.")
            if not ui.ask_literal("Confirm you understand", "I UNDERSTAND"):
                raise ui.WizardAbortError("Verification not confirmed")
            ssl_verify = False

    ui.heading("Authentication")
    ui.info("Token mode is recommended for production.")
    ui.info("Username/password mode is lab-only and disables auto re-auth.")
    auth_choice = ui.ask_choice(
        "Auth mode",
        ["Splunk auth token (recommended)", "Username + password (lab only)"],
    )

    secrets: dict[str, str] = {}
    splunk_token: str | None = None
    username: str | None = None
    password: str | None = None

    if auth_choice.startswith("Splunk auth token"):
        splunk_token = ui.ask_secret("Splunk auth token")
        secrets["SPLUNK_TOKEN"] = splunk_token
    else:
        # Hard-stops mirroring the README guidance.
        if scheme_value == "http":
            raise ui.WizardAbortError(
                "Refusing to send a password over plain HTTP. Pick https or switch to a token."
            )
        if scheme_value == "https" and ssl_verify is False:
            ui.warn("Sending a password to an unverified TLS endpoint is unsafe.")
            if not ui.ask_literal("Confirm you accept the risk", "I UNDERSTAND"):
                raise ui.WizardAbortError("Risk not confirmed")
        username = ui.ask("Splunk username", default="admin")
        password = ui.ask_secret("Splunk password")
        secrets["SPLUNK_USERNAME"] = username
        secrets["SPLUNK_PASSWORD"] = password

    config = SplunkMCPConfig(
        host=host,
        port=port,
        scheme=scheme_value,
        ssl_verify=ssl_verify,
        splunk_token=splunk_token,
        username=username,
        password=password,
    )
    return _CollectedConfig(config=config, secrets=secrets)


# ---------------------------------------------------------------------------
# Step runners
# ---------------------------------------------------------------------------


def _run_prereqs() -> bool:
    """Returns True if no fatal failures (keyring is informational)."""
    ui.heading("Prerequisites")
    results = prereqs.run_all()
    fatal = False
    for r in results:
        if r.passed:
            ui.ok(f"{r.name}: {r.detail}")
        else:
            # Keyring failure is non-fatal -- we'll fall back to dotfile.
            if r.name.startswith("OS keychain"):
                ui.warn(f"{r.name}: {r.detail}")
            else:
                ui.fail(f"{r.name}: {r.detail}")
                fatal = True
    return not fatal


def _run_probe(config: SplunkMCPConfig) -> splunk_probe.ProbeResult:
    ui.heading("Live connectivity test")
    ui.info(f"GET {config.base_url}/services/server/info ({config.auth_mode} auth)")
    result = splunk_probe.probe(config)
    if result.ok:
        ui.ok(f"Connected to {result.server_name or '?'} (version {result.version or '?'})")
    else:
        ui.fail(f"Connection failed: {result.error}")
    return result


def _run_credstore(secrets: dict[str, str], prefer_keyring: bool) -> CredStore:
    ui.heading("Credential storage")
    store = credstore.select_backend(prefer_keyring=prefer_keyring)
    ui.info(f"Backend: {store.name} ({store.location()})")
    for key, value in secrets.items():
        store.store(key, value)
        ui.ok(f"Stored {key}")
    return store


def _select_writer() -> ClientWriter:
    ui.heading("MCP host integration")
    writers = all_writers()
    labels = []
    for w in writers:
        suffix = "" if w.is_available() else "  (not detected)"
        labels.append(f"{w.name}{suffix}")
    chosen = ui.ask_choice("Where should we register spl-bridge?", labels)
    # Strip the suffix to find the writer.
    bare = chosen.replace("  (not detected)", "")
    return next(w for w in writers if w.name == bare)


def _build_launch(config: SplunkMCPConfig) -> SplunkMcpLaunch:
    """Build the launch spec the host will store.

    Connection metadata goes into ``env``; secrets do not, because
    ``spl-bridge`` resolves those from the credstore at runtime via
    ``config._resolve_secret``.
    """
    env: dict[str, str] = {
        "SPLUNK_HOST": config.host,
        "SPLUNK_PORT": str(config.port),
        "SPLUNK_SCHEME": config.scheme,
    }
    if config.ssl_verify is False:
        env["SPLUNK_VERIFY_SSL"] = "false"
    elif isinstance(config.ssl_verify, str):
        env["SPLUNK_VERIFY_SSL"] = config.ssl_verify
    return SplunkMcpLaunch(command="spl-bridge", args=[], env=env)


def _run_writer(writer: ClientWriter, server_name: str, launch: SplunkMcpLaunch) -> WriteResult:
    result = writer.write(server_name, launch)
    ui.ok(f"{writer.name} -> {result.location}")
    if result.backup_path:
        ui.info(f"Backup of previous config at {result.backup_path}")
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _print_summary(
    config: SplunkMCPConfig,
    store: CredStore,
    write_result: WriteResult,
) -> None:
    import json as _json

    ui.heading("Summary")
    ui.ok(f"Splunk: {config.base_url} (auth = {config.auth_mode})")
    ui.ok(f"Credential store: {store.name} ({store.location()})")
    ui.ok(f"MCP host: {write_result.target}")
    if write_result.target == "Print snippet only":
        print(file=sys.stderr)
        print(ui.dim("Add this to your MCP host config:"), file=sys.stderr)
        print(_json.dumps(write_result.snippet, indent=2), file=sys.stderr)
    print(file=sys.stderr)
    ui.info("Restart your MCP host for the new server to appear.")


def main() -> int:
    """Run the wizard. Returns process exit code."""
    # Logging is intentionally minimal for the wizard so the screen stays
    # the user's view of the world. The `spl_bridge` logger is
    # non-propagating (see `spl_bridge/__init__.py`), so we raise its
    # level directly rather than via `basicConfig` on root -- otherwise
    # the wizard's TTY would be filled with INFO lines from the probe's
    # HTTP client.
    logging.getLogger("spl_bridge").setLevel(logging.WARNING)

    print(ui.bold("spl-bridge setup wizard"), file=sys.stderr)
    print(
        ui.dim("Walks you through Splunk creds, secure storage, and MCP host wiring."),
        file=sys.stderr,
    )
    try:
        ui.require_tty()
    except ui.WizardAbortError as exc:
        ui.fail(str(exc))
        return 2

    try:
        if not _run_prereqs():
            ui.fail("Prerequisites failed -- please address the issues above.")
            return 1

        collected = _collect_splunk_config()
        probe_result = _run_probe(collected.config)
        if not probe_result.ok and not ui.ask_yes_no(
            "Continue anyway and persist these settings?", default=False
        ):
            return 1

        # Decide which credstore to try based on the keyring prereq result.
        prefer_keyring = prereqs.check_keyring_backend().passed
        if not prefer_keyring:
            ui.info("OS keychain unavailable; using 0600 dotfile fallback.")
        store = _run_credstore(collected.secrets, prefer_keyring=prefer_keyring)

        server_name = ui.ask("MCP server name", default="splunk")
        writer = _select_writer()
        launch = _build_launch(collected.config)
        write_result = _run_writer(writer, server_name, launch)

        _print_summary(collected.config, store, write_result)
        return 0
    except ui.WizardAbortError as exc:
        ui.fail(str(exc))
        return 2
    except (CredStoreError, WriterError) as exc:
        ui.fail(str(exc))
        return 1
    except KeyboardInterrupt:
        ui.fail("Aborted.")
        return 130
