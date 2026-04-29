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
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

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

# Hard cap on probe-failure edit-and-retry attempts. After the budget
# is exhausted the wizard degrades the failure menu to the historical
# two-option (save-anyway / quit) prompt and points the user at
# ``spl-bridge doctor`` for further iteration. A small finite bound
# keeps the wizard's worst-case runtime predictable and the test
# matrix tractable.
_PROBE_MAX_ATTEMPTS = 3

ProbeFailureChoice = Literal["edit", "save", "quit"]


# ---------------------------------------------------------------------------
# Command resolution
# ---------------------------------------------------------------------------


def _resolve_spl_bridge_command() -> str:
    """Resolve the spl-bridge entry point to an absolute path.

    MCP hosts launched from Finder / launchd (notably **Claude Desktop
    on macOS**, but also some Cursor configurations) inherit a
    stripped-down ``PATH`` that omits common Python install prefixes:
    Homebrew Python user-sites (``~/Library/Python/3.x/bin``), pipx
    venvs, ``uv tool`` venvs, and project venvs. Writing a bare
    ``"spl-bridge"`` into the host's MCP JSON therefore fails with
    ``Failed to spawn process: No such file or directory`` even though
    the user's interactive shell finds it just fine.

    Resolving to an absolute path at setup time avoids that entire
    class of bug. It also makes the snippet emitted by ``SnippetPrinter``
    immediately copy-pastable into hosts the wizard doesn't natively
    target.

    Resolution order:

    1. ``shutil.which("spl-bridge")`` -- whatever the user's shell PATH
       currently resolves to. This is the right answer for pipx,
       Homebrew Python, project venvs, and ``uv tool``.
    2. ``sys.argv[0]`` if it's an absolute path whose basename is
       ``spl-bridge`` (or ``spl-bridge.exe`` on Windows). The wizard
       is being invoked AS ``spl-bridge setup``, so ``argv[0]`` is
       almost always set to the absolute entry-point path even on
       hosts where ``which`` is missing.
    3. Fall back to bare ``"spl-bridge"`` and warn loudly. The MCP
       host will only succeed if its launch-time PATH happens to
       contain the install prefix.
    """
    found = shutil.which("spl-bridge")
    if found:
        return found
    argv0 = Path(sys.argv[0])
    if argv0.is_absolute() and argv0.name in {"spl-bridge", "spl-bridge.exe"}:
        return str(argv0)
    logger.warning(
        "Could not resolve absolute path to 'spl-bridge'; falling back "
        "to bare command name. Some MCP hosts (notably Claude Desktop "
        "on macOS) launch with a stripped PATH and may fail to find it. "
        "If that happens, edit the host's MCP JSON config and replace "
        "the 'command' value with the output of `command -v spl-bridge`."
    )
    return "spl-bridge"


# ---------------------------------------------------------------------------
# Splunk config gathering
# ---------------------------------------------------------------------------


@dataclass
class _CollectedConfig:
    config: SplunkMCPConfig
    secrets: dict[str, str]


def _collect_splunk_config(previous: SplunkMCPConfig | None = None) -> _CollectedConfig:
    """Walk the user through host/port/scheme/auth choices.

    When called with ``previous`` (a probe-failed config from an earlier
    attempt in the same wizard run), every non-secret field is offered
    pre-filled as the prompt's default so the user can hit Enter to
    keep a value or type to override. Secrets (``splunk_token``,
    ``password``) are *never* recalled across attempts -- they are
    re-prompted via :func:`getpass.getpass` exactly like a fresh run.
    This keeps the secret-lifetime story unchanged: a secret enters
    the process once per attempt, is passed straight into the
    credstore on success, and is otherwise dropped when the
    enclosing :class:`_CollectedConfig` goes out of scope.
    """
    if previous is None:
        ui.heading("Splunk connection")
    else:
        ui.heading("Splunk connection (edit and retry)")
        ui.info("Previous answers are pre-filled as defaults; press Enter to keep.")

    host = ui.ask(
        "Splunk host (FQDN or IP)",
        default=previous.host if previous else "localhost",
    )
    if not host:
        raise ui.WizardAbortError("Host is required")

    port_str = ui.ask(
        "Splunk REST management port",
        default=str(previous.port) if previous else "8089",
    )
    try:
        port = int(port_str)
    except ValueError as exc:
        raise ui.WizardAbortError(f"Port must be a number: {exc}") from exc
    if not (1 <= port <= 65535):
        raise ui.WizardAbortError(f"Port {port} out of range")

    # ask_choice's `default` is the 0-indexed position into `choices`.
    # Map the previous scheme back to that index; falls through to 0
    # (https, the recommended option) on first run.
    scheme_default_idx = 1 if (previous is not None and previous.scheme == "http") else 0
    scheme = ui.ask_choice(
        "Connection scheme",
        ["https (recommended)", "http (lab only)"],
        default=scheme_default_idx,
    )
    scheme_value = "https" if scheme.startswith("https") else "http"

    ssl_verify: bool | str = True
    if scheme_value == "https":
        # Map previous ssl_verify (True / str / False) back to the
        # 0/1/2 index of the verify_choice menu. Only reuse when the
        # previous attempt was *also* https; otherwise fall through to
        # the safe default (system CA).
        if previous is not None and previous.scheme == "https":
            if previous.ssl_verify is True:
                tls_default_idx = 0
            elif isinstance(previous.ssl_verify, str):
                tls_default_idx = 1
            else:
                tls_default_idx = 2
        else:
            tls_default_idx = 0
        verify_choice = ui.ask_choice(
            "TLS verification",
            [
                "Verify with system CA bundle (default)",
                "Verify with a custom CA bundle path",
                "DISABLE verification (lab only)",
            ],
            default=tls_default_idx,
        )
        if verify_choice.startswith("Verify with system"):
            ssl_verify = True
        elif verify_choice.startswith("Verify with a custom"):
            ca_default = (
                previous.ssl_verify
                if previous is not None and isinstance(previous.ssl_verify, str)
                else ""
            )
            ssl_verify = ui.ask("Path to CA bundle (.pem)", default=ca_default)
            if not ssl_verify:
                raise ui.WizardAbortError("CA bundle path is required")
        else:
            ui.warn("TLS verification disabled -- vulnerable to MITM.")
            ui.warn("An on-path attacker can transparently intercept this connection.")
            if not ui.ask_yes_no("Continue with TLS verification disabled?", default=False):
                raise ui.WizardAbortError("Verification not confirmed")
            ssl_verify = False

    ui.heading("Authentication")
    ui.info("Token mode is recommended for production.")
    ui.info("Username/password mode is lab-only and disables auto re-auth.")
    # Auth pre-fill: token unless the previous attempt explicitly used
    # username/password. We can't pre-fill the secret itself, but we
    # can save the user the menu pick.
    auth_default_idx = 1 if (previous is not None and previous.username is not None) else 0
    auth_choice = ui.ask_choice(
        "Auth mode",
        ["Splunk auth token (recommended)", "Username + password (lab only)"],
        default=auth_default_idx,
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
            ui.warn("An on-path attacker can capture both the password and session key.")
            if not ui.ask_yes_no("Continue and send the password to this endpoint?", default=False):
                raise ui.WizardAbortError("Risk not confirmed")
        username = ui.ask(
            "Splunk username",
            default=previous.username if previous and previous.username else "admin",
        )
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


def _offer_probe_failure_choice(can_retry: bool) -> ProbeFailureChoice:
    """Render the post-failure choice menu and return the user's pick.

    When ``can_retry`` is True (the wizard has retry budget remaining),
    a three-option menu is shown: edit-and-retry, save-anyway, or
    quit. Default is *quit* so a stray Enter never persists a probe
    that just failed.

    When ``can_retry`` is False (retry budget exhausted), the
    edit-and-retry option is dropped and the user is pointed at
    ``spl-bridge doctor`` for iterative testing without re-running
    the wizard. Default remains *quit*.
    """
    if can_retry:
        choices = [
            "Edit settings and try again",
            "Save anyway (the probe might be a false negative)",
            "Quit without saving",
        ]
        # Default index is the last entry (Quit) -- preserves the
        # historical "stray Enter aborts" behaviour.
        chosen = ui.ask_choice("How would you like to proceed?", choices, default=2)
        if chosen.startswith("Edit"):
            return "edit"
        if chosen.startswith("Save"):
            return "save"
        return "quit"
    ui.info(
        "Retry budget exhausted. Run `spl-bridge doctor` after this exits to "
        "iterate on settings without re-running the wizard."
    )
    choices = [
        "Save anyway (the probe might be a false negative)",
        "Quit without saving",
    ]
    chosen = ui.ask_choice("How would you like to proceed?", choices, default=1)
    if chosen.startswith("Save"):
        return "save"
    return "quit"


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
    return SplunkMcpLaunch(command=_resolve_spl_bridge_command(), args=[], env=env)


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
        # Bounded probe-retry loop. If the probe succeeds we fall
        # through to the credstore step. On failure we offer
        # edit-and-retry up to _PROBE_MAX_ATTEMPTS times; after the
        # budget the menu degrades to the historical save-anyway /
        # quit binary. Hard-stops inside re-collection (http+password,
        # declined risk gates) propagate as WizardAbortError and
        # terminate the wizard with exit code 2 -- we never let the
        # user retry past a security gate.
        attempts = 1
        while not probe_result.ok:
            choice = _offer_probe_failure_choice(can_retry=attempts < _PROBE_MAX_ATTEMPTS)
            if choice == "quit":
                return 1
            if choice == "save":
                break
            # choice == "edit": re-collect with the previous attempt's
            # non-secret answers as defaults and probe again.
            attempts += 1
            collected = _collect_splunk_config(previous=collected.config)
            probe_result = _run_probe(collected.config)

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
