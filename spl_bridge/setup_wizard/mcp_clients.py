"""MCP client config writers.

Each writer takes the user's chosen MCP server name + the spl-bridge
launch args, merges into the client's existing JSON config, writes
atomically with a timestamped backup of the original.

**No secrets are ever written into these files** -- they only contain
the launch command and the chosen connection metadata (host, port,
scheme). Secrets live in the keychain or 0600 dotfile.

Supported targets:

* :class:`CursorWriter`         -> ``~/.cursor/mcp.json``
* :class:`ClaudeDesktopWriter`  -> per-OS Claude Desktop config
* :class:`ClaudeCLIWriter`      -> shells out to ``claude mcp add``
* :class:`SnippetPrinter`       -> echoes the JSON snippet to stderr
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


_SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")


def _validate_server_name(name: str) -> None:
    """Reject MCP server names that could be misinterpreted as CLI flags.

    Used by :class:`ClaudeCLIWriter` (which shells out to ``claude``)
    and the JSON writers (which would happily store a junk key).

    Rules:

    * 1-64 chars total.
    * Must start with an alphanumeric or underscore (so a value like
      ``--scope`` cannot be parsed as a flag by an upstream CLI).
    * Body characters: ``[A-Za-z0-9_.-]``.
    """
    if not isinstance(name, str) or not _SERVER_NAME_RE.fullmatch(name):
        raise ValueError(
            "server_name must match ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$ "
            "(must start with alphanumeric or underscore; "
            "alphanumerics, dot, dash, underscore; 1-64 chars)"
        )


# ---------------------------------------------------------------------------
# Launch spec
# ---------------------------------------------------------------------------


@dataclass
class SplunkMcpLaunch:
    """Launch parameters for the spl-bridge stdio command.

    Connection metadata travels in ``env``; secrets are resolved at
    runtime from the credstore (keychain or 0600 dotfile).
    """

    command: str = "spl-bridge"
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    def to_mcp_json(self) -> dict[str, Any]:
        """Render to the standard ``{"command", "args", "env"}`` shape.

        Most MCP clients accept this exact schema; ``env`` is omitted
        when empty so the user doesn't see noise in their config.
        """
        out: dict[str, Any] = {"command": self.command, "args": list(self.args)}
        if self.env:
            out["env"] = dict(self.env)
        return out


# ---------------------------------------------------------------------------
# Atomic merge helpers
# ---------------------------------------------------------------------------


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    ts = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    backup = path.with_suffix(path.suffix + f".bak.{ts}")
    shutil.copy2(path, backup)
    return backup


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read_existing(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        logger.warning("Could not read existing MCP config at %s", path)
        return {}
    if not text.strip():
        return {}
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise WriterError(
            f"Existing MCP config at {path} is not valid JSON: {exc}. "
            "Refusing to overwrite -- please fix or remove the file."
        ) from exc
    if not isinstance(loaded, dict):
        raise WriterError(f"Existing MCP config at {path} is not a JSON object.")
    return loaded


def _merge_mcp_servers(
    existing: dict[str, Any], server_name: str, launch: dict[str, Any]
) -> dict[str, Any]:
    """Merge ``launch`` under ``mcpServers.<server_name>`` without losing siblings."""
    out = dict(existing)
    servers = dict(out.get("mcpServers") or {})
    servers[server_name] = launch
    out["mcpServers"] = servers
    return out


# ---------------------------------------------------------------------------
# Writer ABC + result type
# ---------------------------------------------------------------------------


class WriterError(RuntimeError):
    """Raised when a config write cannot be safely completed."""


@dataclass
class WriteResult:
    """Outcome the wizard renders to the user."""

    target: str
    location: str
    backup_path: str | None
    snippet: dict[str, Any]


class ClientWriter(ABC):
    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """Cheap check (e.g. binary on PATH, dir exists)."""

    @abstractmethod
    def write(self, server_name: str, launch: SplunkMcpLaunch) -> WriteResult: ...


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


class CursorWriter(ClientWriter):
    name = "Cursor"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or (Path.home() / ".cursor" / "mcp.json")

    def is_available(self) -> bool:
        # Cursor doesn't need to be installed -- the JSON config is
        # what Cursor reads; if the user later installs Cursor, the
        # config is already in place.
        return True

    def write(self, server_name: str, launch: SplunkMcpLaunch) -> WriteResult:
        _validate_server_name(server_name)
        existing = _read_existing(self._path)
        backup = _backup(self._path)
        merged = _merge_mcp_servers(existing, server_name, launch.to_mcp_json())
        _atomic_write_json(self._path, merged)
        return WriteResult(
            target=self.name,
            location=str(self._path),
            backup_path=str(backup) if backup else None,
            snippet=merged["mcpServers"][server_name],
        )


# ---------------------------------------------------------------------------
# Claude Desktop
# ---------------------------------------------------------------------------


def _claude_desktop_config_path() -> Path:
    """Per-OS path Claude Desktop reads.

    Reference: https://modelcontextprotocol.io/quickstart/user
    """
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Claude" / "claude_desktop_config.json"
        return home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    # Linux + others
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else home / ".config"
    return base / "Claude" / "claude_desktop_config.json"


class ClaudeDesktopWriter(ClientWriter):
    name = "Claude Desktop"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _claude_desktop_config_path()

    def is_available(self) -> bool:
        # Best-effort: directory existing implies Claude Desktop is
        # installed. We still allow writes to a not-yet-existing dir
        # so the user can pre-stage the config.
        return True

    def write(self, server_name: str, launch: SplunkMcpLaunch) -> WriteResult:
        _validate_server_name(server_name)
        existing = _read_existing(self._path)
        backup = _backup(self._path)
        merged = _merge_mcp_servers(existing, server_name, launch.to_mcp_json())
        _atomic_write_json(self._path, merged)
        return WriteResult(
            target=self.name,
            location=str(self._path),
            backup_path=str(backup) if backup else None,
            snippet=merged["mcpServers"][server_name],
        )


# ---------------------------------------------------------------------------
# Claude CLI (`claude mcp add`)
# ---------------------------------------------------------------------------


class ClaudeCLIWriter(ClientWriter):
    name = "Claude CLI"

    def is_available(self) -> bool:
        return shutil.which("claude") is not None

    def write(self, server_name: str, launch: SplunkMcpLaunch) -> WriteResult:
        _validate_server_name(server_name)
        if not self.is_available():
            raise WriterError(
                "`claude` CLI not found on PATH. Install with `npm i -g @anthropic-ai/claude`."
            )
        # ``--`` is the standard end-of-options marker. Even though the
        # regex above already prevents flag-shaped names from reaching
        # this point, ``--`` is a defense-in-depth that documents intent
        # and protects against any future relaxation of the regex.
        argv = [
            "claude",
            "mcp",
            "add",
            "--scope",
            "user",
            "--",
            server_name,
            launch.command,
            *launch.args,
        ]
        for k, v in launch.env.items():
            argv.extend(["--env", f"{k}={v}"])
        try:
            subprocess.run(  # noqa: S603 -- inputs are validated literals
                argv,
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.CalledProcessError as exc:
            raise WriterError(
                f"`claude mcp add` failed (exit {exc.returncode}): {exc.stderr.strip()}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise WriterError("`claude mcp add` timed out after 15s") from exc
        return WriteResult(
            target=self.name,
            location="(managed by `claude` CLI)",
            backup_path=None,
            snippet=launch.to_mcp_json(),
        )


# ---------------------------------------------------------------------------
# Snippet-only (no file written)
# ---------------------------------------------------------------------------


class SnippetPrinter(ClientWriter):
    name = "Print snippet only"

    def is_available(self) -> bool:
        return True

    def write(self, server_name: str, launch: SplunkMcpLaunch) -> WriteResult:
        _validate_server_name(server_name)
        snippet = {"mcpServers": {server_name: launch.to_mcp_json()}}
        # Wizard renders this; we just return the data.
        return WriteResult(
            target=self.name,
            location="(stdout snippet only)",
            backup_path=None,
            snippet=snippet,
        )


# ---------------------------------------------------------------------------
# Discovery helpers used by __init__.main()
# ---------------------------------------------------------------------------


def all_writers() -> list[ClientWriter]:
    return [
        CursorWriter(),
        ClaudeDesktopWriter(),
        ClaudeCLIWriter(),
        SnippetPrinter(),
    ]
