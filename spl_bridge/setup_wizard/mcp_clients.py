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

    def inspect_existing(self, server_name: str) -> dict[str, Any] | None:
        """Return the current entry registered under ``server_name`` for this
        target, or ``None`` if no such entry exists.

        Used by the wizard to detect a name collision *before* it issues a
        write -- so the user can be told what is about to be overwritten and
        offered a chance to pick a different name. The default implementation
        returns ``None`` (no persistent state, no collision possible) and is
        appropriate for writers that don't touch the filesystem.

        Implementations must be read-only: a collision check that mutates
        state on the way in would defeat the purpose of asking first.
        """
        _ = server_name
        return None


# ---------------------------------------------------------------------------
# Per-host config-path resolvers (public for `spl-bridge doctor --hosts`)
# ---------------------------------------------------------------------------


def cursor_config_path() -> Path:
    """User-scope Cursor MCP config path.

    Public so ``spl_bridge.doctor`` can resolve the same location the
    ``CursorWriter`` writes to. Per-project ``.cursor/mcp.json`` files
    are not enumerated by this helper; use :func:`find_cursor_project_config`
    when you want to discover the nearest project-scope config from a
    given starting directory.
    """
    return Path.home() / ".cursor" / "mcp.json"


# Maximum directories to walk upward when searching for a project-scope
# ``.cursor/mcp.json``. Plenty of slack for any realistic project depth
# (most repos sit 2-6 levels under $HOME); the cap exists purely as a
# guard against pathological symlink loops.
_PROJECT_WALK_MAX_DEPTH = 32


def find_cursor_project_config(start: Path | None = None) -> Path | None:
    """Walk upward from ``start`` looking for a ``.cursor/mcp.json``.

    Cursor merges project-scope and user-scope configs, with project
    scope winning on name collisions. The wizard only writes user-scope
    today, so when a user runs setup from inside a project tree that
    already has a ``.cursor/mcp.json`` defining the same server name,
    the project entry will silently shadow ours. This helper is the
    discovery half of warning the user about that case.

    Walk semantics deliberately mirror what git does for ``.git`` lookups:

    * Start at ``start`` (defaults to ``Path.cwd()``).
    * Check ``<dir>/.cursor/mcp.json`` at each level; return the first hit.
    * Stop ascending once we cross ``$HOME`` (so a user running setup
      from anywhere in their home tree never accidentally picks up a
      stray ``~/.cursor/mcp.json`` masquerading as project scope, and
      we never inspect anything *outside* the user's home).
    * Stop at the filesystem root regardless.
    * Cap the walk at :data:`_PROJECT_WALK_MAX_DEPTH` iterations as a
      defense against pathological symlink loops or unusual mount
      topology -- at 32 levels of nesting we are well past any realistic
      project layout and entering "something is wrong" territory.

    Returns ``None`` when nothing is found rather than raising, so
    callers can treat "no project config" as a normal, frequent case.
    """
    try:
        cwd = (start or Path.cwd()).resolve()
    except (OSError, RuntimeError):
        # ``cwd`` can be unresolvable if the current directory was
        # unlinked out from under us, or under odd FS conditions.
        return None
    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        home = None

    # Don't ascend out of $HOME. If the start point is itself outside
    # $HOME, we still allow inspection of just that directory (and only
    # that directory) -- but never walk further up, since we have no
    # business inspecting ``/etc/.cursor/mcp.json`` or similar.
    bounded_to_home = home is not None and (cwd == home or home in cwd.parents)

    current = cwd
    for _ in range(_PROJECT_WALK_MAX_DEPTH):
        candidate = current / ".cursor" / "mcp.json"
        if candidate.is_file():
            # Ignore the user-scope file even if the walk happens to
            # land on $HOME -- ``~/.cursor/mcp.json`` is the user-scope
            # config that ``cursor_config_path`` returns, not a
            # project-scope config that would shadow it.
            if (
                home is not None
                and candidate.resolve() == (home / ".cursor" / "mcp.json").resolve()
            ):
                return None
            return candidate
        parent = current.parent
        if parent == current:
            # Reached filesystem root.
            return None
        if bounded_to_home and home is not None and current == home:
            # About to ascend out of $HOME -- stop.
            return None
        current = parent
    return None


def claude_desktop_config_path() -> Path:
    """Per-OS path Claude Desktop reads.

    Reference: https://modelcontextprotocol.io/quickstart/user

    Public so other modules (notably ``spl_bridge.doctor`` for the
    ``--hosts`` scan) can resolve the same canonical location without
    duplicating the per-platform logic.
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


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


class CursorWriter(ClientWriter):
    name = "Cursor"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or cursor_config_path()

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

    def inspect_existing(self, server_name: str) -> dict[str, Any] | None:
        # Read-only inspection of the same file ``write`` would touch. If
        # the file doesn't exist or the server name is absent, returns None.
        # Reuses ``_read_existing`` so a malformed file raises the same
        # ``WriterError`` the wizard already handles -- no need for a
        # separate "soft fail" code path on bad JSON.
        existing = _read_existing(self._path)
        servers = existing.get("mcpServers")
        if not isinstance(servers, dict):
            return None
        entry = servers.get(server_name)
        return entry if isinstance(entry, dict) else None


# ---------------------------------------------------------------------------
# Claude Desktop
# ---------------------------------------------------------------------------


class ClaudeDesktopWriter(ClientWriter):
    name = "Claude Desktop"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or claude_desktop_config_path()

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

    def inspect_existing(self, server_name: str) -> dict[str, Any] | None:
        existing = _read_existing(self._path)
        servers = existing.get("mcpServers")
        if not isinstance(servers, dict):
            return None
        entry = servers.get(server_name)
        return entry if isinstance(entry, dict) else None


# ---------------------------------------------------------------------------
# Claude CLI (`claude mcp add`)
# ---------------------------------------------------------------------------


def _claude_cli_state_path() -> Path:
    """Path to the Claude Code CLI's persistent state file.

    All MCP server registrations made via ``claude mcp add`` end up in
    this file (the per-project keying for local/default scope, the
    top-level ``mcpServers`` for ``--scope user``). It also accumulates
    project memory and auth state, so a defensive backup before we
    invoke the CLI is cheap insurance against the documented merge bugs
    in the upstream ``claude mcp add`` command (see Anthropic GH
    #13281, #32939).
    """
    return Path.home() / ".claude.json"


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
        # Defensive backup of the CLI's state file *before* delegating
        # to ``claude mcp add``. The CLI's merge semantics for the
        # top-level ``~/.claude.json`` have known bugs (Anthropic GH
        # #13281) and the file also holds project memory + auth state,
        # so a pre-write copy is the only way for the user to recover
        # from an upstream regression. ``_backup`` no-ops when the file
        # doesn't exist yet (first-ever invocation), so this is safe to
        # call unconditionally.
        backup = _backup(_claude_cli_state_path())
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
            backup_path=str(backup) if backup else None,
            snippet=launch.to_mcp_json(),
        )

    def inspect_existing(self, server_name: str) -> dict[str, Any] | None:
        """Best-effort collision check via ``claude mcp get``.

        The CLI exits 0 with the entry printed to stdout when a server
        of the given name exists at the requested scope, and exits
        non-zero (typically 1) with a "No MCP server found" message
        when it doesn't. We treat any non-zero exit as "absent" rather
        than letting it bubble up: the wizard's collision UX is a
        belt-and-braces convenience, and we'd rather fall through to
        the (still-backup-protected) write than abort the wizard
        because an older ``claude`` CLI doesn't ship ``mcp get``.

        Returns a stub dict ``{"command": <first-line-of-stdout>}`` on
        a hit so the wizard can show the user what's about to be
        replaced. We don't try to parse the full output -- the exact
        format has shifted between Claude Code versions and the only
        thing the wizard actually needs is "yes there's something
        here, here is some hint of what it is".
        """
        if not self.is_available():
            return None
        argv = [
            "claude",
            "mcp",
            "get",
            "--scope",
            "user",
            "--",
            server_name,
        ]
        try:
            result = subprocess.run(  # noqa: S603 -- inputs are validated literals
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.info(
                "Could not query `claude mcp get` for collision detection: %s. "
                "Continuing without pre-write collision check.",
                exc,
            )
            return None
        if result.returncode != 0:
            return None
        # Stub entry: the first non-empty line of stdout is the most
        # useful single-line summary across the CLI version range we
        # care about. If stdout is empty (some older CLIs return 0
        # with no output), fall back to a sentinel so the wizard still
        # surfaces the collision.
        first_line = next(
            (line.strip() for line in result.stdout.splitlines() if line.strip()),
            "<existing entry>",
        )
        return {"command": first_line}


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
