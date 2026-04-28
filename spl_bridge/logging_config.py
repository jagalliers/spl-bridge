"""Structured JSON logging with request-scoped context for spl-bridge.

Provides:
- ``MCPJsonFormatter``   -- one compact JSON object per log line
- ``MCPContextFilter``   -- injects fields from a ``contextvars`` dict
- ``update_log_context`` / ``clear_log_context`` -- helpers for per-request fields
- ``operation_logger``   -- decorator emitting start/end timing around tool calls
"""

from __future__ import annotations

import contextvars
import functools
import json
import logging
import os
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

LogValue = str | int | float
# B039: ContextVar default must not be a mutable structure shared across
# contexts. We use ``None`` and treat it as "empty dict" everywhere.
_LOG_CONTEXT: contextvars.ContextVar[dict[str, LogValue] | None] = contextvars.ContextVar(
    "mcp_log_context", default=None
)

F = TypeVar("F", bound=Callable[..., Any])


def _ctx_snapshot() -> dict[str, LogValue]:
    """Return a *copy* of the current context dict (or ``{}`` if unset)."""
    cur = _LOG_CONTEXT.get()
    return dict(cur) if cur is not None else {}


def update_log_context(**kwargs: Any) -> None:
    """Merge *kwargs* into the current per-request log context."""
    cur = _ctx_snapshot()
    cur.update({k: v for k, v in kwargs.items() if v is not None})
    _LOG_CONTEXT.set(cur)


def clear_log_context() -> None:
    """Reset the per-request log context to empty."""
    _LOG_CONTEXT.set({})


def set_request_id() -> str:
    """Generate a short random request ID and store it in log context."""
    request_id = os.urandom(6).hex()
    update_log_context(request_id=request_id)
    return request_id


def current_request_id() -> str:
    """Return the current request id from log context, or '?' if unset."""
    val = _ctx_snapshot().get("request_id")
    return str(val) if val is not None else "?"


_REDACT_KEYS = frozenset(
    {
        "token",
        "password",
        "passwd",
        "session_key",
        "sessionkey",
        "authorization",
        "api_key",
        "apikey",
        "secret",
        "bearer",
    }
)


class MCPContextFilter(logging.Filter):
    """Inject ``contextvars``-based fields into every ``LogRecord``."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            for k, v in _ctx_snapshot().items():
                if not hasattr(record, k):
                    setattr(record, k, v)
        except Exception:
            pass
        return True


class MCPJsonFormatter(logging.Formatter):
    """Emit one compact JSON object per log line.

    Fields: ``time`` (ISO-8601 UTC), ``level``, ``logger``, ``pid``,
    ``message``, plus any extras injected by ``MCPContextFilter``.
    """

    _DEFAULT_KEYS: set[str] | None = None

    def _default_record_keys(self) -> set[str]:
        if MCPJsonFormatter._DEFAULT_KEYS is None:
            MCPJsonFormatter._DEFAULT_KEYS = set(vars(logging.makeLogRecord({})).keys())
        return MCPJsonFormatter._DEFAULT_KEYS

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "time": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "pid": record.process,
            "message": record.getMessage(),
        }

        if record.exc_info:
            try:
                log_obj["exception"] = self.formatException(record.exc_info)
            except Exception:
                log_obj["exception"] = "Exception info unavailable"

        defaults = self._default_record_keys()
        for key, value in record.__dict__.items():
            if key not in defaults and key not in log_obj:
                if key.lower() in _REDACT_KEYS:
                    log_obj[key] = "(redacted)"
                    continue
                try:
                    json.dumps({key: value})
                    log_obj[key] = value
                except (TypeError, ValueError):
                    log_obj[key] = str(value)

        return json.dumps(log_obj, separators=(",", ":"))


def configure_logging(
    level: int = logging.INFO,
    *,
    stream: Any | None = None,
) -> None:
    """Install ``MCPJsonFormatter`` + ``MCPContextFilter`` on the root logger.

    Idempotent: re-installing replaces the existing handlers so this is
    safe to call from both ``server.main`` and ``doctor.run_doctor``.

    M7: Refuses to install a handler whose stream is ``sys.stdout``. The
    MCP stdio transport uses stdout exclusively for JSON-RPC framed
    messages; any rogue ``print`` or logger writing to stdout corrupts
    the protocol stream and will hang the host client. Callers that
    really want stdout (e.g. unit tests) can monkeypatch the handler
    afterwards.
    """
    target = stream or sys.stderr
    if target is sys.stdout:
        raise RuntimeError(
            "configure_logging refuses to attach a handler to sys.stdout; "
            "stdout is reserved for MCP JSON-RPC framing. Use sys.stderr."
        )
    handler = logging.StreamHandler(target)
    handler.setFormatter(MCPJsonFormatter())
    handler.addFilter(MCPContextFilter())

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [handler]

    # The package logger is installed with ``propagate=False`` in
    # ``spl_bridge/__init__.py`` to stop double-emit when a caller also
    # configures the root logger. Because of that, the caller's intended
    # level/stream will not reach our records unless we also reset the
    # package logger here -- do it with the same handler so there is
    # exactly one emission path for our logs.
    pkg = logging.getLogger("spl_bridge")
    pkg.setLevel(level)
    pkg.handlers = [handler]


def operation_logger(operation_type: str) -> Callable[[F], F]:
    """Decorator that logs start/end timing and status around a function.

    Expects the wrapped function to either return normally (success) or
    raise an exception (failure).  Context fields ``operation_type``,
    ``operation_phase``, and ``execution_time_seconds`` are set
    automatically via ``update_log_context``.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            log = logging.getLogger(func.__module__)
            start = time.monotonic()
            update_log_context(operation_type=operation_type, operation_phase="start")
            log.info("Operation started: %s", operation_type)

            success = False
            try:
                result = func(*args, **kwargs)
                success = True
                return result
            finally:
                elapsed = round(time.monotonic() - start, 3)
                update_log_context(
                    operation_type=operation_type,
                    operation_phase="end",
                    execution_time_seconds=elapsed,
                )
                if success:
                    log.info("Operation completed: %s (%.3fs)", operation_type, elapsed)
                else:
                    log.error("Operation failed: %s (%.3fs)", operation_type, elapsed)

        return wrapper  # type: ignore[return-value]

    return decorator
