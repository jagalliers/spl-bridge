"""In-process sliding-window rate limiter for MCP tools/call requests.

Default global limit is 600 requests/minute; tuned for typical interactive
MCP workloads.

NOTE: limits are enforced **per process**. Multi-worker deployments enforce
the configured limits per worker, not globally across the deployment.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque

logger = logging.getLogger(__name__)


class RateLimiter:
    """Sliding-window counter scoped to a single key (global or per-tool).

    Thread-safe: ``allow`` and ``remaining`` are guarded by an internal lock.
    """

    def __init__(self, max_requests: int, window_seconds: float = 60.0) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            cutoff = now - self._window
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._max:
                return False
            self._timestamps.append(now)
            return True

    @property
    def remaining(self) -> int:
        with self._lock:
            now = time.monotonic()
            cutoff = now - self._window
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()
            return max(0, self._max - len(self._timestamps))


class RateLimitManager:
    """Manages a global limiter plus optional per-tool limiters."""

    def __init__(
        self,
        global_max: int = 600,
        window_seconds: float = 60.0,
    ) -> None:
        self._global = RateLimiter(global_max, window_seconds)
        self._per_tool: dict[str, RateLimiter] = {}
        self._window = window_seconds

    def set_tool_limit(self, tool_name: str, max_requests: int) -> None:
        self._per_tool[tool_name] = RateLimiter(max_requests, self._window)

    def check(self, tool_name: str) -> bool:
        """Consult per-tool limit BEFORE global so a per-tool denial does not
        consume global budget (R1 fix)."""
        limiter = self._per_tool.get(tool_name)
        if limiter is not None and not limiter.allow():
            logger.warning("Per-tool rate limit exceeded for %s", tool_name)
            return False
        if not self._global.allow():
            logger.warning("Global rate limit exceeded")
            return False
        return True
