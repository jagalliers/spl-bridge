"""Tests for in-process rate limiting."""

from __future__ import annotations

from spl_bridge.rate_limit import RateLimiter, RateLimitManager


class TestRateLimiter:
    def test_allows_up_to_max(self) -> None:
        rl = RateLimiter(max_requests=3, window_seconds=60.0)
        assert rl.allow()
        assert rl.allow()
        assert rl.allow()
        assert not rl.allow()

    def test_remaining(self) -> None:
        rl = RateLimiter(max_requests=5, window_seconds=60.0)
        assert rl.remaining == 5
        rl.allow()
        assert rl.remaining == 4


class TestRateLimitManager:
    def test_global_limit(self) -> None:
        mgr = RateLimitManager(global_max=2, window_seconds=60.0)
        assert mgr.check("tool_a")
        assert mgr.check("tool_b")
        assert not mgr.check("tool_c")

    def test_per_tool_limit(self) -> None:
        mgr = RateLimitManager(global_max=100, window_seconds=60.0)
        mgr.set_tool_limit("expensive_tool", 1)
        assert mgr.check("expensive_tool")
        assert not mgr.check("expensive_tool")
        assert mgr.check("other_tool")

    def test_per_tool_denial_does_not_consume_global_budget(self) -> None:
        """R1 fix: per-tool denial must not deduct from the global budget."""
        mgr = RateLimitManager(global_max=10, window_seconds=60.0)
        mgr.set_tool_limit("expensive_tool", 1)

        assert mgr.check("expensive_tool") is True  # global=1
        for _ in range(20):
            mgr.check("expensive_tool")  # all denied at per-tool stage

        # Global should still have 9 remaining slots after 1 successful call.
        for _ in range(9):
            assert mgr.check("other_tool") is True
        assert mgr.check("other_tool") is False


class TestRateLimiterThreadSafety:
    """R2 fix: ``RateLimiter`` is safe under concurrent invocation."""

    def test_concurrent_allow_consistent_count(self) -> None:
        import threading

        rl = RateLimiter(max_requests=200, window_seconds=60.0)
        granted: list[bool] = []
        granted_lock = threading.Lock()

        def worker() -> None:
            for _ in range(50):
                ok = rl.allow()
                with granted_lock:
                    granted.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 8 * 50 = 400 attempts, max 200 should be granted
        assert sum(1 for g in granted if g) == 200
        assert rl.remaining == 0
