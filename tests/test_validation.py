"""Coverage for _validate_args type/enum checks (R5),
build_spl missing-placeholder hard-fail (R6), and the capability-lock
helper (R9)."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.server import _validate_args
from spl_bridge.splunk_client import SplunkClient
from spl_bridge.tool_registry import build_spl


def _schema(props: dict) -> dict:
    return {"inputSchema": {"type": "object", "properties": props}}


# ---------------------------------------------------------------------------
# R5 - _validate_args type and enum coverage
# ---------------------------------------------------------------------------


class TestValidateArgsTypes:
    def test_string_wrong_type_rejected(self) -> None:
        tool = _schema({"name": {"type": "string"}})
        assert _validate_args(tool, {"name": 123}) == ("Invalid value for name: must be string")

    def test_integer_accepted(self) -> None:
        tool = _schema({"row_limit": {"type": "integer"}})
        assert _validate_args(tool, {"row_limit": 50}) is None

    def test_integer_string_rejected(self) -> None:
        tool = _schema({"row_limit": {"type": "integer"}})
        assert _validate_args(tool, {"row_limit": "50"}) is not None

    def test_integer_bool_rejected(self) -> None:
        tool = _schema({"row_limit": {"type": "integer"}})
        assert _validate_args(tool, {"row_limit": True}) is not None

    def test_boolean_accepted(self) -> None:
        tool = _schema({"flag": {"type": "boolean"}})
        assert _validate_args(tool, {"flag": True}) is None

    def test_boolean_int_rejected(self) -> None:
        tool = _schema({"flag": {"type": "boolean"}})
        assert _validate_args(tool, {"flag": 1}) is not None

    def test_number_accepts_int_and_float(self) -> None:
        tool = _schema({"x": {"type": "number"}})
        assert _validate_args(tool, {"x": 1}) is None
        assert _validate_args(tool, {"x": 1.5}) is None

    def test_number_string_rejected(self) -> None:
        tool = _schema({"x": {"type": "number"}})
        assert _validate_args(tool, {"x": "1.5"}) is not None

    def test_array_required(self) -> None:
        tool = _schema({"items": {"type": "array"}})
        assert _validate_args(tool, {"items": [1, 2]}) is None
        assert _validate_args(tool, {"items": "not-a-list"}) is not None

    def test_object_required(self) -> None:
        tool = _schema({"o": {"type": "object"}})
        assert _validate_args(tool, {"o": {"k": "v"}}) is None
        assert _validate_args(tool, {"o": "x"}) is not None

    def test_enum_applies_to_non_string(self) -> None:
        tool = _schema({"sev": {"type": "integer", "enum": [1, 2, 3]}})
        assert _validate_args(tool, {"sev": 2}) is None
        assert _validate_args(tool, {"sev": 7}) is not None

    def test_enum_on_string_still_works(self) -> None:
        tool = _schema({"mode": {"type": "string", "enum": ["a", "b"]}})
        assert _validate_args(tool, {"mode": "a"}) is None
        assert _validate_args(tool, {"mode": "c"}) is not None


# ---------------------------------------------------------------------------
# R6 - build_spl hard-fail on unfilled placeholders
# ---------------------------------------------------------------------------


class TestBuildSplPlaceholderHardFail:
    def test_missing_placeholder_raises_value_error(self) -> None:
        tool = {
            "_meta": {
                "execution": {"template": "search index=$missing$"},
            },
            "inputSchema": {"properties": {}},
        }
        with pytest.raises(ValueError, match="missing"):
            build_spl(
                tool,
                {},
                default_row_limit=100,
                max_row_limit=1000,
            )

    def test_filled_placeholder_works(self) -> None:
        tool = {
            "_meta": {
                "execution": {"template": "search index=$idx$"},
            },
            "inputSchema": {"properties": {"idx": {"type": "string"}}},
        }
        spl, _, _, _ = build_spl(
            tool,
            {"idx": "main"},
            default_row_limit=100,
            max_row_limit=1000,
        )
        assert spl == "search index=main"


# ---------------------------------------------------------------------------
# R9 - per-process capability lock
# ---------------------------------------------------------------------------


class TestCapabilityLock:
    def test_check_runs_once_per_process(self) -> None:
        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        client = SplunkClient(cfg)
        client.check_capabilities = MagicMock(return_value=(True, ""))

        ok1, _ = client.ensure_capabilities_verified()
        ok2, _ = client.ensure_capabilities_verified()
        assert ok1 and ok2
        assert client.check_capabilities.call_count == 1

    def test_concurrent_calls_run_check_once(self) -> None:
        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        client = SplunkClient(cfg)
        call_lock = threading.Lock()
        call_count = {"n": 0}

        def slow_ok(_: object | None = None) -> tuple[bool, str]:
            with call_lock:
                call_count["n"] += 1
            import time

            time.sleep(0.05)
            return True, ""

        client.check_capabilities = slow_ok

        threads = [
            threading.Thread(target=lambda: client.ensure_capabilities_verified()) for _ in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert call_count["n"] == 1

    def test_failed_check_does_not_set_verified_flag(self) -> None:
        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        client = SplunkClient(cfg)
        client.check_capabilities = MagicMock(side_effect=[(False, "denied"), (True, "")])

        ok1, msg1 = client.ensure_capabilities_verified()
        assert not ok1
        ok2, _ = client.ensure_capabilities_verified()
        assert ok2
        assert client.check_capabilities.call_count == 2


# ---------------------------------------------------------------------------
# M5 - saved-search args allowlist
# ---------------------------------------------------------------------------


class TestSavedSearchArgsAllowlist:
    """The ``args`` field in run_saved_search must reject characters that
    could pivot the dispatch POST into something else (pipes, brackets,
    semicolons, newlines, backticks, ampersands)."""

    def _build_handler(self):
        """Compile a stand-in for ``_saved_search_tool`` that re-uses the
        production allowlist regex + ToolExecutionError class."""
        from spl_bridge.server import (
            _SAVED_SEARCH_ARGS_RE,
            ToolExecutionError,
        )

        def handler(args: str) -> None:
            if len(args) > 4096:
                raise ToolExecutionError("saved-search args exceed 4096 characters")
            if args and not _SAVED_SEARCH_ARGS_RE.fullmatch(args):
                raise ToolExecutionError("Invalid characters in saved-search args.")

        return handler, ToolExecutionError

    @pytest.mark.parametrize(
        "good_args",
        [
            "",
            "name=value",
            "count=10 limit=100",
            'field="some value"',
            "ts=2026-04-14T12:00:00",
            "path=/opt/data/file.csv",
            "tag='alpha+beta'",
        ],
    )
    def test_accepts_legitimate_args(self, good_args: str) -> None:
        handler, _ = self._build_handler()
        handler(good_args)  # must not raise

    @pytest.mark.parametrize(
        "bad_args",
        [
            "; | rest of injection",
            "] | delete",
            "name=value\nrest=evil",
            "name=value\r\nlinefeed",
            "field=`subshell`",
            "field=value & echo pwned",
            "field=value | mvexpand foo",
            "field=value [ subsearch ]",
            "field=value $TOKEN$",
            "name=value;rm -rf /",
        ],
    )
    def test_rejects_injection_payloads(self, bad_args: str) -> None:
        handler, ToolExecutionError = self._build_handler()
        with pytest.raises(ToolExecutionError):
            handler(bad_args)

    def test_rejects_oversized_args(self) -> None:
        handler, ToolExecutionError = self._build_handler()
        with pytest.raises(ToolExecutionError):
            handler("a" * 5000)
