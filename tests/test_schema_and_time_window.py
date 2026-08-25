"""Schema-description, default-time-window, and catalog-alignment tests.

Covers the 0.2.0 time-parameter ergonomics changes:

* The advertised MCP schema carries per-parameter descriptions (FastMCP
  builds the wire schema from the closure signatures in
  ``server._register_tool``, so descriptions must survive annotation
  evaluation under ``from __future__ import annotations``).
* ``run_query`` applies a configurable default time window when both time
  parameters are omitted, disclosed in-band as ``time_window``.
* ``run_saved_search`` and ``get_metadata`` never receive that default.
* ``run_saved_search`` forwards explicit time overrides (regression: they
  were silently dropped while ``time_range`` was false in the catalog).
* ``builtin_tools.json`` stays aligned with the server description
  constants and never grows restrictive patterns on the time parameters.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

import spl_bridge.server as server_mod
from spl_bridge.config import SplunkMCPConfig
from spl_bridge.server import ToolExecutionError, _build_mcp_app, _validate_args
from spl_bridge.tool_registry import load_builtin_tools


def _make_app(
    config: SplunkMCPConfig | None = None,
) -> tuple[Any, MagicMock]:
    cfg = config or SplunkMCPConfig(host="splunk.example.invalid", splunk_token="t")
    client = MagicMock()
    client.check_spl_safe.return_value = (True, "ok")
    client.is_saved_search_disabled.return_value = (False, "ok", "search")
    client.export_search.return_value = {
        "results": [],
        "truncated": False,
        "total_rows": 0,
    }
    return _build_mcp_app(cfg, client), client


def _tool_fn(app: Any, name: str) -> Any:
    return app._tool_manager._tools[name].fn


def _catalog_tool(name: str) -> dict[str, Any]:
    for tool in load_builtin_tools():
        if tool["name"] == name:
            return tool
    raise AssertionError(f"tool {name!r} not in builtin_tools.json")


@pytest.fixture(scope="module")
def parameters() -> dict[str, dict[str, Any]]:
    app, _ = _make_app()
    return {t.name: t.parameters for t in app._tool_manager.list_tools()}


class TestAdvertisedSchema:
    """Descriptions must reach the wire schema FastMCP advertises."""

    def test_run_query_descriptions(self, parameters: dict[str, Any]) -> None:
        props = parameters["splunk_run_query"]["properties"]
        assert props["query"]["description"] == server_mod._QUERY_DESC
        assert props["earliest_time"]["description"] == server_mod._EARLIEST_TIME_DESC
        assert props["latest_time"]["description"] == server_mod._LATEST_TIME_DESC
        assert props["row_limit"]["description"] == server_mod._ROW_LIMIT_DESC

    def test_run_query_earliest_documents_escape_hatch(self, parameters: dict[str, Any]) -> None:
        desc = parameters["splunk_run_query"]["properties"]["earliest_time"]["description"]
        assert '"0"' in desc  # all-time escape hatch is sanctioned
        assert "time_window" in desc  # points at the in-band disclosure

    def test_saved_search_descriptions(self, parameters: dict[str, Any]) -> None:
        props = parameters["splunk_run_saved_search"]["properties"]
        assert props["saved_search_name"]["description"] == server_mod._SS_NAME_DESC
        assert props["args"]["description"] == server_mod._SS_ARGS_DESC
        assert props["earliest_time"]["description"] == server_mod._SS_EARLIEST_DESC
        assert props["latest_time"]["description"] == server_mod._SS_LATEST_DESC
        assert props["app"]["description"] == server_mod._SS_APP_DESC

    def test_get_metadata_descriptions(self, parameters: dict[str, Any]) -> None:
        props = parameters["splunk_get_metadata"]["properties"]
        assert props["type"]["description"] == server_mod._META_TYPE_DESC
        assert props["index"]["description"] == server_mod._META_INDEX_DESC
        assert props["earliest_time"]["description"] == server_mod._META_EARLIEST_DESC
        assert props["latest_time"]["description"] == server_mod._META_LATEST_DESC
        # get_metadata gets no default window, so its description must not
        # claim one.
        assert "default -24h" not in props["earliest_time"]["description"]

    def test_all_advertised_params_have_descriptions(self, parameters: dict[str, Any]) -> None:
        for tool_name, params in parameters.items():
            for prop_name, prop in params.get("properties", {}).items():
                assert prop.get("description"), (
                    f"{tool_name}.{prop_name} advertised without a description"
                )


class TestCatalogAlignment:
    """builtin_tools.json must tell the same story as the wire schema."""

    def test_run_query_catalog_matches_constants(self) -> None:
        props = _catalog_tool("run_query")["inputSchema"]["properties"]
        assert props["query"]["description"] == server_mod._QUERY_DESC
        assert props["earliest_time"]["description"] == server_mod._EARLIEST_TIME_DESC
        assert props["latest_time"]["description"] == server_mod._LATEST_TIME_DESC
        assert props["row_limit"]["description"] == server_mod._ROW_LIMIT_DESC

    def test_saved_search_catalog_matches_constants(self) -> None:
        props = _catalog_tool("run_saved_search")["inputSchema"]["properties"]
        assert props["earliest_time"]["description"] == server_mod._SS_EARLIEST_DESC
        assert props["latest_time"]["description"] == server_mod._SS_LATEST_DESC

    def test_saved_search_time_range_enabled(self) -> None:
        meta = _catalog_tool("run_saved_search")["_meta"]["execution"]
        assert meta["time_range"] is True

    def test_run_query_time_params_have_no_pattern(self) -> None:
        # Time modifiers legitimately contain ``@ : + -`` etc. and travel
        # as REST form fields (never spliced into SPL), so a client-side
        # pattern would only reject valid values. Guard against one being
        # "helpfully" added later.
        props = _catalog_tool("run_query")["inputSchema"]["properties"]
        for field in ("earliest_time", "latest_time", "row_limit"):
            assert "pattern" not in props[field], f"{field} must not carry a pattern"

    def test_run_query_required_unchanged(self) -> None:
        assert _catalog_tool("run_query")["inputSchema"]["required"] == ["query"]


class TestValidationActivation:
    """Declaring the params in the catalog activates _validate_args."""

    def test_row_limit_type_enforced(self) -> None:
        err = _validate_args(_catalog_tool("run_query"), {"query": "x", "row_limit": "50"})
        assert err is not None
        assert "must be integer" in err

    def test_time_modifiers_not_pattern_rejected(self) -> None:
        for value in ("-24h@h", "@d+1h", "2025-12-31T00:00:00", "0", "now"):
            err = _validate_args(
                _catalog_tool("run_query"),
                {"query": "x", "earliest_time": value, "latest_time": value},
            )
            assert err is None, f"{value!r} wrongly rejected: {err}"


class TestDefaultTimeWindow:
    def test_default_applied_and_disclosed(self) -> None:
        app, client = _make_app()
        result = _tool_fn(app, "splunk_run_query")(query="search index=main")
        kwargs = client.export_search.call_args.kwargs
        assert kwargs["earliest_time"] == "-24h"
        assert kwargs["latest_time"] is None
        assert result.structuredContent["time_window"].startswith("-24h to now (default")

    def test_explicit_earliest_suppresses_default(self) -> None:
        app, client = _make_app()
        result = _tool_fn(app, "splunk_run_query")(query="search index=main", earliest_time="-1h")
        assert client.export_search.call_args.kwargs["earliest_time"] == "-1h"
        assert "time_window" not in result.structuredContent

    def test_explicit_latest_alone_suppresses_default(self) -> None:
        # Partial specification is respected as given: defaulting earliest
        # under an explicit historical latest could produce earliest>latest.
        app, client = _make_app()
        result = _tool_fn(app, "splunk_run_query")(query="search index=main", latest_time="-30d")
        kwargs = client.export_search.call_args.kwargs
        assert kwargs["earliest_time"] is None
        assert kwargs["latest_time"] == "-30d"
        assert "time_window" not in result.structuredContent

    def test_zero_escape_hatch_passes_through(self) -> None:
        app, client = _make_app()
        result = _tool_fn(app, "splunk_run_query")(query="search index=main", earliest_time="0")
        assert client.export_search.call_args.kwargs["earliest_time"] == "0"
        assert "time_window" not in result.structuredContent

    def test_config_none_disables_default(self) -> None:
        cfg = SplunkMCPConfig(
            host="splunk.example.invalid",
            splunk_token="t",
            default_earliest_time=None,
        )
        app, client = _make_app(cfg)
        result = _tool_fn(app, "splunk_run_query")(query="search index=main")
        assert client.export_search.call_args.kwargs["earliest_time"] is None
        assert "time_window" not in result.structuredContent

    def test_custom_default_disclosed(self) -> None:
        cfg = SplunkMCPConfig(
            host="splunk.example.invalid",
            splunk_token="t",
            default_earliest_time="-7d",
        )
        app, client = _make_app(cfg)
        result = _tool_fn(app, "splunk_run_query")(query="search index=main")
        assert client.export_search.call_args.kwargs["earliest_time"] == "-7d"
        assert result.structuredContent["time_window"].startswith("-7d to now (default")


class TestDefaultWindowScope:
    """The default must never bleed into other time_range tools."""

    def test_saved_search_gets_no_default(self) -> None:
        app, client = _make_app()
        result = _tool_fn(app, "splunk_run_saved_search")(saved_search_name="My Report")
        kwargs = client.export_search.call_args.kwargs
        assert kwargs["earliest_time"] is None
        assert kwargs["latest_time"] is None
        assert "time_window" not in result.structuredContent

    def test_get_metadata_gets_no_default(self) -> None:
        app, client = _make_app()
        result = _tool_fn(app, "splunk_get_metadata")(type="sourcetypes")
        kwargs = client.export_search.call_args.kwargs
        assert kwargs["earliest_time"] is None
        assert kwargs["latest_time"] is None
        assert "time_window" not in result.structuredContent


class TestSavedSearchTimeForwarding:
    """Regression: explicit overrides were dropped while the catalog had
    ``time_range: false``."""

    def test_explicit_times_reach_export(self) -> None:
        app, client = _make_app()
        _tool_fn(app, "splunk_run_saved_search")(
            saved_search_name="My Report", earliest_time="-7d", latest_time="now"
        )
        kwargs = client.export_search.call_args.kwargs
        assert kwargs["earliest_time"] == "-7d"
        assert kwargs["latest_time"] == "now"

    def test_get_metadata_explicit_times_reach_export(self) -> None:
        app, client = _make_app()
        _tool_fn(app, "splunk_get_metadata")(
            type="sourcetypes", earliest_time="-30d", latest_time="now"
        )
        kwargs = client.export_search.call_args.kwargs
        assert kwargs["earliest_time"] == "-30d"
        assert kwargs["latest_time"] == "now"


class TestTimeoutMessage:
    def test_remediation_hint_present(self) -> None:
        app, _ = _make_app()
        with patch(
            "spl_bridge.server.build_spl",
            side_effect=requests.exceptions.Timeout("read timeout"),
        ):
            with pytest.raises(ToolExecutionError) as excinfo:
                _tool_fn(app, "splunk_run_query")(query="search index=main")
        msg = str(excinfo.value)
        assert "Splunk request timed out after 45.0s" in msg
        assert "earliest_time" in msg
        assert "get_metadata" in msg
        assert "request_id=" in msg
