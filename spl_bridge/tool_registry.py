"""Tool registry: loads builtin_tools.json, binds arguments, builds SPL.

The ``type`` enum for ``get_knowledge_objects`` is resolved via a strict
key->SPL map stored in ``_meta._type_spl_map``.  Only keys present in
that map are accepted (injection prevention).
"""

from __future__ import annotations

import json
import logging
import re
from importlib import resources as pkg_resources
from typing import Any

logger = logging.getLogger(__name__)

_SAVEDSEARCH_RE = re.compile(r"^\s*\|\s*savedsearch\s+\$(\w+)\$", re.IGNORECASE)


def _load_json_resource(name: str) -> Any:
    ref = pkg_resources.files("spl_bridge").joinpath(f"data/{name}")
    return json.loads(ref.read_text(encoding="utf-8"))


def load_builtin_tools() -> list[dict[str, Any]]:
    data = _load_json_resource("builtin_tools.json")
    tools: list[dict[str, Any]] = data.get("tools", [])
    return tools


def load_safe_spl() -> dict[str, Any]:
    result: dict[str, Any] = _load_json_resource("safe_spl.json")
    return result


def load_generating_commands() -> set[str]:
    data = _load_json_resource("generating_commands.json")
    return set(data.get("generating_commands", []))


def mcp_tool_name(tool: dict[str, Any]) -> str:
    """Build the prefixed MCP tool name, e.g. ``splunk_run_query``."""
    meta = tool.get("_meta", {})
    prefix = meta.get("name_prefix") or meta.get("external_app_id", "splunk")
    return f"{prefix}_{tool['name']}"


def build_spl(
    tool: dict[str, Any],
    arguments: dict[str, Any],
    *,
    default_row_limit: int,
    max_row_limit: int,
) -> tuple[str, int | None, str | None, str | None]:
    """Substitute ``$arg$`` placeholders into the execution template.

    Returns ``(spl, effective_row_limit, earliest_time, latest_time)``.
    """
    meta = tool.get("_meta", {})
    execution = meta.get("execution", {})
    template: str = execution.get("template", "")
    row_limiter: bool = execution.get("row_limiter", False)
    time_range: bool = execution.get("time_range", False)

    type_spl_map: dict[str, str] | None = meta.get("_type_spl_map")
    if type_spl_map is not None:
        type_key = arguments.get("type", "")
        if type_key not in type_spl_map:
            raise ValueError(f"Unknown type '{type_key}'. Allowed: {sorted(type_spl_map.keys())}")
        template = type_spl_map[type_key]

    schema_props = tool.get("inputSchema", {}).get("properties", {})

    for arg_name, prop_def in schema_props.items():
        placeholder = f"${arg_name}$"
        if placeholder not in template:
            continue

        value = arguments.get(arg_name)
        if value is None:
            default = prop_def.get("default")
            value = default if default is not None else ""

        str_value = str(value)
        needs_quoting = prop_def.get("_meta", {}).get("formatting", {}).get("needs_quoting", False)
        if needs_quoting:
            str_value = json.dumps(str_value)
        template = template.replace(placeholder, str_value)

    row_limit: int | None = None
    if row_limiter:
        raw_limit = arguments.get("row_limit")
        if raw_limit is not None:
            row_limit = min(int(raw_limit), max_row_limit)
        else:
            row_limit = default_row_limit

    earliest: str | None = None
    latest: str | None = None
    if time_range:
        earliest = arguments.get("earliest_time") or arguments.get("earliest")
        latest = arguments.get("latest_time") or arguments.get("latest")

    spl = template.strip()

    leftover = re.findall(r"\$\w+\$", spl)
    if leftover:
        raise ValueError(f"Missing required template placeholders: {sorted(set(leftover))}")

    return spl, row_limit, earliest, latest
