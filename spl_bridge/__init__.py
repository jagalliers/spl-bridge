"""stdio MCP bridge for the Splunk Enterprise / Splunk Cloud REST API."""

import logging
import sys

from spl_bridge.logging_config import MCPContextFilter, MCPJsonFormatter

# Single source of truth for the package version that the MCP server
# advertises via ``InitializationResult.serverInfo.version`` and that
# downstream tools surface in ``spl-bridge --version`` output. Prefer
# the dist-info recorded by the installer (matches pyproject.toml at
# install time); fall back to a local-version string when running
# from a source checkout that has not been ``pip install``-ed.
try:
    from importlib.metadata import PackageNotFoundError as _PkgNotFound
    from importlib.metadata import version as _pkg_version

    try:
        __version__: str = _pkg_version("spl-bridge")
    except _PkgNotFound:
        __version__ = "0.1.0+dev"
except Exception:  # pragma: no cover - importlib.metadata is stdlib >=3.8
    __version__ = "0.1.0+dev"

# We install one stderr handler on the `spl_bridge` logger and mark the
# logger as non-propagating. Rationale:
#
# 1. Without any handler, callers who import the package without first
#    calling `configure_logging()` get no logs -- a silent failure mode
#    that makes CLI commands like `spl-bridge doctor` useless when
#    something goes wrong.
# 2. If we let records propagate to root, any consumer that also
#    configures the root logger (our own `configure_logging`,
#    `logging.basicConfig`, pytest's `caplog`, a host application's
#    own logging setup) will emit every log line *twice* -- once from
#    this handler and once from the root handler. That's both noisy
#    and a strict correctness violation for the MCP stdio transport,
#    where duplicate or unexpected framing can corrupt the session.
#
# Setting ``propagate = False`` keeps our logs confined to our own
# handler(s), and `configure_logging()` replaces the handler list
# when a caller opts in to JSON-structured output.
_root = logging.getLogger("spl_bridge")
if not _root.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(MCPJsonFormatter())
    _handler.addFilter(MCPContextFilter())
    _root.setLevel(logging.INFO)
    _root.addHandler(_handler)
_root.propagate = False
