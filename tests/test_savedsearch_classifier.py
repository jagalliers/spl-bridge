"""Verify the saved-search HTTP 400 classifier in ``SplunkClient``.

Covers the targeted error-ergonomics opt-in introduced for
``splunk_run_saved_search``: when a saved search rejects with HTTP
400 because a required token argument was not supplied, the upstream
body matches a known marker and we want the client to receive a
project-curated remediation hint rather than the opaque generic
wrapper.

The classifier is intentionally narrow:
  * keyword-only opt-in flag (``classify_400_as_savedsearch``);
    defaults to False so every non-savedsearch call site keeps the
    always-redact behaviour.
  * status must be exactly 400; other statuses fall through.
  * body must contain one of the allow-listed markers.
  * upstream body bytes are *never* echoed to the client; the hint
    string is project-owned text only.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.logging_config import clear_log_context, set_request_id
from spl_bridge.splunk_client import (
    SplunkClient,
    _classify_savedsearch_400,
)

# A body that contains an upstream marker plus realistic Splunk
# decoration. We assert the marker text never reaches the client.
UPSTREAM_BODY_MISSING_TOKEN = (
    '{"messages":[{"type":"ERROR","text":"Error in '
    "'savedsearch' command: Encountered the following error while "
    "building a search for saved search 'Active Index Count': Error "
    "while replacing variable name='hosts'. Could not find variable "
    'in the argument map.","help":""}]}'
)
# Distinctive substrings from the upstream body that must NEVER
# appear in the client-facing error string.
UPSTREAM_LEAK_NEEDLES = (
    "savedsearch",
    "Active Index Count",
    "name='hosts'",
    "variable",  # appears in both upstream body and our hint, but
    # the literal "argument map" / "Could not find" markers are the
    # ones we must keep server-side.
)


def _client() -> SplunkClient:
    cfg = SplunkMCPConfig(host="h", splunk_token="t")
    return SplunkClient(cfg)


def _resp(status: int, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    if text:
        try:
            r.json.return_value = json.loads(text)
        except Exception:
            r.json.side_effect = json.JSONDecodeError("bad", text, 0)
    return r


@pytest.fixture(autouse=True)
def _rid():
    set_request_id()
    yield
    clear_log_context()


class TestClassifierUnit:
    """Pure-function tests for ``_classify_savedsearch_400``."""

    def test_argument_map_marker_returns_args_hint(self) -> None:
        hint = _classify_savedsearch_400(UPSTREAM_BODY_MISSING_TOKEN)
        assert hint is not None
        assert "args" in hint
        # Must not include any upstream-derived identifier. The hint
        # may legitimately use the *word* "hosts" inside its own
        # generic example (``args='hosts="web*"'``), but never any
        # upstream-shaped fragment that would imply we extracted
        # data from the response body.
        assert "Active Index Count" not in hint
        assert "name='hosts'" not in hint
        assert "savedsearch" not in hint

    def test_could_not_find_variable_marker_returns_token_hint(self) -> None:
        # Body that contains the second marker but not the first.
        body = '{"messages":[{"type":"ERROR","text":"Could not find variable in scope"}]}'
        hint = _classify_savedsearch_400(body)
        assert hint is not None
        assert "args" in hint
        # Must not include any upstream-derived identifier.
        assert "scope" not in hint

    def test_first_matching_marker_wins(self) -> None:
        # Body contains both markers; first one in the allow-list
        # ("argument map") should win.
        body = "argument map ... Could not find variable ..."
        first = _classify_savedsearch_400(body)
        second = _classify_savedsearch_400("Could not find variable only")
        # Both return non-None, but the first call produces the
        # "Saved search requires arguments" hint, not the second one.
        assert first is not None and second is not None
        assert first != second
        assert first.startswith("Saved search requires arguments")
        assert second.startswith("Saved search references a token variable")

    def test_empty_body_returns_none(self) -> None:
        assert _classify_savedsearch_400("") is None

    def test_unrelated_400_body_returns_none(self) -> None:
        assert (
            _classify_savedsearch_400('{"messages":[{"type":"ERROR","text":"Internal error"}]}')
            is None
        )

    def test_classifier_is_case_sensitive(self) -> None:
        # Intentionally case-sensitive: uppercase variants must not
        # match. This keeps the marker set small and predictable.
        assert _classify_savedsearch_400("ARGUMENT MAP") is None
        assert _classify_savedsearch_400("could not find variable") is None


class TestExportSearchClassifierIntegration:
    """``export_search`` end-to-end path tests with mocked upstream."""

    def test_400_with_marker_and_flag_returns_hint(self) -> None:
        c = _client()
        with patch.object(c, "call_api", return_value=_resp(400, UPSTREAM_BODY_MISSING_TOKEN)):
            out = c.export_search('| savedsearch "x"', classify_400_as_savedsearch=True)
        assert "error" in out
        # Curated hint and request-id correlation are present.
        assert "args" in out["error"]
        assert "HTTP 400" in out["error"]
        assert "request_id=" in out["error"]
        # Upstream body bytes never appear in the client message.
        for needle in UPSTREAM_LEAK_NEEDLES:
            assert needle not in out["error"], (
                f"Upstream leak: {needle!r} appeared in client error string"
            )

    def test_400_with_marker_but_flag_disabled_uses_generic_wrapper(self) -> None:
        """Default behaviour must not change for callers that don't opt in."""
        c = _client()
        with patch.object(c, "call_api", return_value=_resp(400, UPSTREAM_BODY_MISSING_TOKEN)):
            # No classify_400_as_savedsearch=True kwarg.
            out = c.export_search("search index=main")
        assert "error" in out
        assert "Splunk API error" in out["error"]
        assert "HTTP 400" in out["error"]
        # The hint vocabulary must NOT appear when the flag is off.
        assert "args" not in out["error"]
        # And the upstream body still must not leak.
        for needle in UPSTREAM_LEAK_NEEDLES:
            assert needle not in out["error"]

    def test_400_without_marker_falls_back_to_generic_wrapper(self) -> None:
        c = _client()
        with patch.object(
            c,
            "call_api",
            return_value=_resp(400, '{"messages":[{"type":"ERROR","text":"unrelated"}]}'),
        ):
            out = c.export_search('| savedsearch "x"', classify_400_as_savedsearch=True)
        assert "error" in out
        assert "Splunk API error" in out["error"]
        assert "HTTP 400" in out["error"]
        assert "unrelated" not in out["error"]

    def test_500_with_marker_does_not_classify(self) -> None:
        """Status must be exactly 400; 5xx never gets the hint."""
        c = _client()
        with patch.object(c, "call_api", return_value=_resp(500, UPSTREAM_BODY_MISSING_TOKEN)):
            out = c.export_search('| savedsearch "x"', classify_400_as_savedsearch=True)
        assert "error" in out
        assert "Splunk API error" in out["error"]
        assert "HTTP 500" in out["error"]
        assert "args" not in out["error"]
