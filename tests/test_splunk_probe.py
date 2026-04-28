"""Tests for ``spl_bridge.setup_wizard.splunk_probe``.

The wizard's connectivity probe must never raise -- the operator
will be looking at it on a TTY and a traceback there is hostile.
We assert that:

* Happy path returns ``ok=True`` with server_name/version pulled
  from the ``server/info`` JSON envelope.
* Non-200 returns a structured failure (``ok=False`` with an
  ``HTTP nnn`` error string) instead of raising.
* Any unexpected exception inside the client surfaces as
  ``ok=False`` with a one-line, length-capped error message.
* The shape extractor tolerates every degenerate body shape Splunk
  has shipped over the years (no entry, entry not a list, content
  not a dict, missing fields).
* The ``_short_error`` helper truncates long upstream messages so
  they don't blow up the wizard's TTY layout.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.setup_wizard import splunk_probe


def _config() -> SplunkMCPConfig:
    """Token-mode config so the probe doesn't try to log in."""
    return SplunkMCPConfig(
        host="splunk.example.test",
        port=8089,
        scheme="https",
        ssl_verify=False,
        timeout=2.0,
        splunk_token="fake-token-for-test",  # noqa: S106
    )


def _patch_client(
    monkeypatch: pytest.MonkeyPatch, response: MagicMock | None, raise_with: Exception | None = None
) -> MagicMock:
    fake = MagicMock()
    if raise_with is not None:
        fake.call_api.side_effect = raise_with
    else:
        fake.call_api.return_value = response
    monkeypatch.setattr(splunk_probe, "SplunkClient", lambda _config: fake)
    return fake


def test_probe_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {
        "entry": [
            {
                "content": {
                    "serverName": "splunk-lab-01",
                    "version": "9.2.1",
                    "build": "should-be-ignored-because-version-wins",
                }
            }
        ]
    }
    resp = MagicMock(status_code=200)
    resp.json.return_value = body
    _patch_client(monkeypatch, resp)

    result = splunk_probe.probe(_config())
    assert result.ok is True
    assert result.error is None
    assert result.server_name == "splunk-lab-01"
    assert result.version == "9.2.1"
    assert result.auth_mode == "token"


def test_probe_non_200_returns_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    resp = MagicMock(status_code=403)
    resp.json.return_value = {}
    _patch_client(monkeypatch, resp)

    result = splunk_probe.probe(_config())
    assert result.ok is False
    assert result.server_name is None
    assert result.version is None
    assert "HTTP 403" in (result.error or "")


def test_probe_handles_invalid_json_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the server returns 200 but a body that is not JSON we
    must still return a normal-shaped ProbeResult (the empty body
    just means we won't have server_name/version)."""
    resp = MagicMock(status_code=200)
    resp.json.side_effect = ValueError("not json")
    _patch_client(monkeypatch, resp)

    result = splunk_probe.probe(_config())
    assert result.ok is True
    assert result.server_name is None
    assert result.version is None


def test_probe_swallows_call_api_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Network blow-ups become a structured failure -- the wizard
    UI will render the message rather than crash."""
    _patch_client(monkeypatch, response=None, raise_with=ConnectionError("nope"))

    result = splunk_probe.probe(_config())
    assert result.ok is False
    assert result.error is not None
    assert "nope" in result.error


# ---------------------------------------------------------------------------
# _extract_server_info shape tolerance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        None,
        "not a dict",
        123,
        {},  # missing entry
        {"entry": []},  # empty entry list
        {"entry": "not a list"},  # entry wrong type
        {"entry": [{}]},  # entry[0] has no content
        {"entry": [{"content": "string"}]},  # content wrong type
        {"entry": [{"content": {}}]},  # content has no fields
    ],
)
def test_extract_server_info_handles_degenerate_bodies(body: object) -> None:
    out = splunk_probe._extract_server_info(body)
    assert out == {} or set(out.keys()).issubset({"server_name", "version"})


def test_extract_server_info_prefers_first_alternative_key() -> None:
    body = {
        "entry": [
            {
                "content": {
                    # We allow both ``serverName`` and ``server_name``;
                    # whichever comes first in the lookup wins.
                    "server_name": "wins",
                    "host": "loses",
                    "build": "fallback-version",
                }
            }
        ]
    }
    out = splunk_probe._extract_server_info(body)
    assert out["server_name"] == "wins"
    assert out["version"] == "fallback-version"


# ---------------------------------------------------------------------------
# _short_error
# ---------------------------------------------------------------------------


def test_short_error_one_line() -> None:
    err = ValueError("line one\nline two\n  line three  ")
    out = splunk_probe._short_error(err)
    assert "\n" not in out
    assert "line one" in out


def test_short_error_truncates_at_200_chars() -> None:
    err = RuntimeError("x" * 500)
    out = splunk_probe._short_error(err)
    assert len(out) == 201
    assert out.endswith("…")
