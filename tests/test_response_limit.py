"""L-2: enforce ``max_response_bytes`` cap on Splunk API responses.

A pathological or compromised Splunk endpoint must not be able to exhaust
client memory by streaming an unbounded body.  ``_do_request`` materializes
the response through ``_read_bounded(...)`` and converts an over-cap body
into a synthetic HTTP 502 instead of buffering it all.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from requests import Response

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.splunk_client import (
    ResponseTooLargeError,
    SplunkClient,
    _read_bounded,
)


class _FakeResp:
    """Minimal stand-in for ``requests.Response`` for ``_read_bounded``."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size: int = 65536):  # noqa: ARG002
        yield from self._chunks

    def close(self) -> None:
        self.closed = True


class TestReadBounded:
    def test_under_cap_returns_full_body(self) -> None:
        body = _read_bounded(_FakeResp([b"abc", b"def"]), limit=1024)
        assert body == b"abcdef"

    def test_over_cap_raises(self) -> None:
        big = b"x" * 600
        with pytest.raises(ResponseTooLargeError, match="exceeded"):
            _read_bounded(_FakeResp([big, big]), limit=1024)

    def test_exact_cap_is_allowed(self) -> None:
        body = _read_bounded(_FakeResp([b"x" * 1024]), limit=1024)
        assert len(body) == 1024

    def test_one_byte_over_cap_raises(self) -> None:
        with pytest.raises(ResponseTooLargeError):
            _read_bounded(_FakeResp([b"x" * 1025]), limit=1024)

    def test_empty_body(self) -> None:
        assert _read_bounded(_FakeResp([]), limit=1024) == b""

    def test_response_is_closed_on_overflow(self) -> None:
        resp = _FakeResp([b"x" * 2048])
        with pytest.raises(ResponseTooLargeError):
            _read_bounded(resp, limit=1024)
        assert resp.closed is True


class TestConfigParsing:
    """``MCP_MAX_RESPONSE_BYTES`` is parsed and bounded."""

    def test_default_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "MCP_MAX_RESPONSE_BYTES",
            "SPLUNK_HOST",
            "SPLUNK_TOKEN",
            "SPLUNK_USERNAME",
            "SPLUNK_PASSWORD",
            "SPLUNK_ALLOW_PLAINTEXT",
        ):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.max_response_bytes == 64 * 1024 * 1024

    def test_explicit_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_MAX_RESPONSE_BYTES", "1024")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.max_response_bytes == 1024

    def test_zero_or_negative_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_MAX_RESPONSE_BYTES", "0")
        with pytest.raises(ValueError, match="MCP_MAX_RESPONSE_BYTES"):
            SplunkMCPConfig.from_env()

        monkeypatch.setenv("MCP_MAX_RESPONSE_BYTES", "-1")
        with pytest.raises(ValueError, match="MCP_MAX_RESPONSE_BYTES"):
            SplunkMCPConfig.from_env()

    def test_above_hard_cap_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        # Hard cap is 1 GiB.
        monkeypatch.setenv("MCP_MAX_RESPONSE_BYTES", str(2 * 1024 * 1024 * 1024))
        with pytest.raises(ValueError, match="MCP_MAX_RESPONSE_BYTES"):
            SplunkMCPConfig.from_env()

    def test_non_integer_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_MAX_RESPONSE_BYTES", "not-a-number")
        with pytest.raises(ValueError, match="MCP_MAX_RESPONSE_BYTES"):
            SplunkMCPConfig.from_env()


class TestCallApiEnforcement:
    """End-to-end: ``call_api`` over-cap returns synthetic 502, not OOM."""

    def _client(self, cap: int) -> SplunkClient:
        cfg = SplunkMCPConfig(host="h", splunk_token="t", max_response_bytes=cap)
        return SplunkClient(cfg)

    def _fake_response(self, chunks: list[bytes], status: int = 200) -> Response:
        resp = Response()
        resp.status_code = status
        resp.url = "https://h:8089/services/test?secret=x"
        # Override the streaming hook; ``_read_bounded`` only calls
        # ``iter_content``.  Once ``_do_request`` materializes the body it
        # back-fills ``_content`` so downstream ``.text`` / ``.json()`` work.
        resp.iter_content = lambda chunk_size=65536: iter(chunks)  # type: ignore[method-assign]  # noqa: ARG005
        return resp

    def test_under_cap_returns_real_body(self) -> None:
        client = self._client(cap=1024)
        fake = self._fake_response([b"hello"])

        with patch("spl_bridge.splunk_client.requests.request", return_value=fake):
            response = client.call_api("GET", "services/test")

        assert response.status_code == 200
        assert response.content == b"hello"
        # ``.text`` and ``.json()`` keep working off the materialized body.
        assert response.text == "hello"

    def test_over_cap_returns_502(self, caplog: pytest.LogCaptureFixture) -> None:
        client = self._client(cap=128)
        fake = self._fake_response([b"x" * 256])

        with patch("spl_bridge.splunk_client.requests.request", return_value=fake):
            response = client.call_api("GET", "services/test")

        assert response.status_code == 502
        # The synthetic body must not contain the raw query-string secret.
        assert b"secret=x" not in response.content
        # Server-side log must scrub the query string too.
        assert "secret=x" not in caplog.text

    def test_chunked_body_just_under_cap_succeeds(self) -> None:
        client = self._client(cap=1024)
        fake = self._fake_response([b"x" * 512, b"y" * 512])

        with patch("spl_bridge.splunk_client.requests.request", return_value=fake):
            response = client.call_api("GET", "services/test")

        assert response.status_code == 200
        assert len(response.content) == 1024

    def test_chunked_body_one_byte_over_cap_fails(self) -> None:
        client = self._client(cap=1024)
        fake = self._fake_response([b"x" * 512, b"y" * 512, b"z"])

        with patch("spl_bridge.splunk_client.requests.request", return_value=fake):
            response = client.call_api("GET", "services/test")

        assert response.status_code == 502
