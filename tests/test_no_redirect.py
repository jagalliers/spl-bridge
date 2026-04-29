"""M-1: SplunkClient must not follow HTTP redirects.

A compromised or misconfigured Splunk endpoint must not be able to silently
redirect the bearer-carrying client to another origin.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.splunk_client import SplunkClient


def _client() -> SplunkClient:
    return SplunkClient(SplunkMCPConfig(host="splunk.example", splunk_token="t"))


def test_do_request_disables_redirects() -> None:
    """``allow_redirects=False`` is passed to the underlying session."""
    client = _client()
    fake_response = MagicMock()
    fake_response.status_code = 302

    with patch("spl_bridge.splunk_client.requests.request", return_value=fake_response) as mock_req:
        result = client._do_request(
            method="GET",
            url="https://splunk.example:8089/services/test",
            req_headers={"Authorization": "Bearer t"},
            params=None,
            data=None,
        )

    assert result is fake_response
    assert mock_req.call_count == 1
    kwargs = mock_req.call_args.kwargs
    assert kwargs["allow_redirects"] is False


def test_call_api_returns_redirect_without_following() -> None:
    """A 302 propagates back to the caller; no second outbound request is made."""
    client = _client()
    redirect = MagicMock()
    redirect.status_code = 302
    redirect.headers = {"Location": "http://evil.example/x"}

    with patch("spl_bridge.splunk_client.requests.request", return_value=redirect) as mock_req:
        response = client.call_api("GET", "services/auth/login")

    assert response.status_code == 302
    # Token-mode never retries, and we must not have followed the 302 either.
    assert mock_req.call_count == 1
