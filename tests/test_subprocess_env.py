"""Verify the integration/safety subprocess env builders do NOT leak
unrelated host secrets like AWS_*, ANTHROPIC_*, GITHUB_TOKEN, etc. (G6)."""

from __future__ import annotations

import os

import pytest


def _all_envs() -> list[dict[str, str]]:
    from tests.test_integration import _minimal_subprocess_env as int_env
    from tests.test_safety import _minimal_subprocess_env as safety_env

    return [int_env(), safety_env()]


@pytest.mark.parametrize(
    "leak_var",
    [
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "DOCKER_PASSWORD",
    ],
)
def test_no_unrelated_secret_leaks(leak_var: str, monkeypatch) -> None:
    monkeypatch.setenv(leak_var, "sentinel-must-not-leak")
    for env in _all_envs():
        assert leak_var not in env, f"{leak_var} unexpectedly forwarded to subprocess env"


def test_explicitly_listed_vars_pass_through(monkeypatch) -> None:
    monkeypatch.setenv("SPLUNK_TOKEN", "abc")
    monkeypatch.setenv("SPLUNK_HOST", "splunk.example.test")
    for env in _all_envs():
        assert env.get("SPLUNK_TOKEN") == "abc"
        assert env.get("SPLUNK_HOST") == "splunk.example.test"


def test_path_is_forwarded() -> None:
    for env in _all_envs():
        assert "PATH" in env
        assert env["PATH"] == os.environ.get("PATH", "")
