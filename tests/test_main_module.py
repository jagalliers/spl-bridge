"""Tests for ``python -m spl_bridge``.

This entrypoint is the canonical way docker, distroless, and the
MCP host invoke the server: there is no console_script in the
runtime container. So even though the module is small (3 lines),
breaking it ships a non-bootable image. We assert two contracts:

* Running the module (``runpy`` with run_name="__main__") delegates
  to ``spl_bridge.cli.main`` rather than swallowing the call or
  importing ``spl_bridge.server`` directly (which would skip
  argparse and break ``--help``).
* Subprocess invocation (``python -m spl_bridge --help``) exits 0
  and lists our subcommands. This is the same shape the docker
  hardening test runs against the built image.
"""

from __future__ import annotations

import runpy
import subprocess
import sys
from unittest.mock import MagicMock, patch


def test_module_dispatches_to_cli_main() -> None:
    """``runpy.run_module(..., run_name="__main__")`` triggers the
    ``if __name__ == "__main__":`` guard inside the module."""
    fake_main = MagicMock()
    with patch("spl_bridge.cli.main", fake_main):
        runpy.run_module("spl_bridge", run_name="__main__")
    fake_main.assert_called_once_with()


def test_module_help_exits_zero() -> None:
    """End-to-end: spawn a real interpreter, ``-m spl_bridge --help``,
    expect 0 and the three subcommands. This is what every container
    (and every CI matrix run) actually does."""
    proc = subprocess.run(  # noqa: S603 -- well-known argv, no shell
        [sys.executable, "-m", "spl_bridge", "--help"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert proc.returncode == 0, (
        f"`python -m spl_bridge --help` exited {proc.returncode}\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    out = proc.stdout + proc.stderr
    for sub in ("setup", "serve", "doctor"):
        assert sub in out, f"missing subcommand {sub!r} in --help output:\n{out}"
