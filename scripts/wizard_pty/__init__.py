"""Reusable PTY harness for the spl-bridge setup wizard.

The wizard refuses to run without a real TTY (it must never read
secrets from a pipe). To exercise it end-to-end in CI we spawn it on
a pseudo-terminal via :mod:`pty`, replay the keystrokes a human
would type, and assert the resulting artefacts.

Components:

* :mod:`scripts.wizard_pty.driver` -- :class:`PtyDriver`, the fork +
  ANSI-strip + marker-and-respond loop with transcript capture and
  configurable secret-leak assertions.
* :mod:`scripts.wizard_pty.scenarios` -- one module per wizard
  scenario (token auth, password + Cursor, password + Claude
  Desktop, dotfile fallback, ...). Each scenario declares its
  prepare/script/verify/cleanup steps; the driver runs them.
* :mod:`scripts.run_wizard_pty` -- CLI runner that lists / runs
  scenarios from the command line. Also collected by pytest under
  the ``pty`` marker when ``WIZARD_PTY_TESTS=1`` is set.
"""
