#!/usr/bin/env bash
# Walk the README's CLI surface against a clean editable install:
# the same console-script entry point and `python -m` shim that end
# users get from `pipx install`, exercised here against the in-tree
# source so a regression in the package shape (missing entry point,
# broken extras, doctor crash, setup TTY guard) blocks the push
# before it ships.
#
# Why editable install instead of literal `pipx install` from the
# README's Quick Start: pipx is a thin wrapper around `pip install`
# into a private venv -- same packaging machinery, same
# console_script resolution, same extras handling. `pip install -e .`
# from this checkout exercises the same surface, faster, with no
# dependency on having pipx itself installed on the runner. If a
# pipx-specific regression shows up in the wild we can layer a
# second pipx-based smoke on top later.
#
# What we assert:
#   1. `pip install -e .` installs cleanly.
#   2. `spl-bridge --help` lists *every* documented subcommand
#      (serve, doctor, setup). A typo in the README that disagrees
#      with the CLI surfaces here, before users hit it.
#   3. `python -m spl_bridge --help` produces the same output --
#      this is the canonical entrypoint baked into our docker image
#      and Cursor MCP config blocks; if it ever 1) imports the wrong
#      thing, 2) skips argparse, 3) crashes on a fresh interpreter,
#      this catches it.
#   4. `spl-bridge doctor` against an unreachable host exits 1 (not
#      0, and not 2/137/-15). The README leans on doctor as the
#      first thing operators run; it must always print a friendly
#      message + exit 1, never a traceback.
#   5. Stdout discipline: `doctor` must NEVER print to stdout. The
#      doctor output goes to stderr because stdout is reserved for
#      MCP framing the moment somebody pipes both into a host. A
#      regression here would break MCP framing in some deployments.
#
# Why this lives separate from pytest:
#   It's a *user-facing* smoketest. We want to run it from a fresh
#   shell with nothing imported, mirroring what a new user's
#   environment looks like after `pipx install` (or any other
#   isolated install). Pytest with its plugins, conftest fixtures,
#   and patched env wouldn't catch e.g. a missing console_script
#   entry in pyproject.toml or a broken `python -m` shim.
#
# Usage:
#   scripts/readme_smoketest.sh                     # uses ./.venv-smoketest
#   SMOKETEST_VENV=/tmp/foo scripts/readme_smoketest.sh
#   SMOKETEST_KEEP=1 ...                            # don't delete venv on exit

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKETEST_VENV="${SMOKETEST_VENV:-$REPO_ROOT/.venv-smoketest}"
SMOKETEST_KEEP="${SMOKETEST_KEEP:-0}"

# pyproject requires >= 3.10; macOS ships /usr/bin/python3 as 3.9, so
# we probe candidates in newest-first order. Override with PY=... to
# pin a specific interpreter (CI does this).
pick_python() {
    if [[ -n "${PY:-}" ]]; then
        printf "%s\n" "$PY"
        return
    fi
    for cand in python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$cand" >/dev/null 2>&1; then
            local ver
            ver=$("$cand" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "0.0")
            local major minor
            major=${ver%.*}
            minor=${ver#*.}
            if [[ $major -gt 3 ]] || { [[ $major -eq 3 ]] && [[ $minor -ge 10 ]]; }; then
                printf "%s\n" "$cand"
                return
            fi
        fi
    done
    printf "" # signal failure
}

PY="$(pick_python)"
if [[ -z "$PY" ]]; then
    printf "no Python >= 3.10 found on PATH; set PY=/path/to/python3.x\n" >&2
    exit 1
fi

# --- helpers --------------------------------------------------------

c_red()   { printf "\033[31m%s\033[0m" "$1"; }
c_green() { printf "\033[32m%s\033[0m" "$1"; }
c_dim()   { printf "\033[2m%s\033[0m" "$1"; }
c_bold()  { printf "\033[1m%s\033[0m" "$1"; }

step() { printf "\n%s %s\n" "$(c_bold "==>")" "$1"; }
ok()   { printf "  %s %s\n" "$(c_green "✓")" "$1"; }
die()  { printf "  %s %s\n" "$(c_red   "✗")" "$1"; exit 1; }
note() { printf "  %s %s\n" "$(c_dim   "·")" "$1"; }

cleanup() {
    if [[ "$SMOKETEST_KEEP" != "1" ]]; then
        rm -rf "$SMOKETEST_VENV"
    fi
}
trap cleanup EXIT

# --- 1. clean install -----------------------------------------------

step "Creating isolated venv at $SMOKETEST_VENV"
"$PY" -m venv "$SMOKETEST_VENV" >/dev/null
SMOKE_PY="$SMOKETEST_VENV/bin/python"
SMOKE_PIP="$SMOKETEST_VENV/bin/pip"
SMOKE_BIN="$SMOKETEST_VENV/bin/spl-bridge"
ok "venv created"

step "pip install -e . (mirrors README Quick Start)"
"$SMOKE_PIP" install --quiet --upgrade pip || die "pip upgrade failed"
"$SMOKE_PIP" install --quiet -e "$REPO_ROOT" || die "pip install -e . failed"
ok "package installed"

if [[ ! -x "$SMOKE_BIN" ]]; then
    die "console_script spl-bridge not on \$PATH after install"
fi
ok "console script spl-bridge present"

# --- 2. CLI surface matches README ----------------------------------

step "spl-bridge --help advertises every documented subcommand"
HELP_OUTPUT="$("$SMOKE_BIN" --help 2>&1)" || die "spl-bridge --help exited non-zero"
for sub in serve doctor setup; do
    if ! grep -q -E "(^|[[:space:]])$sub([[:space:]]|$)" <<<"$HELP_OUTPUT"; then
        die "subcommand '$sub' missing from --help output (README claims it exists)"
    fi
done
ok "serve, doctor, setup all present"

# --- 3. `python -m spl_bridge` (Cursor/Docker entrypoint) -----------

step "python -m spl_bridge --help (Cursor MCP / docker entrypoint)"
M_HELP="$("$SMOKE_PY" -m spl_bridge --help 2>&1)" || die "python -m spl_bridge --help exited non-zero"
for sub in serve doctor setup; do
    grep -q "$sub" <<<"$M_HELP" || die "subcommand '$sub' missing from python -m output"
done
ok "module entrypoint matches console script"

# --- 4. `spl-bridge doctor` against unreachable host --------------

step "spl-bridge doctor against unreachable host returns 1 (not crash)"
# An RFC5737 documentation-only address that should never resolve to
# anything live in any environment we'd run in. We deliberately use
# a tight timeout so this completes in a few seconds.
DOCTOR_STDOUT_FILE="$(mktemp)"
DOCTOR_STDERR_FILE="$(mktemp)"
SPLUNK_HOST="192.0.2.123" \
SPLUNK_PORT="8089" \
SPLUNK_TOKEN="not-a-real-token-just-for-doctor-smoketest" \
SPLUNK_VERIFY_SSL="false" \
MCP_TIMEOUT="3" \
    "$SMOKE_BIN" doctor \
    1>"$DOCTOR_STDOUT_FILE" 2>"$DOCTOR_STDERR_FILE"
DOCTOR_RC=$?

if [[ $DOCTOR_RC -ne 1 ]]; then
    note "stderr: $(cat "$DOCTOR_STDERR_FILE")"
    rm -f "$DOCTOR_STDOUT_FILE" "$DOCTOR_STDERR_FILE"
    die "doctor exit code was $DOCTOR_RC, expected 1 (clean failure on unreachable host)"
fi
ok "doctor exited 1 as expected"

# Stdout discipline check. If we ever ship a print() in the doctor
# path, this turns it into a CI failure.
if [[ -s "$DOCTOR_STDOUT_FILE" ]]; then
    note "leaked stdout: $(cat "$DOCTOR_STDOUT_FILE")"
    rm -f "$DOCTOR_STDOUT_FILE" "$DOCTOR_STDERR_FILE"
    die "doctor wrote to stdout (must be silent on stdout to keep MCP framing clean)"
fi
ok "doctor kept stdout pristine"

# Sanity: stderr should at least mention what failed.
if ! grep -qiE "(doctor|fail|error|connect|timeout)" "$DOCTOR_STDERR_FILE"; then
    note "stderr was: $(cat "$DOCTOR_STDERR_FILE")"
    rm -f "$DOCTOR_STDOUT_FILE" "$DOCTOR_STDERR_FILE"
    die "doctor failure message not surfaced on stderr (operators won't know why)"
fi
ok "doctor surfaced a recognizable failure message on stderr"
rm -f "$DOCTOR_STDOUT_FILE" "$DOCTOR_STDERR_FILE"

# --- 5. setup wizard refuses to run without a TTY -----------------

step "spl-bridge setup refuses non-TTY stdin (security invariant)"
# We pipe /dev/null in to guarantee stdin is not a tty. The wizard
# must abort -- secrets must never flow through a pipe.
SETUP_RC=0
SETUP_OUT="$("$SMOKE_BIN" setup </dev/null 2>&1)" || SETUP_RC=$?
if [[ $SETUP_RC -eq 0 ]]; then
    note "setup output: $SETUP_OUT"
    die "setup wizard did NOT abort on non-TTY stdin (would let secrets flow through pipes)"
fi
if ! grep -qi -E "(tty|interactive|pipe)" <<<"$SETUP_OUT"; then
    note "setup output: $SETUP_OUT"
    die "setup wizard aborted but didn't explain why -- abort message regression"
fi
ok "setup correctly refused non-TTY invocation (rc=$SETUP_RC)"

# --- done ----------------------------------------------------------

printf "\n%s %s\n\n" "$(c_green "✓")" "$(c_bold "README walkthrough smoketest passed")"
