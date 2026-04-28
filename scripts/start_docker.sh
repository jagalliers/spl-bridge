#!/usr/bin/env bash
# Start Docker Desktop on macOS (or verify dockerd on Linux) and block
# until the engine is ready to accept commands.
#
# Used by ``tests/test_docker.py`` and ``scripts/release_check.sh`` so
# the developer/CI doesn't need to remember to launch Docker before
# running the container suite.
#
# Exit codes:
#   0   Docker is up and ``docker info`` returned 0
#   1   Docker did not become ready within the deadline
#   2   Docker CLI is not installed
#
# Notes:
#   * On macOS we ``open -a Docker`` (idempotent -- a no-op if Docker
#     Desktop is already running).
#   * On Linux we just poll; we never try to ``systemctl start`` because
#     that requires sudo and the right policy. If the engine isn't up
#     on Linux, the operator already knows about it.
#   * Polling uses ``docker info`` (not ``docker version``) because the
#     latter succeeds against the client even when the daemon socket is
#     unreachable.

set -uo pipefail

DEADLINE_SECS="${DOCKER_START_TIMEOUT:-90}"
POLL_INTERVAL_SECS=2

if ! command -v docker >/dev/null 2>&1; then
    echo "error: 'docker' CLI not found on PATH" >&2
    echo "       install Docker Desktop (macOS) or docker-engine (Linux)" >&2
    exit 2
fi

# Fast path: is the engine already responding?
if docker info >/dev/null 2>&1; then
    echo "docker is already running"
    exit 0
fi

uname_s="$(uname -s)"
case "$uname_s" in
    Darwin)
        echo "starting Docker Desktop (macOS) ..."
        # ``open -a Docker`` exits 0 immediately; the daemon takes
        # noticeably longer to come up (typically 5-30 s on first
        # launch after a reboot).
        if ! open -a Docker; then
            echo "error: failed to launch Docker Desktop via 'open -a Docker'" >&2
            exit 1
        fi
        ;;
    Linux)
        echo "docker engine appears down on Linux; not attempting to start it" >&2
        echo "       try 'sudo systemctl start docker' and re-run" >&2
        exit 1
        ;;
    *)
        echo "error: unsupported platform '$uname_s'" >&2
        exit 1
        ;;
esac

deadline=$(( $(date +%s) + DEADLINE_SECS ))
attempt=0
while true; do
    if docker info >/dev/null 2>&1; then
        echo "docker is ready (after $((attempt * POLL_INTERVAL_SECS))s)"
        exit 0
    fi
    if [[ $(date +%s) -ge $deadline ]]; then
        echo "error: docker did not become ready within ${DEADLINE_SECS}s" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep "$POLL_INTERVAL_SECS"
done
