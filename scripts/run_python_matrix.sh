#!/usr/bin/env bash
# Run the unit suite locally across the same Python versions CI does.
#
# Why this exists:
#   The GitHub Actions matrix in .github/workflows/ci.yml runs
#   3.10 / 3.11 / 3.12 / 3.13 on ubuntu and macos. Catching a
#   version-specific failure (typing surface drift, asyncio behavior
#   change, stdlib removal) before pushing is much cheaper than
#   waiting for CI. This script reproduces that matrix locally using
#   uv, which can fetch and cache toolchains for any of the targets.
#
# Why uv:
#   * No need for pyenv or Homebrew formulas per minor version.
#   * Per-version venvs are created in /tmp and torn down after, so
#     this leaves no junk in the working copy.
#   * Same dependency resolver semantics as `pip install -e '.[dev]'`.
#
# Usage:
#   ./scripts/run_python_matrix.sh                # all versions
#   ./scripts/run_python_matrix.sh 3.12 3.13      # subset
#   PYTHON_MATRIX_FAILFAST=1 ./scripts/run_python_matrix.sh
#
# Exit codes:
#   0  every requested version passed
#   1  one or more versions failed (a final summary is printed)
#   2  uv is not installed or a requested version could not be fetched

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_VERSIONS=("3.10" "3.11" "3.12" "3.13")

if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv is not installed; see https://docs.astral.sh/uv/" >&2
    exit 2
fi

if [[ $# -gt 0 ]]; then
    VERSIONS=("$@")
else
    VERSIONS=("${DEFAULT_VERSIONS[@]}")
fi

FAILFAST="${PYTHON_MATRIX_FAILFAST:-0}"

# Collect per-version results so we can print a clear summary at the
# end. macOS bash 3.2 has no associative arrays, so we keep two
# parallel arrays.
RESULT_VERSIONS=()
RESULT_STATUSES=()

run_one() {
    local pyver="$1"
    local venv_dir
    venv_dir="$(mktemp -d -t "spl-bridge-py${pyver}-XXXXXX")"
    # shellcheck disable=SC2064 -- we want $venv_dir expanded now,
    # not at trap time, so the right directory is removed even if the
    # variable is reassigned for a later iteration.
    trap "rm -rf '$venv_dir'" RETURN

    echo
    echo "================================================================"
    echo "  python ${pyver}  ($(date '+%H:%M:%S'))"
    echo "================================================================"

    # ``uv venv`` will download the requested toolchain on first use
    # and cache it under ~/.local/share/uv/python -- subsequent runs
    # reuse the cache.
    if ! uv venv --python "$pyver" "$venv_dir"; then
        echo "error: uv could not create venv for python ${pyver}" >&2
        return 1
    fi

    # Install the project + dev extras using the matched interpreter.
    # We feed uv the venv's python via --python so it doesn't need to
    # be activated in our shell.
    if ! uv pip install --python "${venv_dir}/bin/python" -e "${REPO_ROOT}[dev]"; then
        echo "error: dependency install failed for python ${pyver}" >&2
        return 1
    fi

    # Run the same fast unit subset that ci.yml runs. Skip integration
    # and safety suites here -- they are gated on a live Splunk and
    # are not part of the version matrix promise.
    "${venv_dir}/bin/python" -m pytest -q \
        --ignore="${REPO_ROOT}/tests/test_integration.py" \
        --ignore="${REPO_ROOT}/tests/test_safety.py" \
        --ignore="${REPO_ROOT}/tests/test_docker.py"
}

OVERALL_RC=0
for v in "${VERSIONS[@]}"; do
    if run_one "$v"; then
        RESULT_VERSIONS+=("$v")
        RESULT_STATUSES+=("PASS")
    else
        RESULT_VERSIONS+=("$v")
        RESULT_STATUSES+=("FAIL")
        OVERALL_RC=1
        if [[ "$FAILFAST" == "1" ]]; then
            echo "PYTHON_MATRIX_FAILFAST=1: stopping after first failure" >&2
            break
        fi
    fi
done

echo
echo "================================================================"
echo "  python matrix summary"
echo "================================================================"
for i in "${!RESULT_VERSIONS[@]}"; do
    printf "  %-6s  %s\n" "${RESULT_VERSIONS[$i]}" "${RESULT_STATUSES[$i]}"
done

exit "$OVERALL_RC"
