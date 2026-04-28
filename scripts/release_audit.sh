#!/usr/bin/env bash
# Pre-release supply-chain audit.
#
# What it does (in order):
#   1. Ensures the release tooling (build, twine, pip-audit, cyclonedx-py)
#      is importable; if not, points at `pip install -e '.[release]'`.
#   2. Builds sdist + wheel into ./dist/ (clean rebuild every run).
#   3. Validates the artefacts with `twine check`.
#   4. Generates a CycloneDX SBOM (JSON) for the *current environment*
#      under ./dist/sbom/spl-bridge.cdx.json. We use the environment
#      SBOM rather than parsing pyproject.toml because it captures
#      every transitive dep that will actually be installed.
#   5. Runs pip-audit against the same environment and (separately)
#      against the freshly-built wheel.
#
# Why this script exists at all (rather than just inlining steps in
# build.yml):
#   * We want developers to be able to run the *exact* same pre-push
#     audit locally before opening a PR, without copy-pasting from a
#     YAML file.
#   * release_check.sh (Phase 8) calls this script as one of its
#     gating steps, so any logic change has a single home.
#
# Exit codes:
#   0  All audits passed; ./dist/ contains validated artefacts and
#      ./dist/sbom/spl-bridge.cdx.json contains the SBOM.
#   1  An audit step failed (vulnerabilities found, twine reject,
#      build error, SBOM generation error). Stderr explains which.
#   2  Required tooling is missing.
#
# Tunables:
#   RELEASE_AUDIT_STRICT=0   Treat pip-audit findings as warnings
#                            (default 1: any finding fails the run).
#   PIP_AUDIT_IGNORE_VULNS   Space-separated CVE/GHSA ids to skip
#                            (passed through as repeated --ignore-vuln).
#                            Document every entry in CHANGELOG.md.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"
SBOM_DIR="$DIST_DIR/sbom"
SBOM_FILE="$SBOM_DIR/spl-bridge.cdx.json"
# Repo-local pip-audit cache so the script works in restricted
# environments (read-only $HOME, sandboxed CI runners) and so cache
# state never bleeds across projects on a developer workstation.
PIP_AUDIT_CACHE_DIR="$REPO_ROOT/.pip-audit-cache"

STRICT="${RELEASE_AUDIT_STRICT:-1}"
EXTRA_IGNORES_RAW="${PIP_AUDIT_IGNORE_VULNS:-}"

# -----------------------------------------------------------------------
# Tooling probe
# -----------------------------------------------------------------------
require_tool() {
    local tool="$1"
    if ! python -c "import importlib, importlib.util, sys; sys.exit(0 if importlib.util.find_spec('$2') else 1)" 2>/dev/null; then
        echo "error: '$tool' is not installed (looked for python module '$2')" >&2
        echo "       fix: pip install -e '.[release]'" >&2
        return 1
    fi
}

probe_tools() {
    local missing=0
    require_tool "build"        "build"           || missing=1
    require_tool "twine"        "twine"           || missing=1
    require_tool "pip-audit"    "pip_audit"       || missing=1
    # cyclonedx-bom registers `cyclonedx_py.environment` (see PyPI page).
    require_tool "cyclonedx-py" "cyclonedx_py"    || missing=1
    return $missing
}

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------
section() {
    printf '\n========================================================\n  %s\n========================================================\n' "$1"
}

run_or_warn() {
    # Honour STRICT: in non-strict mode, audit failures degrade to
    # warnings (still printed; exit code remains the script overall).
    if "$@"; then
        return 0
    fi
    if [[ "$STRICT" == "1" ]]; then
        return 1
    fi
    echo "warning: ${*} returned non-zero, RELEASE_AUDIT_STRICT=0 -> not failing" >&2
    return 0
}

build_ignore_args() {
    # Convert PIP_AUDIT_IGNORE_VULNS="GHSA-xxx GHSA-yyy" into
    # repeated --ignore-vuln args. Bash 3.2-safe (no readarray).
    local out=()
    if [[ -n "$EXTRA_IGNORES_RAW" ]]; then
        # shellcheck disable=SC2206 -- intentional word-split on
        # whitespace; ids are vendor-controlled and contain no spaces.
        local toks=( $EXTRA_IGNORES_RAW )
        for t in "${toks[@]}"; do
            out+=( "--ignore-vuln" "$t" )
        done
    fi
    printf '%s\n' "${out[@]:-}"
}

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
cd "$REPO_ROOT"

section "Pre-flight: release tooling"
if ! probe_tools; then
    exit 2
fi

section "Clean build artefacts"
rm -rf "$DIST_DIR" "$REPO_ROOT/build" "$REPO_ROOT"/*.egg-info
mkdir -p "$DIST_DIR" "$SBOM_DIR" "$PIP_AUDIT_CACHE_DIR"

section "Build sdist + wheel"
python -m build --sdist --wheel --outdir "$DIST_DIR" || exit 1

section "twine check (PyPI metadata sanity)"
python -m twine check "$DIST_DIR"/*.whl "$DIST_DIR"/*.tar.gz || exit 1

section "Generate CycloneDX SBOM (current environment)"
# `cyclonedx-py environment` introspects the active interpreter's
# installed packages. That is the precise set the wheel will
# resolve to at install time when the same extras are used.
python -m cyclonedx_py environment \
    --output-format JSON \
    --output-file "$SBOM_FILE" \
    || exit 1
echo "SBOM written: $SBOM_FILE"

section "pip-audit (current environment)"
# Read ignore-args into a bash array via newline-separated read,
# tolerating empty input.
IGNORE_ARGS=()
while IFS= read -r line; do
    [[ -n "$line" ]] && IGNORE_ARGS+=( "$line" )
done < <(build_ignore_args)

run_or_warn python -m pip_audit \
    --strict \
    --progress-spinner off \
    --vulnerability-service osv \
    --cache-dir "$PIP_AUDIT_CACHE_DIR" \
    ${IGNORE_ARGS[@]+"${IGNORE_ARGS[@]}"} \
    || exit 1

section "pip-audit (built wheel only)"
WHEEL_PATH="$(find "$DIST_DIR" -maxdepth 1 -name '*.whl' -print -quit)"
if [[ -z "$WHEEL_PATH" || ! -f "$WHEEL_PATH" ]]; then
    echo "error: built wheel not found in $DIST_DIR" >&2
    exit 1
fi
# `--no-deps` semantics in pip-audit aren't direct, so we audit the
# wheel by pointing pip-audit at the project's runtime requirements:
# this is the same set declared in pyproject.toml that consumers will
# resolve at install time.
#
# We materialise the requirements to a real temp file rather than using
# process substitution + heredoc, because bash 3.2 (the default on
# macOS) can't parse `<(python - <<'PY' ... PY)` and was silently
# dropping this audit step on developer workstations.
REQS_TMP="$(mktemp -t spl-bridge-reqs.XXXXXX)"
trap 'rm -f "$REQS_TMP"' EXIT
python - "$REQS_TMP" <<'PY'
import sys, tomllib, pathlib
out = pathlib.Path(sys.argv[1])
data = tomllib.loads(pathlib.Path("pyproject.toml").read_text())
deps = list(data["project"].get("dependencies", []))
# Emit in pip requirements format. We don't include extras here --
# `dev`/`release`/`keyring` aren't part of the wheel's runtime install
# surface and have their own audit story.
out.write_text("\n".join(deps) + "\n")
PY

run_or_warn python -m pip_audit \
    --strict \
    --progress-spinner off \
    --vulnerability-service osv \
    --cache-dir "$PIP_AUDIT_CACHE_DIR" \
    --requirement "$REQS_TMP" \
    ${IGNORE_ARGS[@]+"${IGNORE_ARGS[@]}"} \
    || exit 1

section "release_audit.sh complete"
echo "Artefacts under $DIST_DIR:"
ls -la "$DIST_DIR"
echo
echo "SBOM: $SBOM_FILE"
exit 0
