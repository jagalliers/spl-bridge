#!/usr/bin/env bash
# Regenerate docker/requirements-runtime.txt from pyproject.toml.
#
# Run this whenever a runtime dependency in pyproject.toml's
# [project.dependencies] is bumped, added, or removed.  The output is
# the *only* lockfile we ship: it pins the runtime closure (with
# hashes) for the Docker image build.  See L-7/L-8 in
# SECURITY_AUDIT.md.
#
# We deliberately do NOT lock the project-wide install footprint --
# downstream packagers consume the wheel and resolve against their own
# constraints, so a repo-root requirements.lock would create two
# sources of truth.
#
# Usage:
#   bash scripts/refresh_docker_requirements.sh
#
# Requirements:
#   - python3 with `pip-tools` installed (we install it on the fly into
#     a throwaway venv if missing, to avoid mutating the host env).

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out="${repo_root}/docker/requirements-runtime.txt"

# Use an ephemeral venv so we don't depend on whatever happens to be on
# the operator's PATH and don't accidentally ship a system pip-tools
# pin.
tmpvenv="$(mktemp -d)/venv"
trap 'rm -rf "$(dirname "$tmpvenv")"' EXIT

python3 -m venv "$tmpvenv"
"$tmpvenv/bin/python" -m pip install --quiet --upgrade pip pip-tools

"$tmpvenv/bin/pip-compile" \
    --quiet \
    --resolver=backtracking \
    --strip-extras \
    --generate-hashes \
    --output-file="$out" \
    "${repo_root}/pyproject.toml"

echo "Wrote ${out}"
echo "Review the diff and commit alongside the dependency change."
