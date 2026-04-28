# syntax=docker/dockerfile:1.7
#
# Multi-stage build for spl-bridge.
#
# - Stage 1 (builder): python:3.11-slim, builds a wheel via `pip wheel`.
#   The builder Python ABI MUST match the runtime Python ABI; the
#   distroless `python3-debian12` image ships Python 3.11.x, so the
#   builder is pinned to 3.11 to ensure compiled extensions
#   (pydantic_core, cryptography, cffi, ...) load at runtime.
# - Stage 2 (runtime): distroless `python3-debian12:nonroot`. No shell, no
#   package manager, no apt cache, no pip in the final image. Runs as
#   uid 65532 (`nonroot`).
#
# Build:
#   docker build -t spl-bridge:0.1.0 .
#
# Run (token mode, secret mounted as a file -- see docker-compose.example.yml):
#   docker run --rm -i \
#     -e SPLUNK_HOST=splunk.example.com \
#     -e SPLUNK_TOKEN_FILE=/run/secrets/splunk_token \
#     -v /path/to/token:/run/secrets/splunk_token:ro \
#     spl-bridge:0.1.0

# ---- Stage 1: builder ------------------------------------------------------

FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY pyproject.toml LICENSE NOTICE THIRD_PARTY_NOTICES.txt README.md ./
COPY spl_bridge ./spl_bridge
# L-8: pinned, hash-locked runtime closure; refreshed by
# scripts/refresh_docker_requirements.sh.  We install from this
# lockfile and then ``pip install --no-deps`` the wheel so pip never
# re-resolves at build time.
COPY docker/requirements-runtime.txt /tmp/requirements-runtime.txt

RUN pip install --upgrade pip build \
    && python -m build --wheel --outdir /build/dist \
    && pip install --target=/install --require-hashes \
        -r /tmp/requirements-runtime.txt \
    && pip install --target=/install --no-deps /build/dist/*.whl

# ---- Stage 2: runtime ------------------------------------------------------

FROM gcr.io/distroless/python3-debian12:nonroot

LABEL org.opencontainers.image.title="spl-bridge" \
      org.opencontainers.image.description="stdio MCP bridge for the Splunk Enterprise / Splunk Cloud REST API" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/jagalliers/spl-bridge"

# Copy installed packages from builder.
COPY --from=builder /install /app

# Apache-2.0 §4(d): ship the aggregated third-party notices alongside
# the project's own LICENSE/NOTICE inside the runtime image.
COPY --from=builder /build/LICENSE /licenses/LICENSE
COPY --from=builder /build/NOTICE /licenses/NOTICE
COPY --from=builder /build/THIRD_PARTY_NOTICES.txt /licenses/THIRD_PARTY_NOTICES.txt

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Distroless ships with `python3` as the entrypoint executable; we just
# pass the module path. No shell is available, which is by design.
USER nonroot:nonroot
WORKDIR /app
ENTRYPOINT ["python", "-m", "spl_bridge"]
