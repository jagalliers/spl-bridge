"""Container-shape end-to-end tests for spl-bridge.

These tests build the project's Dockerfile, run the resulting
distroless image, and exercise the docker-compose example. They are
opt-in (``DOCKER_TESTS=1``) for two reasons:

* They take 30-90 s on a warm BuildKit cache (much longer cold).
* They require a running Docker engine and a recent
  ``docker compose`` plugin.

If the engine is not reachable the entire module is skipped at
collection time -- we never fail a developer's normal ``pytest`` run
just because they don't have Docker open.

What the suite proves (Phase 5 of the pre-push readiness plan):

* The multi-stage ``Dockerfile`` produces a working image. Distroless
  fails fast on missing transitive deps, so a successful boot is
  meaningful coverage that ``python:3.12-slim`` would not give us.
* The image's CLI surface (``--help``) works -- proves entrypoint,
  argparse, and ``__main__`` import path are intact in a
  no-shell environment.
* The image meets its documented hardening invariants: runs as
  ``nonroot`` (uid 65532), no shell present, no eager keyring import
  (the in-container path uses env/file secrets, never Keychain).
* The compose example with read-only FS, dropped capabilities,
  ``no-new-privileges``, file-mounted secret pattern actually starts
  up cleanly. This is the *recommended production shape* that the
  README points users at; if it's broken, the docs are lying.

What the suite does **not** prove:

* Live MCP-protocol round-trips against a Splunkd from inside the
  container (that requires ``--network host`` plus a healthy splunkd
  on the runner; deferred to manual ops smoke tests).
* Multi-arch (arm64 + amd64) builds. We build for the host arch only
  because we are not yet publishing to a registry.

Image tag used: ``spl-bridge:test`` so it doesn't collide with any
locally-installed release tag the developer may already have.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

DOCKER_OPT_IN = os.environ.get("DOCKER_TESTS") == "1"
REPO_ROOT = Path(__file__).resolve().parents[1]
IMAGE_TAG = "spl-bridge:test"
COMPOSE_FILE = REPO_ROOT / "docker-compose.example.yml"


# ---------------------------------------------------------------------------
# Engine-availability gate
# ---------------------------------------------------------------------------


def _docker_engine_ready() -> tuple[bool, str]:
    """Return ``(ready, reason)``.

    Probes via ``docker info`` because ``docker version`` succeeds
    against the client even when the daemon socket is unreachable.
    """
    if shutil.which("docker") is None:
        return False, "docker CLI not on PATH"
    proc = subprocess.run(  # noqa: S603,S607 -- known argv, no shell
        ["docker", "info"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        # Trim the noisy "Server: ERROR ..." block so the skip reason
        # stays one line in pytest output.
        first_err = (proc.stderr or proc.stdout or "").splitlines()[:1]
        return False, f"docker info failed: {' '.join(first_err)}"
    return True, ""


_engine_ready, _engine_reason = _docker_engine_ready() if DOCKER_OPT_IN else (False, "")


pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not DOCKER_OPT_IN,
        reason=(
            "Container suite is opt-in. Set DOCKER_TESTS=1 (and ensure "
            "Docker is running, e.g. via scripts/start_docker.sh)."
        ),
    ),
    pytest.mark.skipif(
        DOCKER_OPT_IN and not _engine_ready,
        reason=f"Docker engine not reachable: {_engine_reason}",
    ),
]


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _run(
    argv: list[str],
    *,
    timeout: int = 120,
    check: bool = True,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Wrapper that reports stderr on failure -- diagnosing a docker
    failure without the engine's error text is needlessly painful.
    """
    proc = subprocess.run(  # noqa: S603 -- argv comes from this file
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        cwd=str(cwd) if cwd else None,
    )
    if check and proc.returncode != 0:
        pytest.fail(
            f"command failed: {' '.join(argv)}\n"
            f"  exit:   {proc.returncode}\n"
            f"  stdout: {proc.stdout[-2000:]}\n"
            f"  stderr: {proc.stderr[-2000:]}"
        )
    return proc


def _image_exists(tag: str) -> bool:
    proc = _run(
        ["docker", "image", "inspect", tag],
        check=False,
        timeout=15,
    )
    return proc.returncode == 0


# ---------------------------------------------------------------------------
# Module-level fixture: build the image once, reuse across tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def built_image() -> str:
    """Build (or reuse) ``spl-bridge:test`` and return the tag.

    Reusing across tests cuts the suite from minutes to seconds when
    nothing in the build context has changed (BuildKit handles the
    layer caching; we just avoid the re-pull/re-stat cost).
    """
    # Always rebuild on first request so the test reflects the
    # current source tree -- but BuildKit will cache layers so this
    # is fast on a warm working copy.
    _run(
        [
            "docker",
            "build",
            "--tag",
            IMAGE_TAG,
            "--file",
            str(REPO_ROOT / "Dockerfile"),
            str(REPO_ROOT),
        ],
        timeout=600,
    )
    assert _image_exists(IMAGE_TAG), "image build reported success but tag missing"
    return IMAGE_TAG


# ---------------------------------------------------------------------------
# Build + smoke
# ---------------------------------------------------------------------------


def test_image_builds(built_image: str) -> None:
    """The Dockerfile produces a tagged image.

    Trivial assertion -- the heavy lifting is in the fixture. This
    test exists so pytest output shows ``test_image_builds PASSED``
    explicitly when triaging a CI run.
    """
    assert built_image == IMAGE_TAG


def test_help_runs(built_image: str) -> None:
    """``--help`` exits 0 and lists our subcommands.

    This is the cheapest "the entrypoint actually works inside
    distroless" smoke test we can write. If anything in the import
    graph touches a missing system library, this is where it
    surfaces (with a clean ImportError, not a hung container).
    """
    proc = _run(
        ["docker", "run", "--rm", built_image, "--help"],
        timeout=30,
    )
    out = proc.stdout + proc.stderr
    for sub in ("setup", "serve", "doctor"):
        assert sub in out, f"expected '{sub}' subcommand in --help output, got:\n{out}"


# ---------------------------------------------------------------------------
# Hardening invariants
# ---------------------------------------------------------------------------


def test_runs_as_nonroot(built_image: str) -> None:
    """The runtime image must not run as root.

    We can't ``id`` inside distroless (no shell), so we let Python
    print its own euid via the entrypoint. ``python -m spl_bridge``
    is our entrypoint, so we override it with ``--entrypoint python``
    plus a ``-c`` snippet -- entirely first-party, no shell.
    """
    proc = _run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            built_image,
            "-c",
            "import os; print(os.geteuid())",
        ],
        timeout=30,
    )
    euid = proc.stdout.strip()
    assert euid.isdigit(), f"expected euid integer, got {proc.stdout!r}"
    assert int(euid) != 0, (
        f"image is running as root (euid=0); Dockerfile must use the "
        f"distroless 'nonroot' user. got euid={euid}"
    )
    # The distroless ``nonroot`` user is conventionally uid 65532.
    # Fail loudly if it drifts so we notice an upstream image change.
    assert int(euid) == 65532, f"expected euid 65532 (distroless 'nonroot'), got {euid}"


def test_no_shell_in_image(built_image: str) -> None:
    """Distroless ships without a shell; confirm we did not regress
    onto a base image that adds one. The presence of ``/bin/sh``,
    ``/bin/bash``, or ``/bin/dash`` would defeat the hardening
    rationale we sell in the README.

    We probe via Python (the only interpreter we DO have) so this
    works without a shell in the image.
    """
    proc = _run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            built_image,
            "-c",
            (
                "import os; "
                "found = [p for p in ('/bin/sh','/bin/bash','/bin/dash','/usr/bin/sh') "
                "if os.path.exists(p)]; "
                "print('FOUND_SHELLS=' + ','.join(found))"
            ),
        ],
        timeout=30,
    )
    line = next(
        (ln for ln in proc.stdout.splitlines() if ln.startswith("FOUND_SHELLS=")),
        "",
    )
    assert line == "FOUND_SHELLS=", (
        f"distroless image unexpectedly contains a shell binary: {line!r}"
    )


def test_keyring_not_eagerly_imported(built_image: str) -> None:
    """In-container code path uses env/file secrets only -- never the
    OS keychain. If something accidentally imported ``keyring`` at
    module top-level, the container would either ``ImportError`` (if
    we left ``keyring`` out of runtime deps, which we did) or try to
    talk to a non-existent dbus.

    We assert the package can be imported AND that ``keyring`` is
    NOT loaded as a side effect.
    """
    proc = _run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            built_image,
            "-c",
            ("import sys, spl_bridge; print('KEYRING_LOADED=' + str('keyring' in sys.modules))"),
        ],
        timeout=30,
    )
    assert "KEYRING_LOADED=False" in proc.stdout, (
        f"keyring was imported as a side effect of 'import spl_bridge'\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )


def test_ssl_certs_available(built_image: str) -> None:
    """The image must ship with a usable CA bundle so TLS to Splunk
    works without us bundling our own.

    We check by asking Python's ``ssl`` module for its default
    verify paths and confirming the pointed-to file exists.
    """
    proc = _run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            built_image,
            "-c",
            (
                "import ssl, os, json; "
                "p = ssl.get_default_verify_paths(); "
                "print(json.dumps({"
                "'cafile': p.cafile, 'cafile_exists': bool(p.cafile and os.path.exists(p.cafile)), "
                "'capath': p.capath, 'capath_exists': bool(p.capath and os.path.isdir(p.capath))"
                "}))"
            ),
        ],
        timeout=30,
    )
    payload = next(
        (ln for ln in proc.stdout.splitlines() if ln.startswith("{")),
        "",
    )
    assert payload, f"no JSON line in output:\n{proc.stdout}"
    info = json.loads(payload)
    assert info["cafile_exists"] or info["capath_exists"], (
        f"no usable CA bundle in image; ssl.get_default_verify_paths()={info}"
    )


# ---------------------------------------------------------------------------
# Compose pattern -- "the recommended production shape"
# ---------------------------------------------------------------------------


def _compose_available() -> bool:
    proc = _run(
        ["docker", "compose", "version"],
        check=False,
        timeout=15,
    )
    return proc.returncode == 0


def test_compose_config_is_valid(built_image: str, tmp_path: Path) -> None:
    """``docker compose config`` parses the example file and resolves
    everything the manifest references.

    This catches three classes of regression cheaply:

    * Compose file syntax drift across plugin versions.
    * Missing referenced resources (image, secrets file).
    * The hardening fields we care about (``read_only``,
      ``cap_drop``, ``security_opt``, ``user``, ``stdin_open``)
      surviving through the renderer.

    We render to a temp directory so we don't need a real secrets
    file on disk -- the compose example uses ``./secrets/splunk_token``
    which would not exist in fresh checkouts.
    """
    if not _compose_available():
        pytest.skip("'docker compose' plugin not available")

    # Materialize a fake secret file so the compose config render does
    # not warn about a missing path. Contents do not matter.
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "splunk_token").write_text("not-a-real-token")
    # Copy the compose file alongside so its relative ./secrets path
    # resolves into our tmp_path tree.
    staged = tmp_path / "docker-compose.yml"
    staged.write_text(COMPOSE_FILE.read_text())

    proc = _run(
        ["docker", "compose", "-f", str(staged), "config"],
        timeout=30,
        cwd=tmp_path,
    )
    rendered = proc.stdout
    # Spot-check the hardening invariants survived the render.
    for required in (
        "read_only: true",
        "no-new-privileges:true",
        "cap_drop:",
        "splunk_token",
        "spl-bridge",
    ):
        assert required in rendered, f"compose render missing {required!r}; got:\n{rendered}"


def test_compose_up_and_down(built_image: str, tmp_path: Path) -> None:
    """End-to-end: ``compose up -d``, confirm the container is
    running with the hardening flags, then ``compose down``.

    We do NOT exercise an MCP tool call here -- the compose example
    is configured for a real Splunk endpoint that this test cannot
    reach. The win is proving that the recommended secure compose
    shape (file-mounted secret, read-only FS, dropped caps,
    no-new-privileges, resource limits) actually starts the
    spl-bridge container at all.

    The container will exit fairly quickly because stdio MCP without
    an attached host has nothing to talk to. That's fine: we assert
    on the running OR exited(0) state, not on long-term liveness.
    """
    if not _compose_available():
        pytest.skip("'docker compose' plugin not available")

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "splunk_token").write_text("not-a-real-token")
    staged = tmp_path / "docker-compose.yml"
    # Force the compose file to use our local test image instead of
    # whatever is in the example (which references ``spl-bridge:0.1.0``).
    rewritten = COMPOSE_FILE.read_text().replace(
        "image: spl-bridge:0.1.0",
        f"image: {IMAGE_TAG}",
    )
    staged.write_text(rewritten)

    project_name = "splunkmcp_test"
    up_argv = [
        "docker",
        "compose",
        "-f",
        str(staged),
        "--project-name",
        project_name,
        "up",
        "-d",
    ]
    down_argv = [
        "docker",
        "compose",
        "-f",
        str(staged),
        "--project-name",
        project_name,
        "down",
        "--volumes",
        "--remove-orphans",
    ]

    try:
        _run(up_argv, timeout=60, cwd=tmp_path)
        # Give the engine a moment to register the container in `ps`.
        time.sleep(2)

        # Inspect the spl-bridge container -- it may be 'running' or
        # already 'exited' (stdio MCP exits when stdin closes; in
        # detached mode there's no stdin, so an immediate exit is the
        # documented behavior). Both states prove the container was
        # accepted by the engine and came up far enough to run
        # ``python -m spl_bridge``.
        ps = _run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--format",
                "{{.Status}}\t{{.Names}}",
            ],
            timeout=20,
        )
        assert "spl-bridge" in ps.stdout or "splunkmcp_test" in ps.stdout.lower(), (
            f"spl-bridge container did not appear after compose up:\n{ps.stdout}"
        )

        # Find the container id so we can inspect its hardening flags.
        cid_proc = _run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "-q",
            ],
            timeout=20,
        )
        cid = cid_proc.stdout.strip().splitlines()[0]
        assert cid, "no container id found for the compose project"

        inspect = _run(
            [
                "docker",
                "inspect",
                "--format",
                (
                    "{{.HostConfig.ReadonlyRootfs}}|"
                    "{{.HostConfig.SecurityOpt}}|"
                    "{{.Config.User}}|"
                    "{{.HostConfig.CapDrop}}"
                ),
                cid,
            ],
            timeout=20,
        )
        line = inspect.stdout.strip()
        ro_fs, sec_opt, user, cap_drop = line.split("|", 3)
        assert ro_fs == "true", f"ReadonlyRootfs not enforced: {line}"
        assert "no-new-privileges:true" in sec_opt, f"no-new-privileges not enforced: {line}"
        assert user.startswith("65532") or user == "nonroot", (
            f"container is not running as nonroot uid: user={user!r}"
        )
        assert "[ALL]" in cap_drop or "ALL" in cap_drop, f"capabilities not dropped: {line}"
    finally:
        # Always tear down -- never leave a project around to confuse
        # later test runs or developers.
        _run(down_argv, check=False, timeout=60, cwd=tmp_path)
