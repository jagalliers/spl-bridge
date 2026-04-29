# Contributing to spl-bridge

Thanks for taking the time to contribute! This document captures the
ground rules that keep `spl-bridge` boring, predictable, and safe for
the people piping it into their AI clients.

## Ground rules

1. **Security first.** This project speaks to Splunk on behalf of an LLM
   host. A bug here can leak credentials, run arbitrary SPL, or pollute
   the JSON-RPC stdio stream. When in doubt, choose the option that
   fails closed.
2. **Keep stdout clean.** The MCP stdio transport reserves stdout for
   length-framed JSON-RPC messages. Logging, prints, and any ad-hoc
   diagnostics must go to stderr. The startup guard
   (`_assert_no_logging_to_stdout`) will refuse to start if you forget.
3. **Never log or echo a secret.** `MCPJsonFormatter` redacts a
   denylist of field names, but you should not rely on it. Treat
   tokens, passwords, session keys, and Authorization headers as
   "must never appear in any record".
4. **Prefer parameterized API calls.** Anything that builds an SPL
   string from user input must go through `tool_registry.build_spl` or
   the saved-search args allowlist regex.
5. **No hardcoded credentials anywhere**, including tests, examples,
   or fixtures. Use environment variables, the keychain, or the 0600
   dotfile.

## Local development

Requirements:

- Python 3.10+ (we test 3.10–3.13 in CI)
- `pip install -e '.[dev,keyring]'`

Helpful commands (run from the repo root):

```bash
# Run the unit suite (fast)
pytest -q --ignore=tests/test_integration.py --ignore=tests/test_safety.py

# Lint
ruff check spl_bridge
ruff format --check spl_bridge

# Type-check
mypy spl_bridge

# Try the wizard against a lab Splunk
spl-bridge setup
```

Integration tests (`tests/test_integration.py`, `tests/test_safety.py`)
hit a real Splunk endpoint and are skipped unless you provide
credentials via environment variables. Don't enable them in CI for
PRs; we run them manually against lab instances.

### Optional, opt-in test suites

Several suites are gated behind environment variables because they
need extra infrastructure (Docker, a TTY, multiple Python toolchains,
or a real Splunk). They all skip cleanly in a normal `pytest` run.

```bash
# End-to-end MCP protocol tests against the spawned server
# (no Splunk required -- they target an unreachable host on purpose).
pytest -q tests/test_mcp_e2e.py

# Wizard PTY scenarios -- drives `spl-bridge setup` through a real
# pseudo-terminal, asserts side-effects, then restores everything.
# Requires SPLUNK_SMOKETEST_PASSWORD (and optionally _TOKEN). On
# macOS you'll see Keychain access prompts.
WIZARD_PTY_TESTS=1 pytest -q tests/test_wizard_pty_scenarios.py

# Container suite -- builds the distroless image, asserts hardening
# invariants, validates the compose example. Auto-starts Docker
# Desktop on macOS via scripts/start_docker.sh.
./scripts/start_docker.sh
DOCKER_TESTS=1 pytest -q tests/test_docker.py

# Python version matrix -- reproduces the GH Actions matrix locally
# using uv. Catches version-specific breakage before pushing.
./scripts/run_python_matrix.sh                 # all four versions
./scripts/run_python_matrix.sh 3.12 3.13       # subset
```

### Dry-running GitHub Actions locally with `act`

`act` runs our `.github/workflows/*.yml` in containers that
approximate the GitHub-hosted runners. It's the fastest way to find
"works on my machine, breaks in CI" issues without burning Actions
minutes.

```bash
# One-time install (Homebrew):
#   brew install act
# act needs a Docker engine; bring it up first if necessary:
./scripts/start_docker.sh

# Dry-run the CI workflow on push, just listing the jobs:
act push -W .github/workflows/ci.yml --list

# Run only the Linux 3.12 leg of the matrix to keep it fast:
act push -W .github/workflows/ci.yml \
    -j test \
    --matrix os:ubuntu-latest \
    --matrix python-version:3.12

# If a job needs secrets, pass them via --secret-file (don't commit
# this file -- it's already in .gitignore via the *.env pattern):
act push -W .github/workflows/ci.yml --secret-file .env.act.local
```

Notes:

- Use the `medium` runner image (`-P ubuntu-latest=catthehacker/ubuntu:act-latest`)
  if you hit a "command not found" for tools that the default image
  lacks. Stay away from the `slim` images for matrix runs -- they
  drop too many language toolchains.
- macOS jobs cannot be reproduced under `act`; that's a Docker
  limitation, not ours. Run `./scripts/run_python_matrix.sh` on your
  Mac to cover the macos-latest leg locally.

## Branching and commits

- Work on a feature branch off `main`. Keep branches short-lived.
- Commits should describe **why** the change exists. "Fix bug" is not
  enough; "Reject empty SPL placeholders so saved searches don't
  silently dispatch with no constraints" is.
- Squash on merge if your branch has noisy WIP commits.

### Commit trailers (and a note for AI coding assistants)

Two trailers are meaningful in this repo. Anything else is noise.

- **`Signed-off-by:` is required** by the DCO check (see below). Use
  `git commit -s` so the email matches your commit author exactly;
  mismatches make the DCO action fail and force a rewrite.
- **`Co-authored-by:` is only correct when there is a genuinely
  separate human co-author** of the change. Do **not** add it for
  yourself, for the AI tool you used, or as a generic "made with X"
  marker. GitHub renders every `Co-authored-by:` email as a co-author
  avatar on the commit and PR pages, which surfaces (and permanently
  archives) whichever GitHub account owns that email --- including
  alternate accounts of the same human. If you used an AI assistant,
  a `Made-with: <tool>` line in the body is fine; co-authorship is
  not.

If you are an AI coding assistant making a commit on behalf of the
user in this repo: configure the local `user.email` to match the
identity the user wants attributed (ask if unsure), use `git commit
-s`, and do **not** append a `Co-authored-by:` trailer unless the
user has explicitly named another human contributor.

## Pull requests

Every PR must:

1. Pass CI (`pytest`, `ruff`, `mypy`, build).
2. Include or update tests when you change behavior. New security
   features need both a positive case (does it allow the legitimate
   thing?) and a negative case (does it block the attack?).
3. Update `CHANGELOG.md` under "Unreleased" with a one-liner.
4. Update `README.md` if you added a user-visible flag, env var, or
   tool.
5. Note any new dependency in the PR description and explain why it's
   worth taking. We are deliberately small.

If your change touches authentication, credential storage, SPL
parsing, or the wire format, expect a deeper review and additional
test requirements.

## Code style

- We let `ruff format` settle whitespace arguments. Don't fight it.
- Type hints are required on new public functions. Use
  `from __future__ import annotations` so we stay compatible with
  Python 3.10.
- Avoid clever metaprogramming in tool registration paths; readability
  beats brevity for anything that runs inside an MCP request.
- Comments should explain **non-obvious intent**, especially around
  security trade-offs. Skip narration of what the code does.

## Reporting security issues

Do **not** file a public GitHub issue for security problems. See
[`SECURITY.md`](./SECURITY.md) for the private reporting workflow and
disclosure SLA.

## License and provenance

By contributing, you agree your contributions are licensed under the
Apache License, Version 2.0, the same as the project.

### Developer Certificate of Origin (DCO)

Every commit MUST carry a `Signed-off-by:` trailer that matches the
text of version 1.1 of the [Developer Certificate of Origin](https://developercertificate.org/).
Add it automatically with `git commit -s`. CI rejects PRs whose
commits are not signed off.

By signing off your commit you certify, in addition to the standard
DCO 1.1 text:

1. That your contribution was authored against publicly available
   Splunk documentation (REST API Reference, Search Reference,
   Splunkbase product pages, the public `splunkbase.splunk.com` and
   `docs.splunk.com` sites).
2. That you have **not** copied, paraphrased, or re-typed substantial
   expressive content (source code, configuration, JSON schemas, SPL
   templates) from the
   [`CiscoDevNet/Splunk-MCP-Server-official`](https://github.com/CiscoDevNet/Splunk-MCP-Server-official)
   repository (Cisco Sample Code License v1.1, which is not compatible
   with this project's Apache-2.0 license) or from the binary "Splunk
   MCP Server" app on Splunkbase (governed by the Splunk General
   Terms) into this contribution. Any conceptual overlap with those
   sources reflects the public Splunk REST API and SPL surface, which
   is documented at the URLs cited in
   [`spl_bridge/data/PROVENANCE.md`](spl_bridge/data/PROVENANCE.md).
3. That if your contribution adds, removes, or changes a data file
   under `spl_bridge/data/`, you have updated the per-entry
   source-of-record citations in
   [`spl_bridge/data/PROVENANCE.md`](spl_bridge/data/PROVENANCE.md)
   in the same commit.
4. That if your contribution adds a new runtime dependency, you have
   regenerated `THIRD_PARTY_NOTICES.txt` via
   `python scripts/generate_third_party_notices.py > THIRD_PARTY_NOTICES.txt`
   in the same commit.

If you cannot make any of those certifications honestly, please
contact the maintainers privately before opening the PR.

### Trademarks

`spl-bridge` is independently developed and is not
affiliated with, endorsed by, sponsored by, or certified by Splunk
LLC or Cisco Systems, Inc. When writing user-visible strings (CLI
help, log messages, README copy, error text), follow the
[Splunk Trademark Usage Guidelines](https://www.splunk.com/en_us/legal/trademark-usage-guidelines.html):

- Do not include "Splunk" as the leading element of any new module,
  CLI subcommand, package name, or product surface in this project.
- Do refer to "Splunk Enterprise", "Splunk Cloud", and "Splunkbase"
  by their full names when needed for nominative interoperability
  purposes.
- Do not use the Splunk logo, taglines, or any Cisco logo.
