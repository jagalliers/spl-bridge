# Changelog

All notable changes to **spl-bridge** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`spl-bridge doctor --hosts` audits MCP host configs for stale
  bare-command `spl-bridge` entries.** Inspects the user-scope Cursor
  config (`~/.cursor/mcp.json`) and the per-OS Claude Desktop config
  for any `mcpServers.*` entry whose `command` basename is `spl-bridge`
  / `spl-bridge.exe` and whose value is *not* an absolute path. Such
  entries fail to launch from PATH-stripped GUI hosts (notably Claude
  Desktop on macOS — see the absolute-path fix in this release).
  Setup wizards on or after that fix always write the resolved
  absolute path; the audit exists so users with pre-fix configs can
  self-diagnose without trawling host logs. Splunk REST is *not*
  touched in `--hosts` mode, so the audit works even when the
  endpoint is unreachable. Exits 0 if all configs are clean, 1 if any
  warnings emit. Third-party MCP entries (npx, python, etc.) are
  silently skipped — `spl-bridge` does not opine on neighbour
  hygiene. The Claude CLI (`~/.claude.json`) is intentionally not
  scanned in this release: its persistent registration schema is the
  CLI's private API and would require shelling out to `claude mcp
  list --json`.
- **Public `cursor_config_path()` and `claude_desktop_config_path()`
  helpers in `spl_bridge.setup_wizard.mcp_clients`.** The
  Claude Desktop helper was previously underscore-prefixed and only
  used by `ClaudeDesktopWriter`; both are now public so the new
  doctor scan can reuse the same canonical locations rather than
  duplicating per-platform logic. The Cursor helper is also factored
  out for symmetry. Backwards compatibility: no callers existed
  outside the setup_wizard package, and the underscore-prefixed
  Claude Desktop helper has no remaining references in-tree.

### Changed

- **Setup wizard now offers edit-and-retry on probe failure.** When
  `GET /services/server/info` fails (wrong host/port, bad credentials,
  TLS mismatch, network blip), the wizard previously offered only a
  binary "save anyway / quit" prompt — every fix required restarting
  `spl-bridge setup` from the top. The failure menu is now a
  three-way `ask_choice`: **Edit settings and try again** (re-runs
  the Splunk-connection collection with the previous attempt's
  non-secret answers pre-filled as defaults — host, port, scheme,
  TLS verification choice, CA bundle path, auth mode, username),
  **Save anyway** (existing escape hatch, unchanged), or **Quit
  without saving** (default, preserves the historical "stray Enter
  aborts" behaviour). Bounded at 3 attempts; after that the menu
  degrades to the historical two-option (save / quit) prompt and
  points the user at `spl-bridge doctor` for further iteration.
  Secrets (`SPLUNK_TOKEN`, `SPLUNK_PASSWORD`) are **never recalled**
  across attempts — they're re-prompted via `getpass.getpass` on
  every collection round, identical to a fresh wizard run, so the
  secret-lifetime story is unchanged. Hard-stops (http+password,
  declined risk gates) still propagate as `WizardAbortError` and
  terminate the wizard with exit code 2 — the user cannot retry
  past a security gate. Existing exit codes are preserved (0
  happy-path, 1 quit, 2 abort).
- **Setup wizard risk-confirmation prompts switched from "type
  `I UNDERSTAND` to confirm" to plain `y/N` (default no).** The two
  affected gates — disabling TLS verification, and sending a password
  to an unverified TLS endpoint — were ceremoniously friction-y for
  power users without adding any real safety beyond the
  default-no answer. The full warning text still prints first
  (now expanded to two lines spelling out the specific MITM /
  password-capture impact), and a stray Enter still aborts because
  the prompt defaults to no. Behaviour for token mode and for
  unattended pipes (still hard-aborted by the TTY guard) is
  unchanged. The underlying `ui.ask_literal` helper is retained
  for any future genuinely-destructive prompt that warrants the
  verbatim ceremony.

### Fixed

- **Setup wizard now writes the absolute path to `spl-bridge` into MCP
  host configs.** MCP hosts launched from launchd / Finder — notably
  **Claude Desktop on macOS** — inherit a stripped-down `PATH` (only
  `/usr/local/bin`, `/opt/homebrew/bin`, `~/.local/bin`, `~/bin`,
  `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`) and ignore the user's
  interactive shell `PATH`. Installs that land outside that allowlist
  (Homebrew Python user-sites, pipx venvs, `uv tool` venvs, project
  venvs) previously caused Claude Desktop to fail with
  `Failed to spawn process: No such file or directory` immediately
  after `initialize`. The wizard now resolves `spl-bridge` via
  `shutil.which` (with `sys.argv[0]` as a secondary fallback for hosts
  where `which` is missing) and writes the resolved absolute path into
  Cursor / Claude Desktop / Claude CLI / snippet output, so the host
  can spawn the server regardless of its launch-time `PATH`. Falls
  back to the bare command name with a logged warning if neither
  source resolves. Existing JSON configs created by older wizard runs
  can be repaired by re-running `spl-bridge setup` and selecting the
  same host + server name (the wizard is idempotent and will overwrite
  in place with a timestamped backup).

### Documentation

- **README gains a Mac-first `Quick start (macOS)` section** between
  `What it is` and `Install`. Three commands take a fresh user from
  zero to a running setup wizard: `brew install pipx`, `pipx install
  'spl-bridge[keyring] @ git+...'`, `spl-bridge setup`. `pipx` is
  recommended over plain `pip` because it sidesteps PEP 668 on
  Homebrew Python, pulls Python in as a transitive Homebrew
  dependency (so the user does not need to manage an interpreter
  separately), and lands the console script at
  `~/.local/bin/spl-bridge` — which is on the macOS launchd-stripped
  PATH that Cursor and Claude Desktop see at MCP-server spawn time.
  Combined with the absolute-path fix above, the wizard writes the
  resolved absolute path so neither the user nor the host ever has
  to think about PATH again. The existing `## Install` section is
  preserved as the long-form rationale (PEP 508 URL form, the
  `[keyring]` extra explanation, the zsh-quoting note, and the
  editable dev install). The prereq blockquote in `## Install` was
  also softened to acknowledge that `pipx` pulls Python in
  transitively rather than requiring users to install a modern
  Python first. A footnote covers the one common follow-up footgun
  (`spl-bridge: command not found` -> `pipx ensurepath` -> reopen
  terminal) which pipx itself prints during install but which can
  scroll past easily.
- **`scripts/readme_smoketest.sh` header rewritten** so its docstring
  no longer claims to walk the README's "Quick Start" verbatim.
  Since the new Quick Start uses `pipx install`, the smoketest's
  literal premise was stale. The script's body and asserts are
  unchanged — they validate the package shape (console script,
  `python -m` shim, doctor exit codes, setup TTY guard) that pipx
  and pip both consume identically — so the docstring is reframed
  to say so explicitly. A pipx-specific smoke can be added on top
  later if a regression escapes the current surface.

### Changed

- **README restructured around the setup wizard.** The Quick Start now
  presents two parallel paths under one "Setup" heading: (A) the
  recommended `spl-bridge setup` wizard with a sample transcript and an
  explicit "what gets stored where" callout, and (B) full manual
  configuration (env vars, hand-rolled `mcp.json` for Cursor / Claude
  Desktop / Claude CLI, plus the Docker / Kubernetes `_FILE` pattern).
  No facts removed; everything reorganised so the wizard leads.
- **New "Where credentials live" section** in the README documents the
  four-source resolution order (env -> `_FILE` -> OS keychain -> 0600
  dotfile), the per-OS keychain identifiers and dotfile paths, the
  at-rest protection model for each source (encrypted on macOS / Windows
  Keychain; mode-0600 only and **not** encrypted in the dotfile), and
  the dotfile's refusal-to-read rules (`O_NOFOLLOW`, mode != 0600,
  size > 64 KiB). Documents how to inspect or delete stored
  credentials with native OS tooling.
- **CLI help screens upgraded.** `spl-bridge --help` now carries a top
  description plus an epilog that names the three subcommands and links
  to the README. `spl-bridge setup --help`, `... doctor --help`, and
  `... serve --help` each gain a description and a per-subcommand
  epilog explaining what runs, what gets persisted (and what does not),
  and where state ends up. Behaviour unchanged.
- `scripts/smoketest_wizard.py` now prints only the `splunk-wizard-smoketest`
  entry it just created, not the entire `~/.cursor/mcp.json`. Avoids echoing
  pre-existing entries (which may carry bearer tokens in their `args`/`env`)
  to the operator's terminal.
- `splunk_run_saved_search`: when the upstream returns HTTP 400 with a body
  matching a known missing-token-argument pattern (e.g. `Could not find
  variable in the argument map`), the client now receives an actionable hint
  pointing at the `args` parameter instead of the opaque generic wrapper.
  Upstream body bytes still never reach clients; full detail remains in
  stderr under the same `request_id`. Other tools and other 4xx/5xx paths
  retain today's always-redact behaviour.

### Documentation

- **README header now carries three live status badges** (CI status,
  License, supported Python version) directly under the project title,
  matching the layout convention used by adjacent open-source projects
  such as OpsBlaze. The CI badge is driven by GitHub Actions
  (`ci.yml` on `main`) and reflects the latest workflow conclusion in
  real time; the License and Python badges are static and reflect
  `LICENSE` (Apache-2.0) and `pyproject.toml`'s `requires-python`
  (`>=3.10`) respectively. No content removed; tagline and rest of the
  README unchanged.
- `CONTRIBUTING.md` adds a "Commit trailers (and a note for AI coding
  assistants)" subsection clarifying that `Signed-off-by:` is the only
  required trailer and that `Co-authored-by:` should be reserved for
  genuine human co-authors. Includes explicit guidance for AI agents
  about not appending themselves as co-authors.
- **README install section rewritten for clarity.** The install now
  presents two steps -- the bare `pip install spl-bridge` minimum, and
  the optional `pip install 'spl-bridge[keyring]'` add-on for OS-keychain
  storage -- with an explicit callout explaining (a) what `[keyring]` is
  in pip-extras syntax, (b) why the single quotes are required by zsh
  (the macOS default shell) but harmless elsewhere, and (c) that the
  extra is purely additive and re-runnable. Resolves the most common
  source of confusion for first-time users on macOS who hit
  `zsh: no matches found: spl-bridge[keyring]` from copy-pasting the
  install line without quotes. The README's `## Development` install
  line was switched from double-quoted to single-quoted form to match.

### Fixed

- `spl_bridge.setup_wizard.prereqs.check_keyring_backend` now suggests
  `pip install 'spl-bridge[keyring]'` (single-quoted) in its
  "package not installed" error message, instead of the bare
  `pip install spl-bridge[keyring]` form. The bare form is unrunnable
  in zsh -- it fails with "no matches found" -- so any macOS user whose
  base install lacked the `[keyring]` extra and ran `spl-bridge setup`
  would have received a copy-paste-broken hint. Quoted form works in
  bash, zsh, fish, and PowerShell. No other behaviour change.
- **All documented `pip install spl-bridge[...]` commands replaced with
  the working PEP 508 git-URL form.** The README's two install lines
  (base and `[keyring]` extra), the Manual-configuration quick-start,
  and both wizard error suggestions
  (`spl_bridge.setup_wizard.prereqs.check_keyring_backend` and
  `spl_bridge.setup_wizard.credstore.KeyringStore.__init__`) all
  pointed at `pip install spl-bridge`, which fails for every new user
  with `Could not find a version that satisfies the requirement
  spl-bridge` because the project is not yet published to PyPI
  (`https://pypi.org/pypi/spl-bridge/json` returns HTTP 404). Six call
  sites now use the standards-compliant
  `pip install 'spl-bridge[keyring] @ git+https://github.com/jagalliers/spl-bridge.git'`
  form, which works against the latest `main` today. The `## Install`
  callout was extended with an opening bullet that explains the
  `git+https://...` form, why it is currently necessary, and the
  one-line shortening that becomes possible once the package is
  published to PyPI. The dev-clone install
  (`pip install -e '.[dev,keyring]'`) and `CONTRIBUTING.md` are
  unchanged because they install from the local checkout, not PyPI.

## [0.1.0] - YYYY-MM-DD

Initial public release: a stdio MCP bridge that connects an LLM agent
to a Splunk Enterprise / Splunk Cloud instance over the public REST
API. The runtime, the setup wizard, and the published Docker image
are all under the Apache License, Version 2.0.

### Highlights

- **Built-in MCP tool catalogue** wrapping the publicly documented
  Splunk management REST endpoints (`search/jobs/export`, saved
  searches, index discovery, datamodels, lookups, KV Store statistics,
  knowledge objects, and per-instance metadata).
- **Authentication options.** Splunk session tokens (`SPLUNK_TOKEN`),
  optional username/password for lab environments, OS keychain via
  the `[keyring]` extra (macOS Keychain, Windows Credential Manager,
  Linux Secret Service / KWallet), `*_FILE` env-var fallbacks for
  Docker / Kubernetes secret mounts, and a `0600`-permission dotfile
  fallback under `platformdirs.user_config_dir`.
- **Interactive setup wizard** (`spl-bridge setup`) with prereq
  probes, a live `/services/server/info` connectivity check, tiered
  credential storage, writers for Cursor / Claude Desktop / Claude
  CLI / stdout-only snippet output, and hard-stops for unsafe
  scheme + auth combinations (HTTP + password, HTTPS without verify
  + password).
- **Doctor command** (`spl-bridge doctor`) for non-interactive
  connectivity checks.
- **Hardened runtime defaults.** Sliding-window per-tool rate
  limiting (`MCP_RATE_LIMITS`), capability allow-listing
  (`MCP_REQUIRE_CAPABILITIES`) verified once per `SplunkClient`
  instance against `current-context`, structured JSON logging with
  request-id correlation and key-level redaction, NDJSON
  partial-failure surfacing, response-size cap
  (`MCP_MAX_RESPONSE_BYTES`), `allow_redirects=False` on the Splunk
  REST session, strict URL join that rejects absolute / scheme-bearing
  paths, and dotfile reads via `O_NOFOLLOW` with a 64 KiB size cap.
- **Distroless container image.** Multi-stage build with the runtime
  installed from a hash-locked
  [`docker/requirements-runtime.txt`](docker/requirements-runtime.txt)
  via `pip install --require-hashes`, then the project wheel via
  `pip install --no-deps`. Final image is
  `gcr.io/distroless/python3-debian12:nonroot` (no shell, no apt, no
  pip, runs as uid 65532). The runtime image carries
  [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), and
  [`THIRD_PARTY_NOTICES.txt`](THIRD_PARTY_NOTICES.txt) under
  `/licenses/` for Apache-2.0 §4(d) compliance.
- **Aggregated third-party notices.** Apache-2.0 §4(d) attribution for
  the runtime dependency closure is shipped in
  [`THIRD_PARTY_NOTICES.txt`](THIRD_PARTY_NOTICES.txt) (generated by
  [`scripts/generate_third_party_notices.py`](scripts/generate_third_party_notices.py)
  from the hash-locked Docker lockfile, byte-for-byte regenerable in
  CI).

### Provenance and licensing

- This project is independently authored expression developed against
  the publicly documented Splunk REST API and Splunk Search Reference.
  Per-data-file source-of-record citations live in
  [`spl_bridge/data/PROVENANCE.md`](spl_bridge/data/PROVENANCE.md).
- See [`NOTICE`](NOTICE) for the project copyright, the independence
  statement, the trademark attribution to Splunk LLC and Cisco
  Systems, Inc., and the carry-through note for
  [`THIRD_PARTY_NOTICES.txt`](THIRD_PARTY_NOTICES.txt).

### Governance

- DCO sign-off is required on every commit
  (`git commit -s`) and enforced by the `legal.yml` GitHub Actions
  workflow.
- Pull requests use [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
  with a legal/provenance checklist mirroring the contributor
  attestations in [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Security reports go through GitHub Security Advisories on this
  repository — see [`SECURITY.md`](SECURITY.md) for the disclosure
  workflow.

[0.1.0]: https://example.invalid/spl-bridge/releases/tag/v0.1.0
