# Changelog

All notable changes to **spl-bridge** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
