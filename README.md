# spl-bridge

> An independent, open-source bridge that exposes a Splunk Enterprise or Splunk Cloud REST endpoint as a [Model Context Protocol](https://modelcontextprotocol.io) (MCP) stdio server, with built-in SPL safety guardrails.

`spl-bridge` is **not** affiliated with, endorsed by, sponsored by, or certified by Splunk LLC or Cisco Systems, Inc. See [Trademarks and independence](#trademarks-and-independence) below.

## What it is

A small Python server that:

- Speaks the Model Context Protocol over stdio (JSON-RPC framed on stdout, logs on stderr).
- Calls the publicly documented Splunk management REST API (typically TCP 8089) using either a bearer token or, in lab-only password mode, a username/password.
- Enforces a project-curated SPL command allowlist, recursive subsearch validation through Splunk's own parser, row caps, and per-tool sliding-window rate limits.

The tool catalogue exposed to MCP clients wraps a small set of public Splunk REST endpoints (`/services/server/info`, `/services/data/indexes`, `/services/authentication/users`, `/services/server/introspection/kvstore/collectionstats`, `/servicesNS/-/-/saved/searches`, etc.) plus the SPL `| metadata` and `| savedsearch` generating commands. See [`spl_bridge/data/PROVENANCE.md`](spl_bridge/data/PROVENANCE.md) for per-tool source-of-record citations.

The CLI exposes three subcommands: `setup` (interactive wizard), `doctor` (one-shot connectivity check), and `serve` (the stdio server, also the default).

## Install

> Requires Python 3.10 or newer. Confirm with `python3 --version`; on macOS the bundled `python3` is older than this and `pyenv`, `uv`, or Homebrew Python is needed.

The minimum install is one line:

```bash
pip install spl-bridge
```

That gives you the server, the `doctor` connectivity check, and the setup wizard. By itself, secrets land in a 0600 dotfile under `~/Library/Application Support/spl-bridge/` (macOS), `%LOCALAPPDATA%\spl-bridge\` (Windows), or `~/.config/spl-bridge/` (Linux). The dotfile is protected by **filesystem permissions only** — it is not encrypted at rest.

For OS-keychain storage instead — macOS Keychain, Windows Credential Manager, Linux Secret Service / KWallet — install with the optional `keyring` add-on:

```bash
pip install 'spl-bridge[keyring]'
```

> **What's `[keyring]` and why the quotes?**
>
> - **`[keyring]`** is pip's syntax for an *optional dependency group* (declared in our `pyproject.toml`). It tells pip "install `spl-bridge` *plus* the Python `keyring` library, which is the standard cross-platform shim that talks to your OS credential store." The bracket form is purely additive — both commands install the same `spl-bridge` package and CLI; the second one just installs more.
> - **The single quotes** around `'spl-bridge[keyring]'` are only required by some shells, notably **zsh** (the macOS default), which otherwise treats `[` and `]` as filename glob characters and fails with `zsh: no matches found: spl-bridge[keyring]`. In bash, fish, and PowerShell the quotes are harmless, so the quoted form is the safe copy-paste regardless of platform.
> - **It's re-runnable.** You can add OS-keychain support to an existing install at any time by re-running `pip install 'spl-bridge[keyring]'`; pip will only install what's missing.

For development against a checkout, the same `[name]` syntax applies — `.` is the current directory, `[dev,keyring]` selects two extras at once:

```bash
pip install -e '.[dev,keyring]'
```

Where credentials actually end up at runtime — and the four-source resolution order — is documented in full at [Where credentials live](#where-credentials-live).

## Setup — pick one path

There are two ways to wire `spl-bridge` to your MCP host. The wizard is recommended for first-time setup on a developer workstation; manual configuration is fully supported and is the right choice for CI runners, Docker/Kubernetes, multi-environment deployments, or any host the wizard doesn't yet target.

The two paths are not exclusive — credentials stored by the wizard work fine when the same `spl-bridge` is launched manually, and vice-versa, because both go through the same four-source resolver described in [Where credentials live](#where-credentials-live).

### A. Recommended: the setup wizard

```bash
spl-bridge setup
```

The wizard runs five steps and persists nothing until step 4:

1. **Prereqs** — Python version, `mcp` / `requests` / `platformdirs` importable, OS keychain backend usability.
2. **Splunk** — host, port, scheme, TLS verification, auth mode (token or username+password), with hard-stops for unsafe combinations (refuses password over plain HTTP; requires explicit `I UNDERSTAND` to send a password to an unverified TLS endpoint).
3. **Probe** — live `GET /services/server/info` against the credentials you just entered, before persisting anything.
4. **Credstore** — secrets stored in your OS keychain (preferred) or a 0600 dotfile (fallback). See [Where credentials live](#where-credentials-live) for paths and at-rest protection.
5. **MCP host** — writes a launch entry into your MCP host's JSON config (Cursor, Claude Desktop, or via `claude mcp add`), with a timestamped backup of any prior config. Falls back to printing a snippet for hosts the wizard doesn't directly target.

What ends up where:

- **OS keychain or 0600 dotfile**: `SPLUNK_TOKEN` (or `SPLUNK_USERNAME` + `SPLUNK_PASSWORD`).
- **MCP host JSON config** (e.g. `~/.cursor/mcp.json`): only the launch command and the connection metadata (`SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_SCHEME`, optional `SPLUNK_VERIFY_SSL`). **No token, no password.**

The wizard refuses to run if stdin is not a TTY, and never echoes a secret to stdout/stderr.

Sample run (sanitized, abbreviated):

```text
spl-bridge setup wizard
Walks you through Splunk creds, secure storage, and MCP host wiring.

== Prerequisites ==
  ✓ Python version: running 3.13.0 (need >= 3.10)
  ✓ mcp library: importable
  ✓ requests library: importable
  ✓ platformdirs: importable
  ✓ OS keychain (keyring): backend = keyring.backends.macOS.Keyring

== Splunk connection ==
Splunk host (FQDN or IP) [localhost]: splunk.example.com
Splunk REST management port [8089]:
Connection scheme:
  1) https (recommended)
  2) http (lab only)
Choice [1]:
TLS verification:
  1) Verify with system CA bundle (default)
  2) Verify with a custom CA bundle path
  3) DISABLE verification (lab only)
Choice [1]:

== Authentication ==
  · Token mode is recommended for production.
Auth mode:
  1) Splunk auth token (recommended)
  2) Username + password (lab only)
Choice [1]:
Splunk auth token: ********

== Live connectivity test ==
  · GET https://splunk.example.com:8089/services/server/info (token auth)
  ✓ Connected to splunk-sh-01 (version 9.4.2)

== Credential storage ==
  · Backend: keyring (keyring.backends.macOS.Keyring)
  ✓ Stored SPLUNK_TOKEN

MCP server name [splunk]:
== MCP host integration ==
Where should we register spl-bridge?
  1) Cursor
  2) Claude Desktop
  3) Claude CLI
  4) Print snippet only
Choice [1]:
  ✓ Cursor -> /Users/you/.cursor/mcp.json
  · Backup of previous config at /Users/you/.cursor/mcp.json.bak.20260428T220115

== Summary ==
  ✓ Splunk: https://splunk.example.com:8089 (auth = token)
  ✓ Credential store: keyring (keyring.backends.macOS.Keyring)
  ✓ MCP host: Cursor
  · Restart your MCP host for the new server to appear.
```

To rotate a credential or change the connection, re-run `spl-bridge setup` and pick the same MCP server name. The wizard overwrites the keychain entry and updates the JSON config in place, with a fresh timestamped backup.

### B. Manual configuration

Use this path when you're scripting deployment, running in Docker / Kubernetes, integrating with an MCP host the wizard doesn't write for, or simply prefer hand-rolled config.

#### Quick start with environment variables

```bash
pip install spl-bridge

export SPLUNK_HOST=splunk.example.com
export SPLUNK_TOKEN=your-splunk-token

spl-bridge doctor   # one-shot connectivity check
spl-bridge serve    # run the MCP stdio server (or `python -m spl_bridge`)
```

> **WARNING — Lab-only password mode.** Combining `SPLUNK_USERNAME`/`SPLUNK_PASSWORD`
> with `SPLUNK_VERIFY_SSL=false` is **only safe inside a fully isolated lab network**.
> The password is sent in the body of an HTTPS POST to `/services/auth/login`; if TLS
> verification is disabled an on-path attacker can transparently MITM the connection
> and capture both the password and the returned session key. **Never** use this
> combination against shared, staging, or production Splunk instances.

```bash
# Lab-only password mode (DO NOT use outside an isolated network)
export SPLUNK_HOST=splunk.lab.local
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=changeme
export SPLUNK_VERIFY_SSL=false
```

#### Hand-rolled MCP host JSON

The most common pattern puts the token directly in the host's `env` block:

```json
{
  "mcpServers": {
    "splunk": {
      "command": "python",
      "args": ["-m", "spl_bridge"],
      "env": {
        "SPLUNK_HOST": "splunk.example.com",
        "SPLUNK_TOKEN": "your-splunk-token"
      }
    }
  }
}
```

This works, but it places the token in plaintext on disk in your home directory and the MCP host re-reads it on every restart. The wizard's keychain-backed flow (path A) avoids this.

For lab environments with self-signed certs:

```json
{
  "mcpServers": {
    "splunk": {
      "command": "python",
      "args": ["-m", "spl_bridge"],
      "env": {
        "SPLUNK_HOST": "splunk.lab.local",
        "SPLUNK_USERNAME": "admin",
        "SPLUNK_PASSWORD": "changeme",
        "SPLUNK_VERIFY_SSL": "false"
      }
    }
  }
}
```

For Docker / Kubernetes where the secret is mounted as a file:

```json
{
  "mcpServers": {
    "splunk": {
      "command": "spl-bridge",
      "env": {
        "SPLUNK_HOST": "splunk.example.com",
        "SPLUNK_TOKEN_FILE": "/run/secrets/splunk_token"
      }
    }
  }
}
```

## Where credentials live

`spl-bridge` resolves each credential (`SPLUNK_TOKEN`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`) by trying four sources in order. The first non-empty value wins; later sources are not consulted.

| Order | Source | Where | At-rest protection |
|------:|--------|-------|--------------------|
| 1 | `$SPLUNK_TOKEN` (or `_USERNAME` / `_PASSWORD`) | Process environment | None. Visible in `/proc/<pid>/environ`, in shell history if `export`ed interactively, and inherited by any child process. Appropriate for CI runners that scrub env on completion. |
| 2 | `$SPLUNK_TOKEN_FILE` (or `_USERNAME_FILE` / `_PASSWORD_FILE`) | Path read at startup | Whatever the file's filesystem ACLs are. Docker/K8s typically mount these mode 0400; `spl-bridge` reads whatever path you point at. |
| 3 | OS keychain, service `spl-bridge` | macOS Keychain / Windows Credential Manager / Linux Secret Service or KWallet | **Encrypted by the OS** under the user's login (macOS Keychain, Windows DPAPI). Linux Secret Service depends on the backend (gnome-keyring is encrypted; some KWallet configurations are not). Requires the `[keyring]` extra and an active backend. |
| 4 | 0600 dotfile | `platformdirs.user_config_dir("spl-bridge") / credentials` — typically `~/Library/Application Support/spl-bridge/credentials` (macOS), `%LOCALAPPDATA%\spl-bridge\credentials` (Windows), `~/.config/spl-bridge/credentials` (Linux/XDG) | **Filesystem ACLs only** (mode 0600 on POSIX). The file is **not encrypted**. `spl-bridge` refuses to read a dotfile whose mode isn't exactly 0600, refuses to follow symlinks (`O_NOFOLLOW`), and refuses files larger than 64 KiB. Writes are atomic via `mkstemp` + `os.replace`. |

The wizard writes to source #3 if a keychain backend is available, otherwise to source #4. It never writes to source #1 or #2; those are yours to manage.

Connection metadata (`SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_SCHEME`, `SPLUNK_VERIFY_SSL`, `SPLUNK_APP`) is **not** stored in the credstore — it lives in the MCP host's JSON config so you can flip environments without touching the keychain.

To inspect what the wizard stored:

```bash
# macOS Keychain
security find-generic-password -s spl-bridge -a SPLUNK_TOKEN -w

# Linux (Secret Service via secret-tool)
secret-tool lookup service spl-bridge username SPLUNK_TOKEN

# Windows
cmdkey /list:spl-bridge

# Dotfile fallback (any platform)
cat "$(python3 -c 'import platformdirs; print(platformdirs.user_config_dir("spl-bridge"))')/credentials"
```

To remove a credential, delete the keychain entry with the equivalent OS tool (`security delete-generic-password`, `secret-tool clear`, `cmdkey /delete`) or remove the line from the dotfile. There is no `spl-bridge unsetup` — the wizard is idempotent, so re-running it with new values overwrites in place.

## Environment variables (reference)

These can be set directly in the shell, in the MCP host's `env` block, or via `_FILE` companions. The wizard sets the connection variables for you and leaves the secrets to the credstore.

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLUNK_HOST` | *(required)* | Splunk hostname (e.g. `splunk.example.com` or `mystack.splunkcloud.com`) |
| `SPLUNK_PORT` | `8089` | Management REST port |
| `SPLUNK_SCHEME` | `https` | `http` or `https` |
| `SPLUNK_VERIFY_SSL` | `true` | TLS certificate verification. Accepts `true`/`false`, **or a path to a CA bundle (`.pem`)** for self-signed/internal CA setups, e.g. `SPLUNK_VERIFY_SSL=/etc/ssl/certs/my-corp-ca.pem` |
| `SPLUNK_TOKEN` | — | Splunk auth/bearer token (preferred). Resolved via the four-source order in [Where credentials live](#where-credentials-live). |
| `SPLUNK_USERNAME` | — | Username for password auth (lab) |
| `SPLUNK_PASSWORD` | — | Password for password auth (lab) |
| `SPLUNK_APP` | — | Default app context for searches |
| `SPLUNK_TOKEN_FILE` | — | Path to a file containing the token (Docker / K8s secret pattern) |
| `SPLUNK_USERNAME_FILE` | — | Path to a file containing the username |
| `SPLUNK_PASSWORD_FILE` | — | Path to a file containing the password |
| `MCP_TIMEOUT` | `60.0` | HTTP request timeout in seconds |
| `MCP_MAX_ROW_LIMIT` | `1000` | Maximum rows any tool can return |
| `MCP_DEFAULT_ROW_LIMIT` | `100` | Default row limit when not specified |
| `MCP_REQUIRE_CAPABILITIES` | `false` | When `true`, verify the Splunk principal has the `search` capability before serving any tool |
| `MCP_RATE_LIMITS` | — | JSON map of per-tool 60s rate limits, e.g. `{"global":600,"splunk_run_query":120}`. Per-key values are bounded to `[0, 1_000_000]`; `0` means always-deny |
| `MCP_MAX_RESPONSE_BYTES` | `67108864` (64 MiB) | Hard cap on a single Splunk REST response body. Over-cap responses are converted to a synthetic HTTP 502 and the body is dropped before reaching the tool layer. Raise only if your environment legitimately returns >64 MiB single-call payloads (very unusual; per-call streaming and `head` row limits are the right fix) |
| `SPLUNK_ALLOW_PLAINTEXT` | `0` | **Required when** `SPLUNK_SCHEME=http` and a token is configured. Set to `1` to opt-in to sending the bearer token over plain HTTP (lab only). The server always logs a `WARNING` when the scheme is HTTP, regardless of this flag |

**Auth precedence:** If both `SPLUNK_TOKEN` and `SPLUNK_USERNAME`/`SPLUNK_PASSWORD` are set, token mode wins. For each credential variable the direct value wins over its `_FILE` companion, and both env-side options win over the keychain and dotfile (see the four-source order above).

**HTTP scheme.** The server refuses to send a Splunk token over plain HTTP unless `SPLUNK_ALLOW_PLAINTEXT=1` is also set. This catches the common misconfiguration where `SPLUNK_SCHEME=http` is left in place after a copy-paste from a lab `.env`. Username/password mode over `http` was already rejected and remains so. Scheme is HTTP -> always logs a WARNING, regardless of the opt-in flag, so the misconfiguration is visible in operational logs.

## Tools

The MCP tool names below use `splunk_*` as a descriptive prefix (nominative use, indicating which upstream system the tool calls). They are MCP tool identifiers exposed to clients, not Splunk product names.

| MCP tool name | Description | Splunk REST source |
|---------------|-------------|--------------------|
| `splunk_get_info` | Splunk instance info (version, hardware, license) | `/services/server/info` |
| `splunk_get_indexes` | List indexes with size and event counts | `/services/data/indexes` |
| `splunk_get_index_info` | Detailed info for a specific index | `/services/data/indexes` |
| `splunk_get_user_list` | List Splunk users | `/services/authentication/users` |
| `splunk_get_user_info` | Current authenticated user details | `/services/authentication/current-context` |
| `splunk_run_query` | Execute an ad-hoc, allowlisted SPL query | `/services/search/jobs/export` |
| `splunk_get_metadata` | Hosts, sources, or sourcetypes metadata | SPL `| metadata` |
| `splunk_get_kv_store_collections` | KV Store collection statistics (raw bytes) | `/services/server/introspection/kvstore/collectionstats` |
| `splunk_get_knowledge_objects` | Knowledge objects by type (saved searches, macros, lookups, etc.) | `/servicesNS/-/-/...` family |
| `splunk_run_saved_search` | Execute a saved search by name | SPL `| savedsearch` |

## Security

### Credential handling

- Where credentials are stored, in what order they're resolved, and which sources are encrypted at rest is documented in full at [Where credentials live](#where-credentials-live).
- The server itself **never writes a credential to disk**; it only reads from the four sources above. Persistent storage (keychain entry, 0600 dotfile) is performed once by the setup wizard and re-read at every server start.
- Secrets are **redacted from structured logs** by `MCPJsonFormatter` (matches against `token`, `password`, `session_key`, `authorization`, `api_key`, `secret`, `bearer` extras). You should still treat tokens, passwords, and session keys as "must never appear in any record".
- Passwords are exchanged for in-memory session keys via `/services/auth/login`. After a successful login the password reference on the in-process config is cleared as a defence-in-depth measure (Python cannot guarantee zeroisation; see [Known limitations](#known-limitations)).
- Upstream Splunk error response bodies are **not** surfaced to MCP clients — clients only see a stable, generic message of the form `"Splunk API error (HTTP 500; request_id=abcdef123456)"`. Full diagnostic detail is written to the structured stderr log under that same `request_id`.
- Token mode is preferred for production; password mode is a lab convenience.
- Credentials are **never** accepted as MCP tool arguments.

> **WARNING:** Never combine `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` with
> `SPLUNK_VERIFY_SSL=false` outside a fully isolated lab. See [Setup → Manual](#b-manual-configuration).

### SPL safety

- Command allowlist sourced from this project's curated list of 143 SPL commands in [`spl_bridge/data/safe_spl.json`](spl_bridge/data/safe_spl.json). Selection criteria are documented in [`spl_bridge/data/PROVENANCE.md`](spl_bridge/data/PROVENANCE.md). `rest`, `script`, `sendemail`, `outputcsv`, `outputlookup`, `collect`, and `delete` are deliberately *not* on the list.
- Recursive subsearch validation via Splunk's parser API.
- Row limits enforced with `| head` appended to queries.
- A short list of admin-style tools (`splunk_get_info`, `splunk_get_indexes`, `splunk_get_user_list`, `splunk_run_saved_search`, etc.) bypasses the SPL allowlist because their behaviour is governed either by non-SPL REST paths or by Splunk's own authorization boundary (saved searches run under their owner's permissions).

### Splunk roles

The Splunk user/token needs at minimum:

- `search` capability (for running queries)
- `rest_properties_get` / `rest_properties_set` as needed by specific `| rest` tools
- Admin-level tools (`get_user_list`, `get_info`) require appropriate admin capabilities

### Rate limiting

- Global: 600 requests per 60-second window by default; override with `MCP_RATE_LIMITS`.
- Per-tool limits configurable via the same env var, e.g.
  `MCP_RATE_LIMITS='{"global":600,"splunk_run_query":120}'`.
- Per-tool denials do **not** consume the global budget.
- Message payload capped at 128 KB with max JSON depth of 32.
- Limits are enforced **per process**. Multi-worker deployments enforce the
  configured limits per worker, not globally across the deployment.

### Known limitations

- Subsearch bracket extraction in the SPL safety pre-check uses a bracket
  scanner; deeply nested or string-literal-quoted `]` characters inside
  subsearches may yield over- or under-matched extractions. As defence-in-depth,
  every extracted segment is independently revalidated through the Splunk
  parser API, so a malformed extraction cannot bypass the allowlist.
- Python cannot guarantee that a former password byte-string is zeroed in
  memory after dereference. The server drops its reference immediately after
  a successful login, but a memory-dump attacker with local code execution
  could still recover the value before garbage collection.

## Development

```bash
pip install -e '.[dev,keyring]'
pytest tests/ -v
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for ground rules, DCO sign-off, the optional opt-in test suites (PTY wizard scenarios, Docker, Python matrix), and notes for AI coding assistants.

## Splunk Cloud notes

- Use your stack hostname: `https://<stack>.splunkcloud.com:8089`
- Some admin REST endpoints may be restricted by `sc_admin` role limitations
- Prefer bearer tokens over password auth
- Test with `spl-bridge doctor` to verify endpoint accessibility

## Architecture

```
MCP client (Cursor, etc.)
    ↕ stdio (JSON-RPC)
spl-bridge server
    ↕ HTTPS (REST API)
Splunk Enterprise / Cloud (port 8089)
```

The server loads tool definitions from [`spl_bridge/data/builtin_tools.json`](spl_bridge/data/builtin_tools.json), validates SPL against the curated safety corpus, and executes searches via `search/jobs/export` with NDJSON response parsing.

## Trademarks and independence

`spl-bridge` is an independent open-source project. It is **not** affiliated with, endorsed by, sponsored by, or certified by **Splunk LLC** (a Cisco company) or **Cisco Systems, Inc.**

- "Splunk", "Splunk Enterprise", "Splunk Cloud", and "Splunkbase" are trademarks or registered trademarks of Splunk LLC. References to these marks in this documentation are made under nominative fair use solely to identify the upstream system this bridge interoperates with, in accordance with the [Splunk Trademark Usage Guidelines](https://www.splunk.com/en_us/legal/trademark-usage-guidelines.html).
- "Cisco" is a trademark or registered trademark of Cisco Systems, Inc. and/or its affiliates.
- "Model Context Protocol" and "MCP" identify the open protocol specification published at [modelcontextprotocol.io](https://modelcontextprotocol.io).

This project does not redistribute, fork, or port any portion of:

- the **Splunk MCP Server** app published on Splunkbase by Splunk LLC (Splunkbase app id 7931, governed by the Splunk General Terms); or
- the **Splunk-MCP-Server-official** source repository published by Cisco at [CiscoDevNet/Splunk-MCP-Server-official](https://github.com/CiscoDevNet/Splunk-MCP-Server-official) under the Cisco Sample Code License v1.1.

The MCP tool catalogue, SPL command allowlist, and any SPL templates in this project are independently authored against the public Splunk REST API Reference and the public Splunk Search Reference. See [`spl_bridge/data/PROVENANCE.md`](spl_bridge/data/PROVENANCE.md) for source-of-record citations.

Splunk LLC publishes its own MCP server for the Splunk platform at [Splunkbase app 7931](https://splunkbase.splunk.com/app/7931).

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
