# spl-bridge

> An independent, open-source bridge that exposes a Splunk Enterprise or Splunk Cloud REST endpoint as a [Model Context Protocol](https://modelcontextprotocol.io) (MCP) stdio server, with built-in SPL safety guardrails.

`spl-bridge` is **not** affiliated with, endorsed by, sponsored by, or certified by Splunk LLC or Cisco Systems, Inc. See [Trademarks and independence](#trademarks-and-independence) below.

## What it is

A small Python server that:

- Speaks the Model Context Protocol over stdio (JSON-RPC framed on stdout, logs on stderr).
- Calls the publicly documented Splunk management REST API (typically TCP 8089) using either a bearer token or, in lab-only password mode, a username/password.
- Enforces a project-curated SPL command allowlist, recursive subsearch validation through Splunk's own parser, row caps, and per-tool sliding-window rate limits.
- Provides a `doctor` connectivity check and an interactive `setup` wizard that writes config snippets for popular MCP hosts (Cursor, Claude Desktop, Claude CLI).

The tool catalogue exposed to MCP clients wraps a small set of public Splunk REST endpoints (`/services/server/info`, `/services/data/indexes`, `/services/authentication/users`, `/services/server/introspection/kvstore/collectionstats`, `/servicesNS/-/-/saved/searches`, etc.) plus the SPL `| metadata` and `| savedsearch` generating commands. See [`spl_bridge/data/PROVENANCE.md`](spl_bridge/data/PROVENANCE.md) for per-tool source-of-record citations.

## Quick start

> Requires Python 3.10 or newer. Confirm with `python3 --version`; on macOS the bundled `python3` is older than this and `pyenv`, `uv`, or Homebrew Python is needed.

```bash
pip install -e .

export SPLUNK_HOST=splunk.example.com
export SPLUNK_TOKEN=your-splunk-token

spl-bridge doctor
spl-bridge serve
# or
python -m spl_bridge
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

## Cursor MCP configuration

Add to your Cursor MCP settings (`.cursor/mcp.json` or workspace config):

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

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SPLUNK_HOST` | *(required)* | Splunk hostname (e.g. `splunk.example.com` or `mystack.splunkcloud.com`) |
| `SPLUNK_PORT` | `8089` | Management REST port |
| `SPLUNK_SCHEME` | `https` | `http` or `https` |
| `SPLUNK_VERIFY_SSL` | `true` | TLS certificate verification. Accepts `true`/`false`, **or a path to a CA bundle (`.pem`)** for self-signed/internal CA setups, e.g. `SPLUNK_VERIFY_SSL=/etc/ssl/certs/my-corp-ca.pem` |
| `SPLUNK_TOKEN` | — | Splunk auth/bearer token (preferred) |
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

**Auth precedence:** If both `SPLUNK_TOKEN` and `SPLUNK_USERNAME`/`SPLUNK_PASSWORD` are set, token mode wins. For each credential variable the direct value wins over its `_FILE` companion.

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

- Secrets are **never written to disk** by this server, and are **redacted from
  structured logs** (matches against `token`, `password`, `session_key`,
  `authorization`, `api_key`, `secret`, `bearer` extras).
- Passwords are exchanged for in-memory session keys via `/services/auth/login`.
  After a successful login the password reference on the in-process config is
  cleared as a defence-in-depth measure (Python cannot guarantee zeroisation,
  see [Known limitations](#known-limitations)).
- Upstream Splunk error response bodies are **not** surfaced to MCP clients --
  clients only see a stable, generic message of the form
  `"Splunk API error (HTTP 500; request_id=abcdef123456)"`. Full diagnostic
  detail is written to the structured stderr log under that same `request_id`.
- Token mode is preferred for production; password mode is a lab convenience.
- Credentials are **never** accepted as MCP tool arguments.

> **WARNING:** Never combine `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` with
> `SPLUNK_VERIFY_SSL=false` outside a fully isolated lab. See [Quick start](#quick-start).

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
pip install -e ".[dev]"
pytest tests/ -v
```

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
