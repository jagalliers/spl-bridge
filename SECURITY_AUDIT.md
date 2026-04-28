# spl-bridge Security Audit

**Date:** 2026-04-14
**Scope:** Entire repository (`spl_bridge/` runtime, `setup_wizard/`, `Dockerfile`,
`docker-compose.example.yml`, `.github/workflows/`, `scripts/`, `tests/`,
`pyproject.toml`, all data files).
**Method:** Manual code review against the workspace's CodeGuard rule set
(injection, authentication, authorization, cryptography, supply chain, DoS,
logging, deserialization, IaC, MCP-specific CoSAI guidance), supplemented by
static greps for dangerous APIs and a `pip-audit` against the resolved
dependency closure.

---

## 0. Resolution status as of v0.1.0 (initial public release)

All 5 Medium and 6 of 9 Low findings are **fixed in tree** at the
initial public release. Three Lows were intentionally **deferred**
because the cure is worse than the disease (rationale recorded inline
below). Status table:

| ID | Severity | Status | Verifying tests |
|----|----------|--------|-----------------|
| M-1 | Medium | Fixed | `tests/test_no_redirect.py` |
| M-2 | Medium | Fixed | `tests/test_dotfile_safety.py::*symlink*`, `*loose_permissions*` |
| M-3 | Medium | Fixed | `tests/test_dotfile_safety.py::*newline*` |
| M-4 | Medium | Fixed | `tests/test_splunk_client.py::TestSafeJoinSSRF` |
| M-5 | Medium | Fixed | `tests/test_setup_wizard.py::*server_name*`, `*invokes_claude_mcp_add*` |
| L-1 | Low | **Deferred** (see rationale below) | n/a |
| L-2 | Low | Fixed | `tests/test_response_limit.py` |
| L-3 | Low | **Deferred** (see rationale below) | n/a |
| L-4 | Low | Fixed | `tests/test_config.py::TestPlaintextHttpGate` |
| L-5 | Low | Fixed | `tests/test_config.py::TestRateLimitBounds` |
| L-6 | Low | Fixed | `tests/test_dotfile_safety.py::*oversize*` |
| L-7 | Low | Fixed | `.github/workflows/*.yml` (SHA-pinned), `.github/dependabot.yml` |
| L-8 | Low | **Partial** (Docker-only lockfile; project-wide deferred) | manual `docker buildx build` |
| L-9 | Low | Fixed | `tests/test_server_lifecycle.py::test_opt_out_env_var` |

After-fix verification gates that ran clean:
- `ruff check .` — All checks passed
- `mypy spl_bridge` — Success: no issues found
- `pytest -q --cov=spl_bridge --cov-fail-under=80 --cov-branch` —
  383 passed, 45 skipped, **81.42 %** statement+branch coverage
- `bash scripts/check_no_secrets.sh` — clean

### Deferred findings — rationale

**L-1 (message-level log redaction).** A regex backstop on every log
emit would (a) impose a CPU tax on the hot path, (b) introduce
false-positives that mangle legitimate diagnostics — Splunk error text
genuinely contains substrings like `token=...` and `sessionKey not
found in cache` — and (c) remove the developer-discipline pressure that
the existing structured-`extra=...` `_REDACT_KEYS` design relies on.
A future PR adds a CONTRIBUTING note + a `ruff` custom check banning
`logger.*("...token=%s..."` style call sites, which catches the bug at
PR time with zero runtime cost. Tracked as a follow-up; not gating
release.

**L-3 (explicit `SPLUNK_AUTH_SCHEME` config).** Production Splunk
JWTs all start with `eyJ` and the legacy `Splunk` scheme is for opaque
session keys that don't look like JWTs. The "JWT-shaped legacy session
key" case is essentially never observed in real deployments. Adding
a knob to defend against a 0.01 % confusion case trades permanent
operator cognitive load for marginal benefit. The README's security
section now documents the heuristic so operators with truly unusual
keys can understand and report.

**L-8 (project-wide lockfile) — only the Docker compromise was taken.**
The package ships as a wheel that downstream users `pip install`. A
`requirements.lock` at the repo root creates two sources of truth (the
lockfile and `pyproject.toml`'s loose ranges) and confuses downstream
packagers. The right scope for a lockfile is the Docker image only;
that is now `docker/requirements-runtime.txt` (pip-compile-generated,
hash-locked, refreshed via `scripts/refresh_docker_requirements.sh`),
and the Dockerfile installs from it with `pip install --require-hashes`
followed by `pip install --no-deps .`. Project-level `pyproject.toml`
keeps loose ranges so library consumers aren't constrained.

---

## 1. Executive summary (original — preserved as authored 2026-04-14)

The codebase is **well above the typical bar for an early-stage MCP server**.
Threat-model boundaries are explicitly drawn (operator-trusted environment,
trusted Splunk upstream, untrusted MCP host LLM). Defensive controls
(`MAX_PAYLOAD_BYTES`, `MAX_JSON_DEPTH`, per-tool rate limits, structured JSON
logging with key-level redaction, hardened Docker image, secret-scanner
pre-commit hook, `pip-audit` + SBOM in CI) are present and consistently wired
in. No hardcoded production secrets, no `eval`/`pickle`/`yaml.load`/XML
parsing, no `shell=True` subprocesses, no known CVEs in the resolved
dependency set.

The findings below are split between **must-fix before public release** and
**defense-in-depth improvements**. The most important fixes are:

1. Disable HTTP redirects on the Splunk REST session (M-1).
2. Close the dotfile TOCTOU window (M-2).
3. Reject newline characters in dotfile values (M-3).
4. Defend `urljoin` against an absolute-URL `path` argument (M-4).
5. Insert `--` before user-controlled arguments to the `claude` CLI (M-5).

`pip-audit` against the resolved environment returned **no known
vulnerabilities** at audit time.

---

## 2. Findings by severity

### 2.1 Medium

#### M-1. HTTP redirects are followed unconditionally on Splunk REST calls

**Location:** `spl_bridge/splunk_client.py:183-200` (`_do_request`).
**Evidence:** `self._session.request(...)` is called without
`allow_redirects=False` and the codebase contains no `allow_redirects` or
`max_redirects` setting (`rg "allow_redirects|max_redirects"` returned no
matches).
**Risk:** A compromised or misconfigured Splunk endpoint can redirect the MCP
client to an attacker-controlled host. While `requests` strips the
`Authorization` header on cross-host redirects by default (since 2.32), the
behaviour is library-version-dependent and silently changes between releases.
For a security tool that holds a Splunk session key, the safest posture is to
**never follow redirects**: legitimate Splunk management API calls don't use
3xx redirects to other origins.
**Severity:** Medium (auth-bearer client should not implicitly trust upstream
redirects).
**Remediation:** Pass `allow_redirects=False` to
`self._session.request(...)` in `_do_request`, and treat any 3xx response as
an error returned to the caller. Add a regression test that mocks a 302 and
asserts the client raises rather than following it.

#### M-2. TOCTOU between permission check and read of secret dotfile

**Location:**
- `spl_bridge/setup_wizard/credstore.py:_check_perms` and `DotfileStore._read_all`.
- `spl_bridge/config.py:_try_user_dotfile`.

**Evidence:** Both call sites do `path.stat()` to check the mode before
calling `path.read_text()`. An attacker with write access to the parent
directory (e.g. shared user account, world-writable config dir created by a
buggy installer) can swap the path for a symlink between the `stat` and the
`read_text`, causing `spl-bridge` to read an arbitrary file (logging its
parse failure may leak the first few KB of that file).
**Risk:** Local privilege escalation / arbitrary file read. Mitigated in
practice by the requirement that the dotfile already be 0600 owned by the
caller (the chmod is enforced by `_atomic_write`), but the check is
non-atomic so the guarantee is best-effort.
**Severity:** Medium (only exploitable in a multi-user environment with
write-access to the parent directory, which already implies a partially
compromised account).
**Remediation:** Open the file with `os.open(path, os.O_RDONLY |
os.O_NOFOLLOW)` and call `os.fstat()` on the returned descriptor, then read
through `os.fdopen()`. This makes the permission check and the read share a
single inode reference and rejects symlinks outright.

#### M-3. Newline characters not rejected when writing the dotfile

**Location:** `spl_bridge/setup_wizard/credstore.py:DotfileStore.set_secret`
(line interpolation `f"{key}={value}"`).
**Evidence:** Values come from `ui.ask_secret`, which does not validate
content. A token containing `\n` (e.g. pasted with stray whitespace from a
clipboard manager or supplied via `paste-from-stdin` flow) will inject a new
line into the credential dotfile. On the next read, the injected line will
be parsed as `KEY=VALUE`, potentially overriding `SPLUNK_HOST`,
`SPLUNK_VERIFY_SSL`, etc.
**Risk:** Misconfiguration / privilege manipulation via clipboard contents
the user did not realize contained a newline. Not a remote attack but a
real-world configuration footgun.
**Severity:** Medium (data-integrity / silent misconfiguration).
**Remediation:** In `DotfileStore.set_secret` (and on read in
`_parse_dotfile_lines`) reject any value containing `\n`, `\r`, or `\x00`
with a clear error message. Likewise normalise on the wizard side in
`ui.ask_secret` for `splunk_token`/`password` keys.

#### M-4. `urljoin` accepts absolute URLs in `path`

**Location:** `spl_bridge/splunk_client.py:239`
(`urljoin(f"{self._base_url}/", path.lstrip("/"))`).
**Evidence:** All current internal callers either pass hardcoded paths or
URL-encode user input via `quote(name, safe="")`, so this is **not** a live
SSRF today. However, the construct is fragile: a future caller that forgets
to encode (or a regex regression in `_SAFE_APP_RE`) immediately upgrades to
SSRF because `urljoin("https://splunk:8089/", "https://evil/x")` returns
`https://evil/x`.
**Risk:** SSRF to arbitrary hosts, leaking the bearer token (or session
cookie in password mode) to whoever wins the redirect. Combined with M-1
this becomes a realistic exploit path for a malicious tool definition.
**Severity:** Medium (latent SSRF; not exploitable in current call graph).
**Remediation:** Replace `urljoin` with a strict join that asserts
`not urlparse(path).scheme and not urlparse(path).netloc`, and reject any
path containing `://` or starting with `//`. Add a unit test that proves a
caller passing `https://evil/foo` raises rather than reaching out.

#### M-5. Possible argument injection into the `claude` CLI

**Location:**
`spl_bridge/setup_wizard/mcp_clients.py:ClaudeCLIWriter.write` (around
line 261).
**Evidence:** The wizard builds
`["claude", "mcp", "add", "--scope", "user", server_name, ...]` where
`server_name` is taken from interactive user input. There is no `--`
terminator before `server_name`. A user typing `--scope=global` or
`--config=/etc/passwd` would be re-interpreted by the `claude` CLI's option
parser. Since `subprocess.run(..., shell=False)` is used this **cannot** be
escalated into shell command execution against `spl-bridge`, but it can
manipulate the registration scope or trigger CLI-side side effects the user
did not consent to.
**Risk:** Configuration manipulation in the host CLI; minor privilege
escalation surface inside Claude's own config namespace.
**Severity:** Medium (local, requires the user themselves to type the
malicious server name; still worth fixing).
**Remediation:** Insert `"--"` immediately before `server_name` in the
argument list, and validate `server_name` against `^[A-Za-z0-9_.-]{1,64}$`
before invocation. Both defenses are cheap.

### 2.2 Low

#### L-1. Module-level redaction only catches structured-context fields

**Location:** `spl_bridge/logging_config.py:_REDACT_KEYS`.
**Evidence:** Redaction is keyed off `extra=...` field names. A developer
who logs `logger.info("token=%s", real_token)` bypasses the filter. Today
no production code does this (verified by grep), but the invariant relies
on developer discipline.
**Severity:** Low.
**Remediation:** Add a message-level pattern filter (`(?i)(token|password|
session[_-]?key|authorization)\s*[:=]\s*\S+`) that replaces matches with
`***` before formatting. Pair with a unit test that logs a known-secret
literal and asserts the emitted line is sanitized.

#### L-2. No size limit on Splunk JSON / export-search response bodies

**Location:** `spl_bridge/splunk_client.py` (every `response.json()` and
`export_search` text consumer).
**Evidence:** The Splunk upstream is in the trust boundary, but a
misconfigured / compromised Splunk instance returning a 10 GB JSON document
will cause OOM in the MCP server process.
**Severity:** Low (requires upstream compromise; still cheap to mitigate).
**Remediation:** Set `stream=True` on the `requests` call, then read at
most `MCP_MAX_RESPONSE_BYTES` (e.g. 64 MiB, configurable) from
`response.iter_content` before raising. For `export_search` enforce the
same limit on the streamed body.

#### L-3. Unbounded JWT-prefix heuristic in `_token_authorization_value`

**Location:** `spl_bridge/auth.py:_token_authorization_value`.
**Evidence:** The function uses `token.startswith("eyJ")` to decide
between `Authorization: Bearer ...` (JWT-shaped) and
`Authorization: Splunk ...` (legacy). This is a heuristic — a legacy
session key that happens to begin with `eyJ` would be sent with the wrong
scheme, producing a confusing 401.
**Severity:** Low (operational confusion; not a security boundary).
**Remediation:** Make the auth scheme an explicit config setting
(`SPLUNK_AUTH_SCHEME=bearer|splunk|auto`) and only fall back to the
heuristic when `auto` is selected.

#### L-4. `SPLUNK_SCHEME=http` accepted without warning

**Location:** `spl_bridge/config.py:SplunkMCPConfig.from_env`.
**Evidence:** The wizard refuses to use HTTP for password auth, but the
direct `from_env` path silently allows `SPLUNK_SCHEME=http` with a token —
sending the bearer in cleartext over the wire.
**Severity:** Low (operator deliberately set an insecure scheme).
**Remediation:** Emit a `WARNING`-level log at startup whenever `scheme ==
"http"`, and require `SPLUNK_ALLOW_PLAINTEXT=1` to enable token use over
HTTP. Document this in the README's security section.

#### L-5. No bounds on `MCP_RATE_LIMITS` integer values

**Location:** `spl_bridge/config.py:_parse_rate_limits`.
**Evidence:** `MCP_RATE_LIMITS='{"global": 9999999999999}'` is accepted.
The deque-based limiter would happily allocate that many entries on
prolonged hot loops.
**Severity:** Low (operator-controlled).
**Remediation:** Cap each integer at, say, 1e6 and reject negative values
with a clear error.

#### L-6. Dotfile read has no size cap

**Location:**
`spl_bridge/setup_wizard/credstore.py:DotfileStore._read_all` and
`spl_bridge/config.py:_try_user_dotfile`.
**Evidence:** A 1 GB attacker-controlled file mounted at the dotfile path
would be slurped into memory.
**Severity:** Low (requires write access to a 0600 file the operator
controls).
**Remediation:** Read at most 64 KiB and refuse larger files.

#### L-7. Third-party GitHub Actions are pinned by tag, not SHA

**Location:** `.github/workflows/{ci,lint,build}.yml`.
**Evidence:** Uses `actions/checkout@v4`, `actions/setup-python@v5`, etc.
Tag pinning means the action's owner can publish a malicious release that
re-points the tag. The CodeGuard supply-chain rule recommends digest
pinning.
**Severity:** Low (GitHub's own actions are reputable; risk is real but
small for this repo's blast radius).
**Remediation:** Pin to commit SHAs (e.g. `actions/checkout@a5...`) and
add a Dependabot config or `pinact`/`stepsecurity` workflow to keep the
SHAs current.

#### L-8. `pyproject.toml` declares loose dependency ranges

**Location:** `pyproject.toml:dependencies`.
**Evidence:** `mcp>=1.0`, `requests>=2.32`, `platformdirs>=4.0`. There is
no top-level lockfile; reproducible builds depend on the build host's
resolver state.
**Severity:** Low (acceptable for a library; would matter more if we
shipped a frozen wheel + container together).
**Remediation:** Generate and commit a `requirements.lock` (or
`uv.lock`) for the runtime extras and use it in the Dockerfile to ensure
container builds are deterministic byte-for-byte.

#### L-9. `test_server_lifecycle.py` mutates `os.environ` without cleanup

**Location:** `tests/test_server_lifecycle.py:test_opt_out_env_var`.
**Evidence:** Sets `SPLUNK_MCP_ALLOW_STDOUT_LOGGING=1` but never deletes
it; later tests in the same process will see it.
**Severity:** Low (test hygiene; could mask a regression that requires
the negative case).
**Remediation:** Wrap with `monkeypatch.setenv(...)` (pytest already
provides this fixture).

### 2.3 Informational

- **I-1.** `setup_wizard/__init__.py` correctly hard-stops password auth over
  HTTP and over `verify_ssl=False`. Excellent posture, do not regress.
- **I-2.** `safe_spl.json` excludes `rest`, `script`, `sendemail`,
  `outputcsv`, `outputlookup`, `collect`, `delete` from the SPL allowlist
  and is exercised by `tests/test_spl_safety_corpus.py`. The exclusion list
  is the correct backbone of the data-exfil/DoS defense.
- **I-3.** All JSON parsing uses `json.loads` (no `pickle`, no `yaml.load`,
  no XML parsing anywhere in the runtime). XXE / unsafe-deserialization is
  out of scope for this codebase.
- **I-4.** `subprocess.run` is used in exactly one location
  (`mcp_clients.py`) with `shell=False` and validated literal arguments
  (modulo M-5 above).
- **I-5.** `MCPJsonFormatter` JSON-encodes log records, so newlines /
  control characters in user-supplied strings cannot break log structure
  (defeats log injection).
- **I-6.** `_check_json_depth` is iterative (stack-based), not recursive,
  so a deeply nested attacker payload cannot blow the Python stack.
- **I-7.** `RateLimitManager.check` is invoked **before** argument
  validation (`server.py:_execute_tool_inner`). This means even malformed
  requests consume budget — the correct order for anti-DoS.
- **I-8.** Docker image runs as `nonroot` (uid 65532) on
  `gcr.io/distroless/python3-debian12:nonroot`; the example compose file
  drops all capabilities, sets `read_only`, `no-new-privileges`, resource
  limits, and demonstrates secrets-via-file pattern. This matches CodeGuard
  IaC and DevOps recommendations.
- **I-9.** `scripts/check_no_secrets.sh` is wired into pre-commit hooks
  **and** into the `lint.yml` workflow, so it cannot be bypassed by simply
  skipping pre-commit. A current run on the audit workspace returns clean.
- **I-10.** `pip-audit -r <pip freeze>` against the resolved dependency
  closure (35+ packages including `mcp`, `requests`, `cryptography`,
  `keyring`) reported **no known vulnerabilities** at the time of this
  audit.
- **I-11.** Server-level error sanitization is consistent: every
  exception path in `_execute_tool` ends in `raise ToolExecutionError(...)
  from None` with a curated message and a `request_id` for log
  correlation, eliminating Python traceback / upstream-body leaks to the
  MCP host.

---

## 3. Threat-model summary

| Boundary | Trust posture | Mitigation |
|---|---|---|
| MCP host (LLM) → spl-bridge | **Untrusted** | Schema validation, rate limits, payload caps, JSON depth caps, SPL allowlist, generic error strings, request_id correlation. |
| spl-bridge → Splunk REST | **Trusted upstream** | TLS by default, `Authorization: Bearer`/`Splunk`, capability check, one retry on 401/403 in password mode, no retry in token mode. |
| Operator shell → spl-bridge | **Trusted (operator)** | env vars, `_FILE` indirection, OS keyring, 0600 dotfile. |
| Local filesystem (multi-user host) | **Partially trusted** | Findings M-2/M-3/L-6 above. |
| CI / supply chain | **Mostly trusted** | `check_no_secrets.sh`, `pip-audit`, SBOM, twine check, distroless runtime. Findings L-7/L-8 above. |

---

## 4. Test plan for the recommended fixes

For each of M-1 through M-5 and the L-1/L-2 hardening:

- **M-1**: Unit test `requests-mock` returning 302; assert `_do_request`
  raises and does not emit a second outbound request.
- **M-2**: Unit test that creates a regular file, then replaces it with a
  symlink pointing to `/etc/passwd`, and asserts `_check_perms` /
  `_try_user_dotfile` refuse to read.
- **M-3**: Unit test passing `"abc\nSPLUNK_HOST=evil"` to
  `DotfileStore.set_secret`; assert the function raises.
- **M-4**: Unit test `SplunkClient.call_api(method="GET",
  path="https://evil/foo")` and assert it raises rather than reaching out.
- **M-5**: Unit test `ClaudeCLIWriter.write` with `server_name="--scope
  global"` and assert the resulting argv contains `"--"` separator before
  the server name.
- **L-1**: Unit test that logs a literal token via `%s` formatting and
  asserts the emitted JSON contains `***` instead.
- **L-2**: Unit test with `requests-mock` returning a 100 MiB body; assert
  the client truncates / raises.

All fixes are local (single-file or two-file edits) with no runtime
behaviour change for legitimate callers.

---

## 5. Audit metadata

- Files reviewed: 100% of `spl_bridge/**/*.py`, all data files, all top-level
  config, all CI workflows, all release scripts, all tests.
- Static checks run: `ruff check`, `ruff format --check`, `mypy`,
  `bash scripts/check_no_secrets.sh`, regex grep for dangerous APIs
  (`eval|exec|os.system|subprocess|pickle|yaml.load|fromstring|allow_redirects|verify=False`).
- Network audit: `pip-audit -r <pip freeze --exclude-editable>` against
  PyPI vulnerability service (clean).
- Out of scope: live penetration test against a running container
  (recommend doing this once M-1..M-5 are fixed); cryptographic key
  rotation procedures (not relevant — this server holds no long-lived keys
  of its own beyond the operator-supplied Splunk token).
