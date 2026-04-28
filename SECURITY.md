# Security Policy

`spl-bridge` connects an LLM agent to a Splunk Enterprise / Splunk Cloud
instance over the REST API. Misconfigurations in this kind of bridge can
expose credentials, leak indexed data, or let an agent run unintended SPL.
Because of that we treat security reports with high priority.

## Supported versions

| Version | Status               |
|---------|----------------------|
| 0.1.x   | Active — patched     |
| < 0.1   | Pre-release, unsupported |

Only the latest minor release line gets security backports. Pin to a
specific version in production and watch [CHANGELOG.md](CHANGELOG.md) for
patch releases.

## Reporting a vulnerability

**Please do not open a public GitHub issue.** Use the private
channel below:

- **GitHub Security Advisories.** Go to the repo's `Security` tab →
  "Report a vulnerability". This creates a private advisory only the
  maintainers can read. The advisory form supports image and log
  attachments, comments, and a coordinated-disclosure timeline.

If GitHub Security Advisories is unavailable to you (for example, you
do not have a GitHub account), open a minimal public issue titled
"Security: please contact me privately" with **no** technical detail,
and a maintainer will reach back out via the email on your GitHub
profile or a channel of your choosing.

Do **not** email the maintainers' personal addresses with
unencrypted vulnerability detail; route everything through GitHub
Security Advisories where the audit trail is preserved.

Please include:

- Affected version (`pip show spl-bridge`)
- A minimal reproducer (env vars, tool call payload, expected vs.
  observed behaviour)
- Impact assessment in your own words (data exposure, RCE, auth bypass,
  etc.)
- Whether you've shared the issue with anyone else

## Disclosure SLA

| Stage                              | Target window |
|------------------------------------|---------------|
| Initial acknowledgement            | 3 business days |
| Triage + severity assessment       | 7 business days |
| Patched release for High/Critical  | 30 calendar days |
| Public advisory (after patch)      | 90 calendar days from acknowledgement |

We will coordinate on a CVE if the issue meets MITRE's criteria. We
credit reporters by default in the advisory unless you ask otherwise.

## Out of scope

- Misconfiguration in **your** Splunk deployment (e.g. you granted the
  service account `admin_all_objects`). The README documents the
  recommended capability set; we cannot harden a Splunk role for you.
- Vulnerabilities in upstream libraries (`mcp`, `requests`, `keyring`)
  that are tracked by their maintainers. Please file with them first; we
  will pin to a fixed version when one is available.
- Issues that require local admin or physical access to the host
  running `spl-bridge` (the threat model assumes the host is trusted).
- Behaviours documented as known limitations in `README.md`
  (e.g. password mode disabling automatic re-authentication after a
  credential rotation).

## Known security limitations

Documented in `README.md` under *"Security advisories and known
limitations"*. The short list:

- Username/password mode is **lab-only** and disables automatic
  re-authentication after the initial login. Use a token in production.
- `SPLUNK_VERIFY_SSL=false` disables certificate validation and exposes
  the agent to MITM attacks. Do not combine with passwords.
- The MCP host trusts `spl-bridge` to enforce its allowlist. If you
  expose the server over a transport other than stdio, add network-level
  authentication (the official MCP spec does not yet mandate one for
  stdio).

## Hardening checklist

If you maintain a `spl-bridge` deployment:

1. Use a Splunk **HEC/auth token** scoped to a least-privilege role.
2. Set `MCP_REQUIRE_CAPABILITIES` to the smallest set the user needs.
3. Set `MCP_RATE_LIMITS` to bound abusive prompt-driven loops.
4. Pass secrets via `SPLUNK_TOKEN_FILE` or the OS keychain (see the
   setup wizard) rather than environment variables in shell history.
5. Always run with `SPLUNK_VERIFY_SSL=true` (or a CA bundle path).
6. Monitor `_internal` for failed `/services/auth/login` attempts and
   anomalous SPL submitted by the service account.
