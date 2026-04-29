"""Thin HTTP client for the publicly documented Splunk REST API (management port, typically 8089)."""

from __future__ import annotations

import contextlib
import http
import json
import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import requests
import urllib3
from requests import Response

from spl_bridge.auth import (
    SplunkLoginError,
    get_auth_header,
    invalidate_session,
)
from spl_bridge.config import SplunkMCPConfig
from spl_bridge.logging_config import current_request_id

logger = logging.getLogger(__name__)

_SAFE_APP_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
_ERROR_MESSAGE_TYPES = frozenset({"ERROR", "FATAL", "WARN"})


class ResponseTooLargeError(Exception):
    """Raised when a Splunk REST response exceeds the configured byte cap.

    Distinct from ``ValueError`` so the server-level classifier can
    return a curated message and the operator knows to either raise
    ``MCP_MAX_RESPONSE_BYTES`` or narrow the SPL.
    """


def _read_bounded(response: Response, limit: int) -> bytes:
    """Materialize ``response`` body into bytes, refusing oversize payloads.

    Used in conjunction with ``stream=True`` so we can fail fast before
    pulling a multi-GB payload into memory. Reuses the response's own
    iterator so chunked encoding works correctly.

    The cap protects against:

    * a misconfigured Splunk instance that returns a huge JSON document
      from ``services/search/jobs/<sid>/results`` when the operator
      forgot a count limit;
    * a compromised upstream that tries to OOM the MCP server.
    """
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > limit:
                raise ResponseTooLargeError(
                    f"Splunk response exceeded configured limit of {limit} bytes"
                )
            chunks.append(chunk)
    finally:
        # Always release the underlying socket back to the pool.
        with contextlib.suppress(Exception):
            response.close()
    return b"".join(chunks)


def _safe_join(base: str, path: str) -> str:
    """Join ``base`` and ``path`` only if ``path`` is unambiguously relative.

    Defends against an SSRF where a caller (or a future regression in
    a sanitizer regex) supplies an absolute URL or a protocol-relative
    URL via ``path``. ``urllib.parse.urljoin`` is intentionally
    permissive for these inputs -- e.g.
    ``urljoin("https://splunk:8089/", "https://evil/x")`` returns
    ``"https://evil/x"`` -- so we reject them up front.
    """
    if not isinstance(path, str):
        raise ValueError("path must be a string")
    if path.startswith("//"):
        raise ValueError("path must be relative; protocol-relative URLs are rejected")
    parsed = urlparse(path)
    if parsed.scheme or parsed.netloc:
        raise ValueError("path must be relative; absolute URLs are rejected")
    return urljoin(base + "/", path.lstrip("/"))


def _client_safe_error(prefix: str, status: int | None = None) -> str:
    """Build a stable, sanitized error message for MCP clients.

    Never includes upstream response bodies, exception strings, or paths.
    Includes the request id so server-side logs can be correlated.
    """
    rid = current_request_id()
    if status is not None:
        return f"{prefix} (HTTP {status}; request_id={rid})"
    return f"{prefix} (request_id={rid})"


# Minimal allow-list mapping from upstream substring markers to
# project-curated hint strings for HTTP 400 responses to
# ``services/search/jobs/export`` when the originating tool was
# ``splunk_run_saved_search``. We never echo upstream bytes back to
# the client; we only assert that the caller has hit a known failure
# mode and return a fixed, project-owned remediation hint. Order
# matters: the first matching marker wins. Markers are matched
# case-sensitively against the *raw* upstream body before any
# sanitisation.
#
# Growing this list is an explicit code change plus a test (see
# tests/test_savedsearch_classifier.py); resist the temptation to
# regex-extract structured fields from the upstream body, since that
# would break the README invariant that upstream bodies are not
# surfaced to clients.
_SAVEDSEARCH_400_HINTS: tuple[tuple[str, str], ...] = (
    (
        "argument map",
        "Saved search requires arguments that were not provided. "
        "Pass them via the `args` parameter as space-separated "
        'key="value" pairs, for example args=\'hosts="web*"\'.',
    ),
    (
        "Could not find variable",
        "Saved search references a token variable that was not "
        "supplied. Pass the missing token via the `args` parameter "
        'as space-separated key="value" pairs.',
    ),
)


def _classify_savedsearch_400(upstream_body: str) -> str | None:
    """Map a known 400 upstream body to a project-curated hint, or ``None``."""
    if not upstream_body:
        return None
    for marker, hint in _SAVEDSEARCH_400_HINTS:
        if marker in upstream_body:
            return hint
    return None


def _sanitize_for_log(body: str, max_len: int = 500) -> str:
    """Shorten and lightly redact REST error bodies before logging."""
    if not body:
        return ""
    text = body.replace("\r\n", "\n").strip()
    if len(text) > max_len:
        text = text[:max_len] + "…(truncated)"
    # Splunk occasionally echoes auth-related fragments in HTML error pages
    text = re.sub(
        r"(?i)(session[_-]?key|authorization|password|passwd|token)\s*[:=]\s*\S+",
        r"\1=(redacted)",
        text,
    )
    return text


def _synthetic_response(status: int, detail: str) -> Response:
    response = Response()
    response.status_code = status
    response._content = json.dumps({"detail": detail}).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    return response


@dataclass
class NdjsonParseResult:
    results: list
    errors: list


def convert_ndjson_to_dict(ndjson_text: str) -> NdjsonParseResult:
    """Parse Splunk search/jobs/export NDJSON into results and message errors."""
    valid_results: list[Any] = []
    errors: list[str] = []

    for raw_line in ndjson_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            json_obj = json.loads(line)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse NDJSON line: %s", e)
            continue

        if not isinstance(json_obj, dict):
            continue

        for msg in json_obj.get("messages", []) or []:
            if isinstance(msg, dict) and msg.get("type") in _ERROR_MESSAGE_TYPES:
                text = msg.get("text")
                if text:
                    errors.append(str(text))

        result_data = json_obj.get("result", {})
        if isinstance(result_data, dict):
            for md_field in ("preview", "offset", "lastrow"):
                result_data.pop(md_field, None)

        if result_data:
            valid_results.append(result_data)

    if errors:
        logger.error("NDJSON stream contained %d error message(s)", len(errors))

    return NdjsonParseResult(results=valid_results, errors=errors)


def normalize_search_command(
    spl: str, max_row_limit: int, generating_commands: Iterable[str]
) -> str:
    """Normalize SPL and cap rows with ``| head {max_row_limit + 1}``."""
    spl = spl.strip()
    if not spl:
        logger.warning("Empty SPL query provided")
        return ""

    gen_set = {c.lower() for c in generating_commands}
    head_suffix = f" | head {max_row_limit + 1}"

    if spl.lower().startswith("search ") or spl.startswith("|"):
        return f"{spl}{head_suffix}"

    tokens = spl.split(maxsplit=1)
    if not tokens:
        return ""

    first_word = tokens[0].lower()
    if first_word in gen_set:
        return f"{spl}{head_suffix}"

    return f"search {spl}{head_suffix}"


class SplunkClient:
    """HTTP client for Splunk management REST (port 8089 by default)."""

    def __init__(self, config: SplunkMCPConfig) -> None:
        import threading

        self.config = config
        self._base_url = f"{config.scheme}://{config.host}:{config.port}"
        self._capabilities_checked = False
        self._capabilities: set[str] = set()
        self._token_invalid_logged = False
        # Tracks whether the per-process capability gate has been satisfied.
        self._capability_verified = False
        self._cap_lock = threading.Lock()
        if config.ssl_verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # No persistent ``requests.Session()``: we mirror Splunk's own
        # reference MCP server (`Splunk_MCP_Server/bin/splunk_api.py`),
        # which issues each REST call with its own connection.  The
        # earlier R12 design pooled connections via a shared Session,
        # but that exposed an intermittent ``urllib3`` keep-alive race
        # where Splunk Cloud / load-balanced endpoints with short idle
        # timeouts would close a pooled socket the moment we tried to
        # reuse it -- surfacing as ``http.client.RemoteDisconnected``
        # / ``requests.exceptions.ConnectionError("Connection
        # aborted")``.  Per-call ``requests.request(...)`` trades a
        # ~50ms TLS handshake per call (negligible at human MCP
        # cadence) for guaranteed freedom from that race.

    def close(self) -> None:
        """No-op kept for API back-compat. We no longer pool a Session."""
        return None

    def ensure_capabilities_verified(self, required: set[str] | None = None) -> tuple[bool, str]:
        """Run :py:meth:`check_capabilities` once per process under a lock.

        Returns ``(True, "")`` once verified.
        """
        with self._cap_lock:
            if self._capability_verified:
                return True, ""
            ok, msg = self.check_capabilities(required)
            if ok:
                self._capability_verified = True
            return ok, msg

    def _do_request(
        self,
        method: str,
        url: str,
        req_headers: dict[str, str],
        params: Mapping[str, Any] | None,
        data: dict[str, Any] | str | bytes | None,
    ) -> Response:
        try:
            # Per-call ``requests.request(...)`` (no shared Session):
            # mirrors ``Splunk_MCP_Server/bin/splunk_api.py`` and
            # avoids the urllib3 pool keep-alive race that surfaced as
            # ``RemoteDisconnected`` on Splunk Cloud / load-balanced
            # endpoints.  See ``__init__`` for the full rationale and
            # the trade-off (~50ms TLS handshake per call).
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                params=dict(params) if params is not None else None,
                data=data,
                verify=self.config.ssl_verify,
                timeout=self.config.timeout,
                allow_redirects=False,
                stream=True,
            )
        except (requests.Timeout, requests.ConnectionError):
            # Re-raise so the server-level classifier in
            # ``server._execute_tool`` can produce the curated,
            # operationally-useful messages ("Splunk request timed
            # out after Ns" / "Could not connect to Splunk at host:port").
            # Without this, callers that go through ``call_api`` would
            # only ever see a synthetic HTTP 500/504 with the generic
            # "Splunk API error" string -- which is the exact failure
            # mode the Phase 2 classifier exists to fix.
            logger.exception("Splunk REST transport error (will propagate)")
            raise
        except requests.RequestException as e:
            # Catch-all for less common transport faults (chunked
            # encoding, decoding, malformed responses). Returning a
            # synthetic 500 keeps the response-shape contract for
            # callers that only inspect ``response.status_code``; the
            # server's ``RequestException`` classifier handles the
            # propagating cases above.
            logger.error("Splunk REST request failed: %s", e)
            return _synthetic_response(
                int(http.HTTPStatus.INTERNAL_SERVER_ERROR),
                _client_safe_error("Splunk API request failed"),
            )

        # L-2: Materialize the body up to ``max_response_bytes`` and
        # back-fill ``response._content`` so that ``.text`` / ``.json()``
        # / ``.content`` continue to work synchronously for downstream
        # callers without each having to be aware of streaming.
        try:
            body = _read_bounded(response, self.config.max_response_bytes)
        except ResponseTooLargeError as exc:
            logger.error(
                "Splunk response over %d byte cap (HTTP %s, url=%s)",
                self.config.max_response_bytes,
                response.status_code,
                # Keep the host:port + path; never log query params.
                response.url.split("?", 1)[0],
            )
            return _synthetic_response(
                int(http.HTTPStatus.BAD_GATEWAY),
                _client_safe_error(str(exc)),
            )
        except requests.RequestException as e:
            logger.error("Splunk REST body read failed: %s", e)
            return _synthetic_response(
                int(http.HTTPStatus.INTERNAL_SERVER_ERROR),
                _client_safe_error("Splunk API body read failed"),
            )

        response._content = body
        return response

    def call_api(
        self,
        method: str,
        path: str,
        params: Mapping[str, Any] | None = None,
        data: dict[str, Any] | str | bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        """Perform an authenticated request against ``{base_url}/{path}``.

        On 401/403 in **password** auth mode, invalidates the cached session
        key and retries exactly once. In token mode, never retries: a single
        per-process warning is logged and the original 401/403 is returned.
        """
        url = _safe_join(self._base_url, path)

        def _build_headers() -> dict[str, str]:
            req_headers: dict[str, str] = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Authorization": get_auth_header(self.config),
            }
            if headers:
                req_headers.update(dict(headers))
            return req_headers

        logger.info("%s %s", method.upper(), url)

        response = self._do_request(method, url, _build_headers(), params, data)

        if response.status_code in (401, 403):
            if self.config.auth_mode == "password":
                logger.warning(
                    "Splunk returned HTTP %s; invalidating cached "
                    "session key and re-authenticating once",
                    response.status_code,
                )
                invalidate_session()
                try:
                    response = self._do_request(method, url, _build_headers(), params, data)
                except SplunkLoginError as exc:
                    logger.error("Re-auth failed: %s", exc)
                    return _synthetic_response(
                        int(http.HTTPStatus.UNAUTHORIZED),
                        _client_safe_error("Re-authentication failed", 401),
                    )
            elif self.config.auth_mode == "token":
                if not self._token_invalid_logged:
                    logger.error(
                        "Splunk rejected token (HTTP %s); token may be "
                        "invalid or expired. Will not retry.",
                        response.status_code,
                    )
                    self._token_invalid_logged = True

        return response

    def check_capabilities(self, required: set[str] | None = None) -> tuple[bool, str]:
        """Verify the authenticated user has the required Splunk capabilities.

        Results are cached for the lifetime of this client instance.
        Returns ``(True, "")`` on success or ``(False, message)`` on failure.
        """
        if required is None:
            required = {"mcp_tool_execute"}

        if self._capabilities_checked:
            missing = required - self._capabilities
            if missing:
                return False, f"User lacks required capabilities: {', '.join(sorted(missing))}"
            return True, ""

        response = self.call_api(
            "GET",
            "services/authentication/current-context",
            params={"output_mode": "json"},
        )

        if response.status_code != 200:
            logger.warning("current-context check returned HTTP %s", response.status_code)
            return False, f"Failed to check capabilities (HTTP {response.status_code})"

        try:
            payload = response.json()
            entry = payload["entry"][0]
            caps = entry.get("content", {}).get("capabilities", [])
            self._capabilities = set(caps) if isinstance(caps, list) else set()
        except (json.JSONDecodeError, KeyError, IndexError, ValueError, TypeError) as exc:
            logger.error("Failed to parse current-context response: %s", exc)
            return False, _client_safe_error("Failed to parse capability response")

        self._capabilities_checked = True

        missing = required - self._capabilities
        if missing:
            return (
                False,
                f"User lacks required capabilities: {', '.join(sorted(missing))}",
            )
        return True, ""

    def build_app_endpoint(
        self, base: str, app_name: str | None = None, object_name: str = ""
    ) -> str:
        """Build ``services/...`` or ``servicesNS/...`` REST path."""
        if app_name is not None and app_name != "":
            if not _SAFE_APP_RE.match(app_name):
                raise ValueError(f"Invalid app name: {app_name!r}")
            path = f"servicesNS/-/{app_name}/{base}"
        else:
            path = f"services/{base}"
        if object_name:
            path = f"{path}/{object_name}"
        return path

    def export_search(
        self,
        query: str,
        earliest_time: str | None = None,
        latest_time: str | None = None,
        row_limit: int = 100,
        app: str | None = None,
        *,
        classify_400_as_savedsearch: bool = False,
    ) -> dict[str, Any]:
        """POST to ``search/jobs/export`` and parse NDJSON results.

        ``classify_400_as_savedsearch`` is opt-in. When True and the
        upstream returns HTTP 400 with a body matching one of the
        known ``_SAVEDSEARCH_400_HINTS`` markers, the returned
        ``error`` string carries a project-curated remediation hint
        (still tagged with the request id) instead of the opaque
        generic wrapper. Defaults to False to preserve the
        always-redact behaviour for every other call site.
        """
        data: dict[str, Any] = {
            "search": query,
            "output_mode": "json",
            "preview": "false",
        }
        if earliest_time is not None:
            data["earliest_time"] = earliest_time
        if latest_time is not None:
            data["latest_time"] = latest_time

        path = self.build_app_endpoint("search/jobs/export", app)
        response = self.call_api("POST", path, data=data)

        if response.status_code != 200:
            err_preview = _sanitize_for_log(response.text)
            logger.error(
                "export_search failed HTTP %s: %s",
                response.status_code,
                err_preview,
            )
            if classify_400_as_savedsearch and response.status_code == 400:
                hint = _classify_savedsearch_400(response.text)
                if hint is not None:
                    return {"error": f"{hint} (HTTP 400; request_id={current_request_id()})"}
            return {"error": _client_safe_error("Splunk API error", response.status_code)}

        parsed = convert_ndjson_to_dict(response.text)
        if parsed.errors and not parsed.results:
            joined = "\n".join(parsed.errors)
            logger.error(
                "Search produced no results and returned errors: %s",
                _sanitize_for_log(joined),
            )
            return {"error": _client_safe_error("Search returned errors; see server logs")}

        results = parsed.results
        max_row_limit = self.config.max_row_limit
        truncated = len(results) > row_limit
        out: dict[str, Any] = {
            "results": results[:row_limit],
            "truncated": truncated,
        }
        if len(results) == max_row_limit + 1:
            out["approx_total"] = f"{max_row_limit}+"
        else:
            out["total_rows"] = len(results)
        # R7: surface the *count* of NDJSON-level errors/warnings alongside
        # results without leaking the raw upstream text to clients.  The
        # full text is logged server-side (sanitized) for operators.
        if parsed.errors:
            joined = "\n".join(parsed.errors)
            logger.warning(
                "Search returned %d error message(s) alongside %d result(s): %s",
                len(parsed.errors),
                len(results),
                _sanitize_for_log(joined),
            )
            out["warnings"] = [
                _client_safe_error(
                    f"Search produced {len(parsed.errors)} error message(s); see server logs"
                )
            ]
        return out

    def check_spl_safe(
        self,
        query: str,
        safe_commands: set[str],
        sub_search_arg_cmd: dict[str, list[str]],
    ) -> tuple[bool, str]:
        """Validate SPL via ``services/search/parser`` including subsearches."""
        safe_lower = {c.strip().lower() for c in safe_commands if c.strip()}

        def validate(q: str) -> tuple[bool, str]:
            response = self.call_api(
                "POST",
                "services/search/parser",
                data={
                    "q": q,
                    "expand_macros": "0",
                    "output_mode": "json",
                    "parse_only": "1",
                },
            )
            if response.status_code != 200:
                body = _sanitize_for_log(response.text)
                logger.error(
                    "Parser API returned %s: %s",
                    response.status_code,
                    body,
                )
                return False, _client_safe_error("SPL parser error", response.status_code)

            try:
                query_tree = response.json()
            except json.JSONDecodeError as e:
                logger.error("Invalid JSON from parser: %s", e)
                return False, _client_safe_error("SPL parser returned invalid response")

            parsed_commands = query_tree.get("commands", [])
            if not isinstance(parsed_commands, list):
                return False, "Error parsing Splunk query response: invalid commands"

            for cmd in parsed_commands:
                if not isinstance(cmd, dict):
                    continue
                cmd_name = str(cmd.get("command", "")).strip().lower()
                if cmd_name and cmd_name not in safe_lower:
                    logger.warning("Forbidden command detected: %s", cmd_name)
                    return False, f"Forbidden command found: {cmd_name}"

                if cmd_name in sub_search_arg_cmd:
                    subsearch_args = sub_search_arg_cmd[cmd_name]
                    cmd_args = cmd.get("args", {})

                    for arg_name in subsearch_args:
                        if arg_name == "args":
                            raw_args = cmd.get("rawargs", "")
                            if raw_args:
                                for subsearch in re.findall(r"\[([^]]+)]", raw_args):
                                    ok, msg = validate(subsearch.strip())
                                    if not ok:
                                        return (
                                            False,
                                            f"Unsafe subsearch in {cmd_name}: {msg}",
                                        )
                        else:
                            values_to_check: list[str] = []
                            if isinstance(cmd_args, dict):
                                if arg_name in cmd_args:
                                    arg_value = cmd_args[arg_name]
                                    if isinstance(arg_value, str):
                                        values_to_check.append(arg_value)
                            elif isinstance(cmd_args, list):
                                for item in cmd_args:
                                    if isinstance(item, dict) and arg_name in item:
                                        item_value = item[arg_name]
                                        if isinstance(item_value, str):
                                            values_to_check.append(item_value)
                                    elif isinstance(item, str):
                                        values_to_check.append(item)
                            elif isinstance(cmd_args, str):
                                values_to_check.append(cmd_args)

                            for value in values_to_check:
                                start = 0
                                while True:
                                    open_idx = value.find("[", start)
                                    if open_idx == -1:
                                        break
                                    close_idx = value.find("]", open_idx + 1)
                                    if close_idx == -1:
                                        break
                                    subsearch = value[open_idx + 1 : close_idx].strip()
                                    if subsearch:
                                        ok, msg = validate(subsearch)
                                        if not ok:
                                            return (
                                                False,
                                                f"Unsafe subsearch in {cmd_name} {arg_name}: {msg}",
                                            )
                                    start = close_idx + 1

            return True, "Query is safe to run."

        try:
            return validate(query)
        except (requests.Timeout, requests.ConnectionError, SplunkLoginError):
            # Let ``server._execute_tool`` classify these into the
            # curated, operationally-useful messages
            # ("Splunk request timed out" / "Could not connect to
            # Splunk at host:port" / "Splunk authentication failed")
            # rather than misattributing them to the safety check.
            raise
        except Exception:
            logger.exception("SPL validator unexpected failure")
            return False, _client_safe_error("SPL safety check could not complete")

    def is_saved_search_disabled(
        self, name: str, app: str | None = None
    ) -> tuple[bool, str, str | None]:
        """Return whether a saved search is disabled in Splunk."""
        app_ns = app if app is not None else "-"
        if app is not None and not _SAFE_APP_RE.match(app):
            return False, f"Invalid app name: {app}", None

        encoded_name = quote(name, safe="")
        path = self.build_app_endpoint("saved/searches", app_ns, object_name=encoded_name)
        response = self.call_api(
            "GET",
            path,
            params={"output_mode": "json", "count": 1},
        )

        not_found_msg = (
            f"Saved search '{name}' not found. "
            "Use get_knowledge_objects with type='saved_searches' "
            "to list available saved searches."
        )

        if response.status_code != http.HTTPStatus.OK:
            body = _sanitize_for_log(response.text)
            logger.error(
                "Saved searches API returned %s: %s",
                response.status_code,
                body,
            )
            if app and response.status_code in (
                http.HTTPStatus.FORBIDDEN,
                http.HTTPStatus.NOT_FOUND,
            ):
                return (
                    False,
                    f"Saved search '{name}' not found in app '{app}'. "
                    "Verify the app name and saved search name are correct, "
                    "or omit the app parameter to search across all apps.",
                    None,
                )
            if not app and response.status_code == http.HTTPStatus.NOT_FOUND:
                return False, not_found_msg, None
            return (
                False,
                f"Failed to check saved search status (HTTP {response.status_code}).",
                None,
            )

        try:
            payload = response.json()
            entries = payload["entry"]
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to parse saved search response: %s", e)
            return (
                False,
                _client_safe_error("Error checking saved search status"),
                None,
            )

        if not entries:
            return False, not_found_msg, None

        if app is None and len(entries) > 1:
            entries = sorted(
                entries,
                key=lambda e: (e.get("acl") or {}).get("app", ""),
            )
            logger.info(
                "Saved search %r exists in multiple apps; using %r",
                name,
                (entries[0].get("acl") or {}).get("app"),
            )

        entry = entries[0]
        resolved_app = (entry.get("acl") or {}).get("app")

        try:
            content = entry["content"]
        except KeyError as e:
            logger.error("Failed to parse saved search entry: %s", e)
            return (
                False,
                _client_safe_error("Error checking saved search status"),
                None,
            )

        disabled = content.get("disabled", False)
        if disabled is True or disabled == "1":
            logger.warning("Saved search %r is disabled", name)
            return (
                True,
                f"Saved search '{name}' is disabled and cannot be executed.",
                resolved_app,
            )

        logger.info("Saved search %r is enabled", name)
        return False, "Saved search is enabled.", resolved_app


__all__ = [
    "NdjsonParseResult",
    "SplunkClient",
    "convert_ndjson_to_dict",
    "normalize_search_command",
]
