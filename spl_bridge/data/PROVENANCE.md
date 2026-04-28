# Data file provenance

This directory contains three data files that drive the runtime
behaviour of `spl-bridge`. This document records, on a
per-file basis, the public sources those files were authored against,
so future contributors and downstream auditors can verify that nothing
in this directory was copied from a license-incompatible upstream.

## Independence statement

No source code, configuration, JSON schema, or SPL template content in
this directory has been copied from, or paraphrased from:

- `CiscoDevNet/Splunk-MCP-Server-official` (Cisco Sample Code License
  v1.1) on GitHub; or
- The "Splunk MCP Server" app on Splunkbase (Splunk LLC, governed by
  the Splunk General Terms).

All content is independently authored against publicly accessible
Splunk documentation listed below.

If you contribute to these files, you affirm by your DCO sign-off
(`Signed-off-by:`) that you have not copied, paraphrased, or re-typed
substantial expressive content from either upstream distribution into
this contribution. Any conceptual overlap with those sources reflects
the public Splunk REST API and SPL surface, which is documented at the
URLs cited per file below.

## `builtin_tools.json`

Catalogue of MCP tools. Each tool wraps exactly one publicly documented
Splunk REST endpoint with a thin SPL `| rest` invocation. The endpoint
URLs and response field names are dictated by the Splunk REST API
itself; selection of which fields to surface is editorial.

Source-of-record for each entry:

| Tool | Splunk REST endpoint | Public reference |
|------|----------------------|------------------|
| `get_info` | `GET /services/server/info` | https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTserver |
| `get_indexes` / `get_index_info` | `GET /services/data/indexes` | https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTindex |
| `get_user_list` | `GET /services/authentication/users` | https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTaccess |
| `get_user_info` | `GET /services/authentication/current-context` | https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTaccess |
| `run_query` | `POST /services/search/jobs/export` | https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch |
| `get_metadata` | SPL `| metadata` generating command | https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/Metadata |
| `get_kv_store_collections` | `GET /services/server/introspection/kvstore/collectionstats` | https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTintrospec |
| `get_knowledge_objects` | `GET /servicesNS/-/-/...` (saved searches, props, transforms, datamodel, ui, apps) | https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTknowledge https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput |
| `run_saved_search` | SPL `| savedsearch` generating command | https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/Savedsearch |

The `_key` namespace `spl_bridge:builtin:*` is this
project's own identifier scheme; it does not match any namespace used
by the upstream Splunk app or the CiscoDevNet repository.

## `safe_spl.json`

`safe_spl_commands` is a curated allowlist of SPL command names that
this project considers safe to dispatch on behalf of an LLM caller.
The list is authored against the public Splunk Search Reference index:

- https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ListOfSearchCommands

Selection criteria (this project's own editorial policy):

- Include search/transformation/reporting commands that do not write
  back to the Splunk instance, do not reach external systems, and do
  not invoke the operating system.
- Exclude commands whose primary effect is mutation, exfiltration, or
  arbitrary code execution, including but not limited to: `rest`,
  `script`, `sendemail`, `outputcsv`, `outputlookup`, `collect`,
  `delete`, `tscollect`, `summaryindex`, and `script`-style hooks.
- Exclude commands gated by Splunk Enterprise Security or the Machine
  Learning Toolkit when their availability cannot be assumed in a
  vanilla Splunk install (`fit`, `apply`, `score`, `summary` are
  included only because they are independently exercisable through the
  REST API and are commonly available in MLTK-equipped deployments;
  operators who lack MLTK should remove them).

`exclude_tools` lists the MCP tool names whose execution path bypasses
the SPL allowlist (because the tool either calls a non-SPL REST
endpoint directly, or dispatches a saved search whose contents are
governed by the saved-search owner's role rather than by this
project's policy).

`sub_search_arg_cmd` records, per command, the argument names whose
values are themselves SPL fragments and therefore must be re-validated
against the allowlist (defence-in-depth against subsearch injection).
The selection of commands and arg names is authored against each
command's public Search Reference page.

## `generating_commands.json`

A list of SPL commands that are valid in the leading position of a
search pipeline (i.e., do not require an upstream `search` to source
events). Authored against the per-command "Description" sections of
the Splunk Search Reference at the URL above. The list is purely
factual.
