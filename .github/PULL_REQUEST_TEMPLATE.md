<!--
  Thanks for contributing to spl-bridge.
  Please complete the checklists below. PRs that leave the legal /
  provenance section blank or unchecked will be held until they are.
-->

## Summary

<!-- One paragraph: what does this change do, and why. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Refactor / internal-only
- [ ] Documentation only
- [ ] Test / CI only

## Test plan

<!--
  Bullet list of what you ran locally and what passed.
  Examples:
    - `pytest -q`
    - `ruff check .`
    - `mypy spl_bridge`
    - smoke tested against a lab Splunk at <host>
-->

## Legal / provenance checklist

> Required by `CONTRIBUTING.md` and the project's DCO. Do not skip.

- [ ] Every commit in this PR is signed off (`git commit -s`).
- [ ] I authored this contribution against publicly available Splunk
      documentation only (REST API Reference, Search Reference,
      Splunkbase product pages, `docs.splunk.com`, `splunkbase.splunk.com`).
- [ ] I have **not** copied, paraphrased, or re-typed substantial
      expressive content (source code, configuration, JSON schemas,
      SPL templates) from `CiscoDevNet/Splunk-MCP-Server-official`
      (Cisco Sample Code License v1.1) or the Splunk MCP Server app
      published on Splunkbase (Splunk General Terms) into this
      contribution. Any conceptual overlap with those sources reflects
      the public Splunk REST API and SPL surface, which is documented
      at the URLs cited in `spl_bridge/data/PROVENANCE.md`.
- [ ] If I touched a file under `spl_bridge/data/`, I updated
      `spl_bridge/data/PROVENANCE.md` with a source-of-record
      citation in the same commit.
- [ ] If I added a new runtime dependency, I regenerated
      `THIRD_PARTY_NOTICES.txt` via
      `python scripts/generate_third_party_notices.py > THIRD_PARTY_NOTICES.txt`
      in the same commit.
- [ ] I have not introduced any user-visible string that leads with
      the "Splunk" mark as a product or component name (per Splunk's
      [Trademark Usage Guidelines](https://www.splunk.com/en_us/legal/trademark-usage-guidelines.html)).
      Nominative phrases such as "for Splunk" / "Splunk REST API" are
      fine.

## Security checklist

- [ ] No secrets, tokens, passwords, or PII added to any file (the
      `secret-grep` pre-commit hook should catch this; double-check
      anyway).
- [ ] If this changes credential handling, SPL parsing, the wire
      format, or trust boundaries, I have flagged it for deeper
      review and added both positive and negative test cases.
