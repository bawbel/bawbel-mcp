# Changelog

All notable changes to bawbel-mcp are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [1.1.0] - 2026-05-23

### Added

**Three new tools**

- `scan_creds`: Credential-focused scan. Delegates to `bawbel creds`, filtering
  results to AVE-2026-00047 (hardcoded credentials) and related rules. Detects API
  keys, tokens, passwords, private keys, and URL-embedded credentials in skill
  file content.

- `scan_chain`: Delegation chain scan. Delegates to `bawbel chain`, filtering
  results to AVE-2026-00048 (unsafe agent delegation) and related rules. Detects
  sub-agent spawning with inherited permissions and missing trust boundaries.

- `accept_finding`: Justified suppression via the MCP server. Calls `bawbel accept`
  to insert a structured suppression comment directly into a skill file. Supports
  `false-positive` (permanent) and `accepted-risk` (with expiry date) types. The
  suppression comment is written into the file so it lives in version control and
  shows up in PR reviews. Expired accepted risks resurface automatically on the
  next scan.

**`no_ignore` parameter**

Added `no_ignore: bool = False` to `scan_content`, `scan_server_card`,
`scan_creds`, and `scan_chain`. When `True`, bypasses all suppression layers
(FP-2, FP-3, inline, justified) and returns every finding. Equivalent to
`bawbel scan --no-ignore`.

**`accepted_findings` in scan output**

`_format_scan_result` now renders the `accepted_findings` block from scan results.
Shows AVE ID, reason, reviewer, expiry date, and a warning if the accepted risk
has expired and the finding has resurfaced.

**`suppressed_findings` count**

Suppressed finding count is now shown in the summary line of every scan result
so callers know when findings are being filtered by the FP pipeline.

### Changed

- `bawbel-scanner` dependency bumped from `>=1.1.1` to `>=1.2.2` to pick up
  the Bug 1/2/3 fixes (unknown profile threshold, `--no-ignore` audit mode repair,
  `risk_score` including toxic flows).

- **Field name correction**: all references to `cvss_ai_score` and `cvss_ai` in
  finding and toxic flow formatting updated to `aivss_score`. PiranhaDB responses
  use `.get("aivss_score", .get("cvss_ai_score"))` fallback for backward compat
  while the API migration completes.

- **Toxic flow formatting**: `aivss_score` (not `cvss_ai`) is now used for the
  AIVSS score displayed next to each toxic flow in scan output.

- `_format_finding` extracted as a standalone helper used by both active and
  suppressed finding rendering. Reduces duplication.

- User-Agent header bumped to `bawbel-mcp/1.1`.

### Fixed

- `check_pins`: missing `try/except` around `subprocess.run` meant a
  `FileNotFoundError` (bawbel not installed) produced an unhandled exception
  instead of a clean error message. Now returns a human-readable error string
  for `FileNotFoundError` and `TimeoutExpired`.

- `list_ave`: query string construction used string concatenation instead of
  `"&".join(params)`, which produced a trailing `&` when no filters were set.

---

## [1.0.1] - 2026-05-07

### Fixed

- Added `<!-- mcp-name: io.github.bawbel/bawbel-mcp -->` marker to README.md
  so the MCP official registry validator can verify PyPI package ownership.
  No functional changes.

---

## [1.0.0] - 2026-05-04

### Added

First public release.

- `scan_content`: scan raw text content for AVE vulnerabilities
- `scan_server_card`: fetch and scan an MCP server-card by URL
- `check_conformance`: score a server manifest against the MCP spec (18 checks, A+ to F)
- `lookup_ave`: get a full AVE record by ID from PiranhaDB
- `search_ave`: search AVE records by keyword
- `list_ave`: list all AVE records with optional severity/category filters
- `check_pins`: detect rug pull drift in a directory of skill files
- `ave://stats` resource: current AVE database statistics
- `ave://record/{ave_id}` resource: full AVE record for a specific ID
- stdio transport (Claude Desktop, Claude Code, Cursor)
- Streamable HTTP transport for remote deployment

---

[Unreleased]: https://github.com/bawbel/bawbel-mcp/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/bawbel/bawbel-mcp/releases/tag/v1.1.0
[1.0.1]: https://github.com/bawbel/bawbel-mcp/releases/tag/v1.0.1
[1.0.0]: https://github.com/bawbel/bawbel-mcp/releases/tag/v1.0.0