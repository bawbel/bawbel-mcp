# Bawbel MCP Server

<!-- mcp-name: io.github.bawbel/bawbel-mcp -->

**Security scanner for MCP servers and agentic AI components, exposed as MCP tools.**

Bawbel MCP Server lets any MCP-compatible agent scan servers, check skill files,
score conformance, and query the AVE threat intelligence database mid-conversation.

[![PyPI version](https://badge.fury.io/py/bawbel-mcp.svg)](https://pypi.org/project/bawbel-mcp/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![AVE Standard](https://img.shields.io/badge/AVE_Records-45-teal.svg)](https://github.com/bawbel/bawbel-ave)

---

## Install

```bash
pip install bawbel-mcp
```

Or with all detection engines (YARA, Semgrep, LLM, Magika):

```bash
pip install "bawbel-mcp[all]"
```

---

## Tools

| Tool | Description |
|---|---|
| `scan_content` | Scan raw text content for AVE vulnerabilities |
| `scan_server_card` | Fetch and scan an MCP server-card before connecting |
| `check_conformance` | Score a server manifest against the MCP spec (18 checks, A+ to F) |
| `lookup_ave` | Get a full AVE record by ID with remediation guidance |
| `search_ave` | Search AVE records by keyword |
| `list_ave` | List all AVE records with optional severity/category filters |
| `check_pins` | Detect rug pull drift in a directory of skill files |

## Resources

| Resource | Description |
|---|---|
| `ave://stats` | Current AVE database statistics |
| `ave://record/{ave_id}` | Full AVE record for a specific ID |

---

## Usage

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bawbel": {
      "command": "uvx",
      "args": ["bawbel-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add bawbel uvx bawbel-mcp
```

### Cursor / Windsurf

Add to your MCP settings:

```json
{
  "bawbel": {
    "command": "uvx",
    "args": ["bawbel-mcp"]
  }
}
```

### Remote deployment (Streamable HTTP)

```bash
uvx bawbel-mcp --transport streamable-http --host 0.0.0.0 --port 8000
```

---

## Example conversations

**Scan a server before connecting:**

> "Before I add this MCP server to my config, scan it for security issues:
> https://api.some-mcp-server.com"

Claude calls `scan_server_card("https://api.some-mcp-server.com")` and reports any
findings with AVE IDs, severity, and remediation steps.

**Check a skill file:**

> "Check this skill file content for prompt injection vulnerabilities:
> [paste content]"

Claude calls `scan_content(content)` and returns findings.

**Score a server against the spec:**

> "Does this server follow the MCP spec? https://api.some-mcp-server.com"

Claude calls `check_conformance("https://api.some-mcp-server.com")` and returns
a score, grade, and list of failed checks.

**Look up a vulnerability:**

> "What is AVE-2026-00041 and how do I fix it?"

Claude calls `lookup_ave("AVE-2026-00041")` and returns the full record with
behavioral fingerprint, IOCs, and remediation steps.

**Search for relevant vulnerabilities:**

> "What AVE records cover credential exfiltration?"

Claude calls `search_ave("credential exfiltration")` and returns matching records.

---

## Requirements

- Python 3.10+
- `bawbel-scanner>=1.1.1` (installed automatically)
- `fastmcp>=3.0.0` (installed automatically)

The `bawbel` CLI must be available in PATH. Installing `bawbel-mcp` installs
`bawbel-scanner` which provides the `bawbel` CLI.

---

## Related

- [bawbel-scanner](https://github.com/bawbel/bawbel-scanner) — CLI scanner
- [bawbel-ave](https://github.com/bawbel/bawbel-ave) — AVE standard and records
- [api.piranha.bawbel.io](https://api.piranha.bawbel.io) — Threat intel API
- [bawbel.io/docs](https://bawbel.io/docs) — Full documentation

---

Apache 2.0. Built by [Bawbel](https://bawbel.io).
