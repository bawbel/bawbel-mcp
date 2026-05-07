"""
Bawbel MCP Server

Exposes Bawbel Scanner functionality as MCP tools so any agent
can scan MCP servers, check skill files, score conformance, and
query the AVE threat intelligence database mid-conversation.

Tools:
    scan_content: scan raw content or a file path
    scan_server_card: fetch and scan an MCP server-card URL
    check_conformance: score an MCP server manifest against the spec
    lookup_ave: get a full AVE record by ID
    search_ave: search AVE records by keyword
    list_ave: list all AVE records with optional filters
    check_pins: detect rug pull drift in a directory

Usage:
    # stdio (Claude Desktop, Claude Code)
    uvx bawbel-mcp

    # Streamable HTTP (remote deployment)
    uvx bawbel-mcp --transport streamable-http --port 8000
"""

import json
import subprocess  # nosec B404  # noqa: S404
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP

mcp = FastMCP(
    name="Bawbel Scanner",
    instructions=(
        "Security scanner for MCP servers and agentic AI components. "
        "Use scan_server_card before connecting to any MCP server. "
        "Use scan_content to check skill files or system prompts. "
        "Use check_conformance to verify a server follows the MCP spec. "
        "Use lookup_ave or search_ave to query the AVE threat intelligence database."
    ),
)

PIRANHA_API = "https://api.piranha.bawbel.io"
MAX_CONTENT_BYTES = 100 * 1024  # 100KB


# ── Helpers ────────────────────────────────────────────────────────────────────


def _run_bawbel(args: list[str], input_file: Optional[str] = None) -> dict:
    """
    Run bawbel CLI and return parsed JSON output.
    Returns error dict on failure.
    """
    cmd = ["bawbel"] + args + ["--format", "json"]
    if input_file:
        cmd.append(input_file)

    try:
        result = subprocess.run(  # nosec B603  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = result.stdout.strip()
        if not raw:
            return {
                "error": result.stderr.strip() or "Scanner produced no output",
                "findings": [],
                "toxic_flows": [],
                "risk_score": 0,
            }

        # JSON output is a list of file results
        start = raw.find("[")
        if start < 0:
            return {"error": raw[:300], "findings": [], "toxic_flows": [], "risk_score": 0}

        results = json.loads(raw[start:])
        if results:
            return results[0]
        return {"findings": [], "toxic_flows": [], "risk_score": 0}

    except subprocess.TimeoutExpired:
        return {"error": "Scan timeout (60s)", "findings": [], "toxic_flows": [], "risk_score": 0}
    except json.JSONDecodeError as e:
        return {"error": f"Parse error: {e}", "findings": [], "toxic_flows": [], "risk_score": 0}
    except FileNotFoundError:
        return {
            "error": (
                "bawbel CLI not found. "
                "Install with: pip install bawbel-scanner"
            ),
            "findings": [],
            "toxic_flows": [],
            "risk_score": 0,
        }


def _fetch_url(url: str) -> tuple[Optional[str], Optional[str]]:
    """Fetch content from a URL. Returns (content, error)."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "bawbel-mcp/1.0 (https://bawbel.io)"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:  # nosec B310  # noqa: S310
            return r.read(MAX_CONTENT_BYTES).decode("utf-8", errors="replace"), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return None, f"URL error: {e.reason}"
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def _piranha_get(path: str) -> dict:
    """GET from PiranhaDB API. Returns parsed JSON or error dict."""
    url = f"{PIRANHA_API}{path}"
    content, err = _fetch_url(url)
    if err:
        return {"error": f"PiranhaDB unavailable: {err}"}
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"error": "Invalid response from PiranhaDB"}


def _format_scan_result(result: dict) -> str:
    """Format scan result for human-readable MCP response."""
    if result.get("error"):
        return f"Error: {result['error']}"

    findings = result.get("findings", [])
    toxic_flows = result.get("toxic_flows", [])
    risk_score = result.get("risk_score", 0)
    max_severity = result.get("max_severity", "NONE")

    lines = []

    if not findings and not toxic_flows:
        lines.append("Clean: no findings detected.")
        lines.append(f"Risk score: {risk_score:.1f}/10")
        return "\n".join(lines)

    lines.append(f"Risk score: {risk_score:.1f}/10  ({max_severity})")
    lines.append(f"Findings: {len(findings)}  Toxic flows: {len(toxic_flows)}")
    lines.append("")

    if findings:
        lines.append("FINDINGS")
        lines.append("-" * 50)
        for f in findings:
            sev = f.get("severity", "?")
            ave_id = f.get("ave_id", "")
            title = f.get("title", "")
            line_no = f.get("line_number")
            owasp_mcp = ", ".join(f.get("owasp_mcp", []))
            lines.append(f"[{sev}] {ave_id}  {title}")
            if line_no:
                lines.append(f"  Line {line_no}")
            if owasp_mcp:
                lines.append(f"  OWASP MCP: {owasp_mcp}")
            lines.append(
                f"  Details: {PIRANHA_API}/records/{ave_id}"
            )
            lines.append("")

    if toxic_flows:
        lines.append("TOXIC FLOWS DETECTED")
        lines.append("-" * 50)
        for flow in toxic_flows:
            title = flow.get("title", "")
            cvss = flow.get("cvss_ai", 0)
            caps = " + ".join(flow.get("capabilities", []))
            ave_ids = ", ".join(flow.get("ave_ids", []))
            lines.append(f"⛓  CRITICAL {cvss}  {title}")
            lines.append(f"  Chain: {caps}")
            lines.append(f"  AVEs: {ave_ids}")
            lines.append("")

    return "\n".join(lines)


# ── Tools ──────────────────────────────────────────────────────────────────────


@mcp.tool()
def scan_content(
    content: str,
    label: str = "submitted-content",
) -> str:
    """
    Scan raw text content for AVE security vulnerabilities.

    Use this to check skill file content, system prompts, MCP tool
    descriptions, or any agentic AI component before using it.

    Returns findings with AVE IDs, severity, OWASP MCP categories,
    and links to full remediation guidance. Also detects toxic flows
    where two findings combine into a complete attack chain.

    Args:
        content: The text content to scan (skill file, system prompt, etc.)
        label:   Optional label for the content in the output (default: submitted-content)
    """
    if not content or not content.strip():
        return "Error: content is empty"

    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        return f"Error: content exceeds {MAX_CONTENT_BYTES // 1024}KB limit"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", prefix="bawbel_mcp_",
        delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        tmp_path = f.name

    try:
        result = _run_bawbel(["scan"], input_file=tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return _format_scan_result(result)


@mcp.tool()
async def scan_server_card(url: str) -> str:
    """
    Fetch and scan an MCP server-card for security vulnerabilities.

    Fetches .well-known/mcp.json from the given server URL and scans
    all tool descriptions, parameter descriptions, and config schemas
    for AVE vulnerabilities before your agent connects.

    This is the primary tool to run before adding any MCP server to
    your configuration. A poisoned server-card injects behavioral
    instructions at the discovery layer, before any tool call is made.

    Args:
        url: Base URL of the MCP server (e.g. https://api.example.com)
    """
    if not url.startswith(("http://", "https://")):
        return "Error: URL must start with http:// or https://"

    # Try server-card path first, then fall back to direct URL
    server_card_url = url.rstrip("/") + "/.well-known/mcp.json"
    content, err = _fetch_url(server_card_url)

    if not content:
        # Try direct URL (might be a direct link to mcp.json)
        content, err = _fetch_url(url)
        if not content:
            return f"Error: Could not fetch server-card from {server_card_url}\n{err}"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="bawbel_mcp_ssc_",
        delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        tmp_path = f.name

    try:
        result = _run_bawbel(["scan"], input_file=tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    output = [f"Server-card scan: {server_card_url}", ""]
    output.append(_format_scan_result(result))

    # Suggest conformance check
    if not result.get("error"):
        output.append("")
        output.append(
            f"Tip: run check_conformance('{url}') to score "
            "this server against the MCP spec."
        )

    return "\n".join(output)


@mcp.tool()
def check_conformance(url_or_path: str) -> str:
    """
    Score an MCP server manifest against the MCP specification.

    Runs 18 checks across 3 tiers (REQUIRED, RECOMMENDED, BEST PRACTICE)
    and returns a grade from A+ to F. A server is conformant when all
    REQUIRED checks pass. Grade F means at least one REQUIRED check failed.

    Accepts:
        - A local file path to a server.json manifest
        - A server base URL (fetches .well-known/mcp.json automatically)

    Args:
        url_or_path: Local path to server.json OR base URL of MCP server
    """
    result = _run_bawbel(["scan-conformance", url_or_path])

    if result.get("error"):
        return f"Error: {result['error']}"

    score = result.get("score", 0)
    grade = result.get("grade", "?")
    is_conformant = result.get("is_conformant", False)
    checks = result.get("checks", [])

    lines = [
        f"Conformance score: {score:.0f}/100  Grade: {grade}",
        f"Conformant: {'Yes' if is_conformant else 'No (REQUIRED check failed)'}",
        "",
    ]

    failed = [c for c in checks if c.get("status") == "FAIL"]
    passed = [c for c in checks if c.get("status") == "PASS"]
    skipped = [c for c in checks if c.get("status") == "SKIP"]

    if failed:
        lines.append(f"FAILED ({len(failed)}):")
        for c in failed:
            tier = c.get("tier", "")
            name = c.get("check_id", "")
            msg = c.get("message", "")
            lines.append(f"  [{tier}] {name}: {msg}")
        lines.append("")

    lines.append(
        f"Passed: {len(passed)}  Failed: {len(failed)}  Skipped: {len(skipped)}"
    )

    return "\n".join(lines)


@mcp.tool()
def lookup_ave(ave_id: str) -> str:
    """
    Get the full AVE record for a specific vulnerability ID.

    Returns the complete record including title, description,
    CVSS-AI score, behavioral fingerprint, indicators of compromise,
    OWASP MCP mapping, NIST AI RMF mapping, and remediation steps.

    Args:
        ave_id: AVE ID in the format AVE-2026-NNNNN (e.g. AVE-2026-00001)
    """
    ave_id = ave_id.strip().upper()
    if not ave_id.startswith("AVE-"):
        return "Error: AVE ID must be in the format AVE-2026-NNNNN"

    data = _piranha_get(f"/records/{ave_id}")

    if data.get("error"):
        return f"Error: {data['error']}"

    lines = [
        f"{data.get('ave_id', '')}  {data.get('title', '')}",
        f"Severity:     {data.get('severity', '')}  (CVSS-AI {data.get('cvss_ai_score', '')})",
        f"Attack class: {data.get('attack_class', '')}",
        f"Component:    {data.get('component_type', '')}",
        f"Status:       {data.get('status', '')}",
        "",
        f"Description:",
        f"  {data.get('description', '')}",
        "",
        f"Behavioral fingerprint:",
        f"  {data.get('behavioral_fingerprint', '')}",
        "",
    ]

    owasp = data.get("owasp_mapping", [])
    owasp_mcp = data.get("owasp_mcp", [])
    if owasp:
        lines.append(f"OWASP ASI:  {', '.join(owasp)}")
    if owasp_mcp:
        lines.append(f"OWASP MCP:  {', '.join(owasp_mcp)}")

    remediation = data.get("remediation", "")
    if remediation:
        lines.append("")
        lines.append("Remediation:")
        lines.append(f"  {remediation}")

    iocs = data.get("indicators_of_compromise", [])
    if iocs:
        lines.append("")
        lines.append("Indicators of compromise:")
        for ioc in iocs:
            lines.append(f"  - {ioc}")

    lines.append("")
    lines.append(f"Full record: {PIRANHA_API}/records/{ave_id}")

    return "\n".join(lines)


@mcp.tool()
def search_ave(
    query: str,
    limit: int = 10,
) -> str:
    """
    Search AVE records by keyword.

    Searches across AVE ID, title, attack class, description, and
    behavioral fingerprint. Returns matching records with severity,
    CVSS-AI score, and a link to the full record.

    Args:
        query: Search term (e.g. "tool poisoning", "credential", "MCP01")
        limit: Maximum number of results to return (default 10, max 20)
    """
    limit = min(limit, 20)
    data = _piranha_get(f"/records/search?q={urllib.parse.quote(query)}&limit={limit}")

    if data.get("error"):
        return f"Error: {data['error']}"

    records = data.get("records", [])
    total = data.get("total", 0)

    if not records:
        return f"No AVE records found for query: {query}"

    lines = [f"Found {total} record(s) for '{query}' (showing {len(records)})", ""]

    for r in records:
        ave_id = r.get("ave_id", "")
        title = r.get("title", "")
        severity = r.get("severity", "")
        score = r.get("cvss_ai_score", 0)
        owasp_mcp = ", ".join(r.get("owasp_mcp", []))
        lines.append(f"[{severity} {score}] {ave_id}  {title}")
        if owasp_mcp:
            lines.append(f"  OWASP MCP: {owasp_mcp}")
        lines.append(f"  {PIRANHA_API}/records/{ave_id}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
def list_ave(
    severity: Optional[str] = None,
    component_type: Optional[str] = None,
    owasp_mcp: Optional[str] = None,
) -> str:
    """
    List AVE records with optional filters.

    Use this to browse the full AVE database or filter by severity,
    component type, or OWASP MCP category.

    Args:
        severity:       Filter by CRITICAL, HIGH, MEDIUM, or LOW
        component_type: Filter by skill, mcp, prompt, or plugin
        owasp_mcp:      Filter by OWASP MCP category (e.g. MCP03, MCP05)
    """
    params = []
    if severity:
        params.append(f"severity={severity.upper()}")
    if component_type:
        params.append(f"component_type={component_type.lower()}")
    if owasp_mcp:
        params.append(f"owasp_mcp={owasp_mcp.upper()}")
    params.append("limit=50")

    qs = "&".join(params)
    data = _piranha_get(f"/records?{qs}")

    if data.get("error"):
        return f"Error: {data['error']}"

    records = data.get("records", [])
    total = data.get("total", 0)

    if not records:
        return "No AVE records found with the given filters."

    lines = [f"Showing {len(records)} of {total} AVE records", ""]

    for r in records:
        ave_id = r.get("ave_id", "")
        title = r.get("title", "")
        severity_val = r.get("severity", "")
        score = r.get("cvss_ai_score", 0)
        owasp_mcp_val = ", ".join(r.get("owasp_mcp", []))
        lines.append(f"[{severity_val} {score}] {ave_id}  {title}")
        if owasp_mcp_val:
            lines.append(f"  OWASP MCP: {owasp_mcp_val}")

    lines.append("")
    lines.append(f"Full database: {PIRANHA_API}/records")

    return "\n".join(lines)


@mcp.tool()
def check_pins(path: str = ".") -> str:
    """
    Check a directory for skill file rug pull drift.

    Compares current SHA-256 hashes of skill files against the pins
    stored in .bawbel-pins.json. Reports any files that changed after
    the last audit.

    Run bawbel pin <path> from the CLI to create the initial pin file.

    Args:
        path: Directory to check (default: current directory)
    """
    result = subprocess.run(  # nosec B603  # noqa: S603
        ["bawbel", "check-pins", path, "--format", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    raw = result.stdout.strip()
    if not raw:
        stderr = result.stderr.strip()
        if "No pin file found" in stderr or result.returncode == 1:
            return (
                f"No .bawbel-pins.json found in {path}.\n"
                "Run 'bawbel pin <path>' from the CLI to create initial pins."
            )
        return stderr or "No output from pin check"

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw

    drifted = data.get("drifted", [])
    pinned = data.get("pinned_count", 0)
    status = data.get("status", "")

    if not drifted:
        return f"Clean: all {pinned} pinned files match their stored hashes."

    lines = [
        f"DRIFT DETECTED: {len(drifted)} of {pinned} files changed",
        "",
    ]
    for f in drifted:
        lines.append(f"  {f.get('file', '')}")
        lines.append(f"    Pinned:  {f.get('pinned_hash', '')[:16]}...")
        lines.append(f"    Current: {f.get('current_hash', '')[:16]}...")
        lines.append("")

    lines.append(
        "Action: review the changed files with 'bawbel report <file>'. "
        "If safe, re-pin with 'bawbel pin --update <file>'."
    )

    return "\n".join(lines)


# ── Resources ──────────────────────────────────────────────────────────────────


@mcp.resource("ave://stats")
def ave_stats() -> str:
    """Current AVE database statistics from PiranhaDB."""
    data = _piranha_get("/stats/ecosystem")
    if data.get("error"):
        return f"Error: {data['error']}"

    ave = data.get("ave_records", {})
    by_sev = ave.get("by_severity", {})

    lines = [
        f"AVE Records: {ave.get('total', 0)}",
        f"  CRITICAL: {by_sev.get('CRITICAL', 0)}",
        f"  HIGH:     {by_sev.get('HIGH', 0)}",
        f"  MEDIUM:   {by_sev.get('MEDIUM', 0)}",
        f"  LOW:      {by_sev.get('LOW', 0)}",
        "",
        f"API: {PIRANHA_API}",
        f"AVE Standard: https://github.com/bawbel/bawbel-ave",
    ]

    registry = data.get("registry_scans", {})
    if registry.get("total_servers_scanned"):
        lines.append("")
        lines.append(
            f"Registry scans: {registry['total_servers_scanned']} servers scanned, "
            f"{registry['total_findings']} findings"
        )

    return "\n".join(lines)


@mcp.resource("ave://record/{ave_id}")
def ave_record(ave_id: str) -> str:
    """Full AVE record for a specific vulnerability ID."""
    return lookup_ave(ave_id)


# ── Entry point ────────────────────────────────────────────────────────────────


def main():
    mcp.run()


if __name__ == "__main__":
    main()
