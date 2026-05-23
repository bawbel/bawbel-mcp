"""
Bawbel MCP Server

Exposes Bawbel Scanner functionality as MCP tools so any agent
can scan MCP servers, check skill files, score conformance, query
the AVE threat intelligence database, and manage justified suppressions
mid-conversation.

Tools:
    scan_content        scan raw content or a file path
    scan_server_card    fetch and scan an MCP server-card URL
    scan_creds          credential-focused scan (AVE-2026-00047 and related)
    scan_chain          delegation chain scan (AVE-2026-00048 and related)
    check_conformance   score an MCP server manifest against the spec
    accept_finding      insert a justified suppression into a skill file
    lookup_ave          get a full AVE record by ID
    search_ave          search AVE records by keyword
    list_ave            list all AVE records with optional filters
    check_pins          detect rug pull drift in a directory

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
        "Use accept_finding to suppress false positives with a justified reason. "
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
            headers={"User-Agent": "bawbel-mcp/1.1 (https://bawbel.io)"},
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


def _format_finding(f: dict) -> list[str]:
    """Format a single finding into display lines."""
    lines = []
    sev = f.get("severity", "?")
    ave_id = f.get("ave_id", "")
    title = f.get("title", "")
    line_no = f.get("line")
    aivss = f.get("aivss_score", 0)
    owasp_mcp = ", ".join(f.get("owasp_mcp", []))
    engine = f.get("engine", "")
    match = f.get("match", "")

    lines.append(f"[{sev}] {ave_id}  {title}  AIVSS {aivss:.1f}")
    if line_no:
        lines.append(f"  Line {line_no}: {match[:80]}" if match else f"  Line {line_no}")
    if engine:
        lines.append(f"  Engine: {engine}")
    if owasp_mcp:
        lines.append(f"  OWASP MCP: {owasp_mcp}")
    lines.append(f"  Details: {PIRANHA_API}/records/{ave_id}")
    return lines


def _format_scan_result(result: dict, show_suppressed: bool = False) -> str:
    """Format a full scan result for human-readable MCP response."""
    if result.get("error"):
        return f"Error: {result['error']}"

    findings = result.get("findings", [])
    toxic_flows = result.get("toxic_flows", [])
    suppressed = result.get("suppressed_findings", [])
    accepted = result.get("accepted_findings", [])
    risk_score = result.get("risk_score", 0)
    max_severity = result.get("max_severity")

    lines = []

    if not findings and not toxic_flows:
        lines.append("Clean: no findings detected.")
        lines.append(f"Risk score: {risk_score:.1f}/10")
        if suppressed:
            lines.append(
                f"Note: {len(suppressed)} finding(s) suppressed "
                "(run scan with no_ignore=True to see all)"
            )
        if accepted:
            lines.append(
                f"Note: {len(accepted)} accepted risk(s) on file "
                "(justified suppression active)"
            )
        return "\n".join(lines)

    sev_label = max_severity if max_severity else "UNKNOWN"
    lines.append(f"Risk score: {risk_score:.1f}/10  ({sev_label})")
    lines.append(
        f"Findings: {len(findings)}  "
        f"Toxic flows: {len(toxic_flows)}  "
        f"Suppressed: {len(suppressed)}  "
        f"Accepted: {len(accepted)}"
    )
    lines.append("")

    if findings:
        lines.append("FINDINGS")
        lines.append("-" * 50)
        for f in findings:
            lines.extend(_format_finding(f))
            lines.append("")

    if toxic_flows:
        lines.append("TOXIC FLOWS DETECTED")
        lines.append("-" * 50)
        for flow in toxic_flows:
            title = flow.get("title", "")
            aivss = flow.get("aivss_score", 0)
            chain = flow.get("chain", "")
            ave_ids = ", ".join(flow.get("ave_ids", []))
            owasp_mcp = ", ".join(flow.get("owasp_mcp", []))
            lines.append(f"CRITICAL  {aivss:.1f}  {title}")
            if chain:
                lines.append(f"  Chain: {chain}")
            if ave_ids:
                lines.append(f"  AVEs: {ave_ids}")
            if owasp_mcp:
                lines.append(f"  OWASP MCP: {owasp_mcp}")
            lines.append("")

    if accepted:
        lines.append("ACCEPTED RISKS (justified suppressions active)")
        lines.append("-" * 50)
        for af in accepted:
            ave_id = af.get("ave_id", "")
            reason = af.get("reason", "")
            reviewer = af.get("reviewer", "")
            expires = af.get("expires_at", "")
            is_expired = af.get("is_expired", False)
            expiry_note = " [EXPIRED - finding resurfaced]" if is_expired else (
                f" (expires {expires})" if expires else ""
            )
            lines.append(f"  {ave_id}: {reason} - reviewed by {reviewer}{expiry_note}")
        lines.append("")

    if show_suppressed and suppressed:
        lines.append("SUPPRESSED FINDINGS")
        lines.append("-" * 50)
        for f in suppressed:
            reason = f.get("suppression_reason", "")
            lines.extend(_format_finding(f))
            if reason:
                lines.append(f"  Suppressed: {reason}")
            lines.append("")

    return "\n".join(lines)


# ── Tools ──────────────────────────────────────────────────────────────────────


@mcp.tool()
def scan_content(
    content: str,
    label: str = "submitted-content",
    no_ignore: bool = False,
) -> str:
    """
    Scan raw text content for AVE security vulnerabilities.

    Use this to check skill file content, system prompts, MCP tool
    descriptions, or any agentic AI component before using it.

    Returns findings with AVE IDs, AIVSS severity scores, OWASP MCP
    categories, and links to full remediation guidance. Also detects
    toxic flows where two findings combine into a complete attack chain.

    Args:
        content:   The text content to scan (skill file, system prompt, etc.)
        label:     Optional label for the content in the output
        no_ignore: If True, bypass all suppressions and show every finding
    """
    if not content or not content.strip():
        return "Error: content is empty"

    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        return f"Error: content exceeds {MAX_CONTENT_BYTES // 1024}KB limit"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", prefix="bawbel_mcp_",
        delete=False, encoding="utf-8",
    ) as f:
        f.write(content)
        tmp_path = f.name

    try:
        args = ["scan"]
        if no_ignore:
            args.append("--no-ignore")
        result = _run_bawbel(args, input_file=tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return _format_scan_result(result)


@mcp.tool()
def scan_server_card(url: str, no_ignore: bool = False) -> str:
    """
    Fetch and scan an MCP server-card for security vulnerabilities.

    Fetches .well-known/mcp.json from the given server URL and scans
    all tool descriptions, parameter descriptions, and config schemas
    for AVE vulnerabilities before your agent connects.

    This is the primary tool to run before adding any MCP server to
    your configuration. A poisoned server-card injects behavioral
    instructions at the discovery layer, before any tool call is made.

    Args:
        url:       Base URL of the MCP server (e.g. https://api.example.com)
        no_ignore: If True, bypass all suppressions and show every finding
    """
    if not url.startswith(("http://", "https://")):
        return "Error: URL must start with http:// or https://"

    server_card_url = url.rstrip("/") + "/.well-known/mcp.json"
    content, err = _fetch_url(server_card_url)

    if not content:
        content, err = _fetch_url(url)
        if not content:
            return f"Error: Could not fetch server-card from {server_card_url}\n{err}"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="bawbel_mcp_ssc_",
        delete=False, encoding="utf-8",
    ) as f:
        f.write(content)
        tmp_path = f.name

    try:
        args = ["scan"]
        if no_ignore:
            args.append("--no-ignore")
        result = _run_bawbel(args, input_file=tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    output = [f"Server-card scan: {server_card_url}", ""]
    output.append(_format_scan_result(result))

    if not result.get("error"):
        output.append("")
        output.append(
            f"Tip: run check_conformance('{url}') to score "
            "this server against the MCP spec."
        )

    return "\n".join(output)


@mcp.tool()
def scan_creds(content: str, no_ignore: bool = False) -> str:
    """
    Credential-focused scan of skill file content.

    Filters to AVE-2026-00047 (hardcoded credentials) and related
    rules only. Detects API keys, tokens, passwords, private keys,
    and URL-embedded credentials.

    Use this when you specifically want to check whether a skill file
    contains hardcoded secrets before adding it to your agent config.

    Args:
        content:   The text content to scan
        no_ignore: If True, bypass all suppressions
    """
    if not content or not content.strip():
        return "Error: content is empty"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", prefix="bawbel_mcp_creds_",
        delete=False, encoding="utf-8",
    ) as f:
        f.write(content)
        tmp_path = f.name

    try:
        args = ["creds"]
        if no_ignore:
            args.append("--no-ignore")
        result = _run_bawbel(args, input_file=tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return _format_scan_result(result)


@mcp.tool()
def scan_chain(content: str, no_ignore: bool = False) -> str:
    """
    Delegation chain scan of skill file content.

    Filters to AVE-2026-00048 (unsafe agent delegation) and related
    rules. Detects sub-agent spawning with inherited permissions and
    missing trust boundaries.

    Use this when evaluating a skill that spawns sub-agents or
    delegates tasks to other agents.

    Args:
        content:   The text content to scan
        no_ignore: If True, bypass all suppressions
    """
    if not content or not content.strip():
        return "Error: content is empty"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", prefix="bawbel_mcp_chain_",
        delete=False, encoding="utf-8",
    ) as f:
        f.write(content)
        tmp_path = f.name

    try:
        args = ["chain"]
        if no_ignore:
            args.append("--no-ignore")
        result = _run_bawbel(args, input_file=tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return _format_scan_result(result)


@mcp.tool()
def accept_finding(
    ave_id: str,
    file_path: str,
    line: int,
    reason: str,
    reviewer: str,
    acceptance_type: str = "false-positive",
    expires_days: Optional[int] = None,
) -> str:
    """
    Insert a justified suppression comment into a skill file.

    Marks a finding as a false positive or accepted risk with a
    documented reason, reviewer, and optional expiry date. The
    suppression is written directly into the file as a structured
    comment that lives in version control and shows up in PR reviews.

    Accepted risks with an expiry date automatically resurface as
    active findings on the next scan after the expiry date passes.

    Args:
        ave_id:          AVE ID to suppress (e.g. AVE-2026-00001)
        file_path:       Absolute or relative path to the skill file
        line:            Line number of the finding to suppress
        reason:          Why this finding is a false positive or accepted risk
        reviewer:        Your GitHub handle or name
        acceptance_type: "false-positive" (permanent) or "accepted-risk" (with expiry)
        expires_days:    Days until the accepted risk expires (required for accepted-risk)
    """
    if not Path(file_path).exists():
        return f"Error: file not found: {file_path}"

    if acceptance_type not in ("false-positive", "accepted-risk"):
        return "Error: acceptance_type must be 'false-positive' or 'accepted-risk'"

    if acceptance_type == "accepted-risk" and not expires_days:
        return "Error: expires_days is required for accepted-risk type"

    cmd = [
        "bawbel", "accept", ave_id, file_path,
        "--line", str(line),
        "--reason", reason,
        "--reviewer", reviewer,
        "--type", acceptance_type,
    ]

    if expires_days:
        cmd.extend(["--expires", f"{expires_days}d"])

    try:
        result = subprocess.run(  # nosec B603  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return f"Error: {result.stderr.strip() or result.stdout.strip()}"

        return (
            f"Accepted: {ave_id} on line {line} of {file_path}\n"
            f"Type: {acceptance_type}\n"
            f"Reason: {reason}\n"
            f"Reviewer: {reviewer}\n"
            + (f"Expires: {expires_days} days from today\n" if expires_days else "")
            + "\nThe suppression comment has been written into the file. "
            "Commit this change so the approval is tracked in version control."
        )
    except subprocess.TimeoutExpired:
        return "Error: accept command timed out"
    except FileNotFoundError:
        return "Error: bawbel CLI not found. Install with: pip install bawbel-scanner"


@mcp.tool()
def check_conformance(url_or_path: str) -> str:
    """
    Score an MCP server manifest against the MCP specification.

    Runs 18 checks across 3 tiers (REQUIRED, RECOMMENDED, BEST PRACTICE)
    and returns a grade from A+ to F. A server is conformant when all
    REQUIRED checks pass.

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

    Returns the complete record including title, description, AIVSS score,
    behavioral fingerprint, indicators of compromise, OWASP MCP mapping,
    and remediation steps.

    Args:
        ave_id: AVE ID in the format AVE-2026-NNNNN (e.g. AVE-2026-00001)
    """
    ave_id = ave_id.strip().upper()
    if not ave_id.startswith("AVE-"):
        return "Error: AVE ID must be in the format AVE-2026-NNNNN"

    data = _piranha_get(f"/records/{ave_id}")

    if data.get("error"):
        return f"Error: {data['error']}"

    aivss = data.get("aivss_score", data.get("cvss_ai_score", ""))

    lines = [
        f"{data.get('ave_id', '')}  {data.get('title', '')}",
        f"Severity:     {data.get('severity', '')}  AIVSS {aivss}",
        f"Attack class: {data.get('attack_class', '')}",
        f"Component:    {data.get('component_type', '')}",
        f"Status:       {data.get('status', '')}",
        "",
        "Description:",
        f"  {data.get('description', '')}",
        "",
        "Behavioral fingerprint:",
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
def search_ave(query: str, limit: int = 10) -> str:
    """
    Search AVE records by keyword.

    Searches across AVE ID, title, attack class, description, and
    behavioral fingerprint. Returns matching records with severity,
    AIVSS score, and a link to the full record.

    Args:
        query: Search term (e.g. "tool poisoning", "credential", "MCP01")
        limit: Maximum number of results (default 10, max 20)
    """
    limit = min(limit, 20)
    data = _piranha_get(
        f"/records/search?q={urllib.parse.quote(query)}&limit={limit}"
    )

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
        aivss = r.get("aivss_score", r.get("cvss_ai_score", 0))
        owasp_mcp = ", ".join(r.get("owasp_mcp", []))
        lines.append(f"[{severity} AIVSS {aivss}] {ave_id}  {title}")
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

    data = _piranha_get(f"/records?{'&'.join(params)}")

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
        aivss = r.get("aivss_score", r.get("cvss_ai_score", 0))
        owasp_mcp_val = ", ".join(r.get("owasp_mcp", []))
        lines.append(f"[{severity_val} AIVSS {aivss}] {ave_id}  {title}")
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
    try:
        result = subprocess.run(  # nosec B603  # noqa: S603
            ["bawbel", "check-pins", path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "Error: pin check timed out"
    except FileNotFoundError:
        return "Error: bawbel CLI not found. Install with: pip install bawbel-scanner"

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

    if not drifted:
        return f"Clean: all {pinned} pinned files match their stored hashes."

    lines = [f"DRIFT DETECTED: {len(drifted)} of {pinned} files changed", ""]
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
        "AVE Standard: https://github.com/bawbel/bawbel-ave",
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