"""
Bawbel MCP Server - configuration.

The one place for outbound endpoints and limits. Each value can be overridden from the
environment; a value that is not valid is ignored with a warning and the default is used.
The variable names match bawbel-scanner's where the setting is the same.
"""

import logging
import os
import re
from importlib.metadata import PackageNotFoundError, version
from typing import Optional
from urllib.parse import quote, urlsplit

log = logging.getLogger(__name__)

# host or host:port: letters, digits, dots, and hyphens only. No credentials, spaces, or quotes.
_HOST_PORT = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


def env_http_url(var: str) -> Optional[str]:
    """Return the http(s) URL in environment variable var, normalised, or None.

    The value must parse as http(s) with a plain host[:port]. The result is rebuilt from
    scheme, host, and percent-encoded path, without query, fragment, or trailing slash.
    None when var is unset or empty, or when the value does not qualify (logged).
    """
    raw = (os.environ.get(var) or "").strip()
    if not raw:
        return None
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme in ("http", "https") and _HOST_PORT.match(parts.netloc):
        return f"{scheme}://{parts.netloc}{quote(parts.path, safe='/%')}".rstrip("/")
    log.warning("Ignoring %s: not an http(s) URL", var)
    return None


def env_int(var: str, default: int, minimum: int = 1) -> int:
    """Return the integer in environment variable var, or default when unset or invalid."""
    raw = (os.environ.get(var) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = minimum - 1
    if value < minimum:
        log.warning("Ignoring %s: not an integer >= %d; using %d", var, minimum, default)
        return default
    return value


def _package_version() -> str:
    try:
        return version("bawbel-mcp")
    except PackageNotFoundError:
        return "unknown"


# ── Endpoints ─────────────────────────────────────────────────────────────────

# AVE API: records at {AVE_API_URL}/records/{ave_id}, search at {AVE_API_URL}/search?q=.
AVE_API_URL_DEFAULT = "https://api.aveproject.org"
AVE_API_URL = env_http_url("BAWBEL_AVE_API_URL") or AVE_API_URL_DEFAULT

# The published AVE corpus: the fallback when the API is unavailable, and the source for
# list and stats, which the API cannot filter.
AVE_CORPUS_URL_DEFAULT = (
    "https://raw.githubusercontent.com/aveproject/ave/main/dist/ave-records-latest.json"
)
AVE_CORPUS_URL = env_http_url("BAWBEL_AVE_CORPUS_URL") or AVE_CORPUS_URL_DEFAULT

# The AVE project (standard and records), for links in replies.
AVE_PROJECT_URL = "https://github.com/aveproject/ave"

# ── Limits ────────────────────────────────────────────────────────────────────

HTTP_TIMEOUT_SEC = env_int("BAWBEL_HTTP_TIMEOUT_SEC", 10)
AVE_CORPUS_TTL_SEC = env_int("BAWBEL_AVE_CORPUS_TTL_SEC", 3600)
# JSON from the AVE API or corpus. The full corpus is about 0.7 MB (87 records, 2026-10).
MAX_API_RESPONSE_BYTES = env_int("BAWBEL_MAX_API_RESPONSE_BYTES", 4 * 1024 * 1024)
# Content fetched for scanning (server cards).
MAX_CONTENT_BYTES = 100 * 1024

# ── Identity ──────────────────────────────────────────────────────────────────

USER_AGENT = f"bawbel-mcp/{_package_version()} (+https://github.com/bawbel/bawbel-mcp)"


def ave_record_url(ave_id: str) -> str:
    """Link to one AVE record."""
    return f"{AVE_API_URL}/records/{quote(ave_id, safe='')}"
