"""
Bawbel MCP Server - AVE record source.

Lookups and searches go to the AVE API first. When the API is unavailable (5xx, timeout,
network error) they fall back to the published AVE corpus, which is fetched once and
cached for AVE_CORPUS_TTL_SEC. List and stats use the cached corpus, because the API
cannot filter. Every result says which source it came from.

Nothing here raises to the caller: every failure comes back as an error string.
"""

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

from bawbel_mcp import config

SOURCE_API = "AVE API"
SOURCE_CORPUS = "published AVE corpus"

# Fields searched locally; the first four are the ones ave-api's /search uses.
SEARCH_FIELDS = ("title", "description", "attack_class", "behavioral_fingerprint", "ave_id")


@dataclass
class FetchError:
    """Why a fetch failed. status is the HTTP status, or None for a network-level error."""

    message: str
    status: Optional[int] = None

    @property
    def is_not_found(self) -> bool:
        return self.status == 404


@dataclass
class Result:
    """Data from one source, or an error. note explains a fallback when one happened."""

    data: Any = None
    source: str = ""
    error: Optional[str] = None
    note: Optional[str] = None


def http_get_json(url: str, max_bytes: int) -> tuple[Any, Optional[FetchError]]:
    """GET url and parse JSON. Never raises; a body larger than max_bytes is an error."""
    req = urllib.request.Request(
        url, headers={"User-Agent": config.USER_AGENT, "Accept": "application/json"}
    )
    try:
        # B310/S310: url is built from config, which only admits http(s) URLs.
        timeout = config.HTTP_TIMEOUT_SEC
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310  # noqa: S310
            body = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as e:
        return None, FetchError(f"HTTP {e.code}", e.code)
    except urllib.error.URLError as e:
        return None, FetchError(f"network error: {e.reason}")
    except (TimeoutError, OSError) as e:
        return None, FetchError(f"network error: {type(e).__name__}")
    if len(body) > max_bytes:
        return None, FetchError(f"response larger than {max_bytes} bytes")
    try:
        return json.loads(body), None
    except ValueError:
        return None, FetchError("response is not valid JSON")


Fetch = Callable[[str, int], tuple[Any, Optional[FetchError]]]


class AveSource:
    """AVE records from the API, with the published corpus as cache and fallback."""

    def __init__(
        self,
        api_url: str = config.AVE_API_URL,
        corpus_url: str = config.AVE_CORPUS_URL,
        ttl_sec: int = config.AVE_CORPUS_TTL_SEC,
        max_bytes: int = config.MAX_API_RESPONSE_BYTES,
        fetch: Fetch = http_get_json,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._api_url = api_url
        self._corpus_url = corpus_url
        self._ttl = ttl_sec
        self._max_bytes = max_bytes
        self._fetch = fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._corpus: Optional[list[dict]] = None
        self._corpus_at = 0.0

    # ── Corpus ────────────────────────────────────────────────────────────────

    def _load_corpus(self) -> tuple[Optional[list[dict]], Optional[str]]:
        """The cached corpus, refreshed after the TTL. A stale copy beats no copy."""
        with self._lock:
            fresh = self._corpus is not None and self._clock() - self._corpus_at < self._ttl
            if fresh:
                return self._corpus, None
            data, err = self._fetch(self._corpus_url, self._max_bytes)
            records = data.get("records") if isinstance(data, dict) else data
            if err is None and isinstance(records, list):
                self._corpus = [r for r in records if isinstance(r, dict)]
                self._corpus_at = self._clock()
                return self._corpus, None
            reason = err.message if err else "unexpected corpus format"
            if self._corpus is not None:
                return self._corpus, None  # serve the stale copy
            return None, reason

    def records(self) -> Result:
        """Every record, from the corpus."""
        corpus, err = self._load_corpus()
        if corpus is None:
            return Result(error=f"AVE records unavailable: published corpus ({err})")
        return Result(data=corpus, source=SOURCE_CORPUS)

    # ── Lookup and search ─────────────────────────────────────────────────────

    def record(self, ave_id: str) -> Result:
        """One record by AVE ID: the API, or the corpus when the API is unavailable."""
        url = f"{self._api_url}/records/{urllib.parse.quote(ave_id, safe='')}"
        data, err = self._fetch(url, self._max_bytes)
        if err is None and isinstance(data, dict):
            return Result(data=data, source=SOURCE_API)
        if err is not None and err.is_not_found:
            return Result(error=f"{ave_id} not found")
        api_reason = err.message if err else "unexpected response format"
        corpus, corpus_err = self._load_corpus()
        if corpus is None:
            return Result(
                error=f"AVE data unavailable: API ({api_reason}), published corpus ({corpus_err})"
            )
        for rec in corpus:
            if rec.get("ave_id") == ave_id:
                return Result(
                    data=rec, source=SOURCE_CORPUS, note=f"AVE API unavailable ({api_reason})"
                )
        return Result(error=f"{ave_id} not found")

    def search(self, query: str) -> Result:
        """Records matching query: the API, or a local search of the corpus."""
        url = f"{self._api_url}/search?q={urllib.parse.quote(query)}"
        data, err = self._fetch(url, self._max_bytes)
        if err is None and isinstance(data, list):
            return Result(data=[r for r in data if isinstance(r, dict)], source=SOURCE_API)
        api_reason = err.message if err else "unexpected response format"
        corpus, corpus_err = self._load_corpus()
        if corpus is None:
            return Result(
                error=f"AVE data unavailable: API ({api_reason}), published corpus ({corpus_err})"
            )
        return Result(
            data=search_records(corpus, query),
            source=SOURCE_CORPUS,
            note=f"AVE API unavailable ({api_reason})",
        )


def search_records(records: list[dict], query: str) -> list[dict]:
    """Case-insensitive substring match over SEARCH_FIELDS."""
    needle = query.lower()
    return [r for r in records if any(needle in str(r.get(f, "")).lower() for f in SEARCH_FIELDS)]


def matches_component(value: Optional[str], wanted: str) -> bool:
    """component_type filter: exact, or a prefix family ("mcp" matches "mcp_server")."""
    value = (value or "").lower()
    wanted = wanted.lower()
    return value == wanted or value.startswith(wanted + "_")


SOURCE = AveSource()
