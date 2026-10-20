"""AveSource: API first, published corpus as cache and fallback. No network."""

from bawbel_mcp.ave_source import (
    SOURCE_API,
    SOURCE_CORPUS,
    AveSource,
    FetchError,
    matches_component,
    search_records,
)

API = "https://api.test"
CORPUS = "https://corpus.test/ave.json"
REC1 = {"ave_id": "AVE-2026-00001", "title": "External fetch", "severity": "HIGH"}
REC2 = {"ave_id": "AVE-2026-00002", "title": "Tool poisoning", "severity": "MEDIUM"}


class FakeFetch:
    """Maps URL to (data, error) and records every call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url, max_bytes):
        self.calls.append(url)
        return self.routes.get(url, (None, FetchError("HTTP 503", 503)))


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def make(routes, clock=None, ttl=60):
    fetch = FakeFetch(routes)
    src = AveSource(API, CORPUS, ttl_sec=ttl, max_bytes=1000, fetch=fetch, clock=clock or Clock())
    return src, fetch


def test_record_from_api():
    src, _ = make({f"{API}/records/AVE-2026-00001": (REC1, None)})
    res = src.record("AVE-2026-00001")
    assert res.data == REC1 and res.source == SOURCE_API and res.error is None


def test_record_falls_back_to_corpus_when_api_is_down():
    src, _ = make({CORPUS: ([REC1, REC2], None)})
    res = src.record("AVE-2026-00002")
    assert res.data == REC2 and res.source == SOURCE_CORPUS
    assert "HTTP 503" in res.note


def test_record_404_is_not_found_without_fallback():
    src, fetch = make({f"{API}/records/AVE-2026-09999": (None, FetchError("HTTP 404", 404))})
    res = src.record("AVE-2026-09999")
    assert res.error == "AVE-2026-09999 not found"
    assert CORPUS not in fetch.calls


def test_both_sources_down_is_an_error_not_an_exception():
    src, _ = make({})
    res = src.record("AVE-2026-00001")
    assert res.data is None
    assert "API (HTTP 503)" in res.error and "published corpus (HTTP 503)" in res.error


def test_search_from_api_and_corpus_fallback():
    src, _ = make({f"{API}/search?q=tool": ([REC2], None)})
    assert src.search("tool").data == [REC2]
    src, _ = make({CORPUS: ([REC1, REC2], None)})
    res = src.search("POISON")
    assert res.data == [REC2] and res.source == SOURCE_CORPUS


def test_corpus_is_cached_for_the_ttl_then_refreshed():
    clock = Clock()
    src, fetch = make({CORPUS: ([REC1], None)}, clock=clock, ttl=60)
    src.records()
    src.records()
    assert fetch.calls.count(CORPUS) == 1
    clock.now = 61
    src.records()
    assert fetch.calls.count(CORPUS) == 2


def test_stale_corpus_served_when_refresh_fails():
    clock = Clock()
    src, fetch = make({CORPUS: ([REC1], None)}, clock=clock, ttl=60)
    assert src.records().data == [REC1]
    fetch.routes = {}
    clock.now = 61
    res = src.records()
    assert res.data == [REC1] and res.error is None


def test_corpus_object_with_records_key_and_bad_format():
    src, _ = make({CORPUS: ({"records": [REC1]}, None)})
    assert src.records().data == [REC1]
    src, _ = make({CORPUS: ({"unexpected": True}, None)})
    assert "unexpected corpus format" in src.records().error


def test_helpers():
    assert search_records([REC1, REC2], "aVe-2026-00001") == [REC1]
    assert matches_component("mcp_server", "mcp")
    assert matches_component("skill", "SKILL")
    assert not matches_component("mcpx", "mcp")
    assert not matches_component(None, "skill")
