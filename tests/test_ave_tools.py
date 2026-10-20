"""The AVE tools and the stats resource, over a fake source. No network."""

import pytest

from bawbel_mcp import ave_source, server
from bawbel_mcp.ave_source import SOURCE_API, SOURCE_CORPUS, Result

REC = {
    "ave_id": "AVE-2026-00004",
    "title": "Shell pipe injection",
    "severity": "HIGH",
    "aivss_score": 8.8,
    "component_type": "mcp_server",
    "owasp_asi": ["ASI01"],
    "owasp_mcp": ["MCP05"],
    "remediation": "Remove the pipe.",
    "indicators_of_compromise": ["curl | bash"],
}
REC_SKILL = {
    "ave_id": "AVE-2026-00001",
    "title": "Fetch",
    "severity": "MEDIUM",
    "component_type": "skill",
    "owasp_mcp": ["MCP03"],
}


class FakeSource:
    def __init__(self, record=None, search=None, records=None):
        self._record, self._search, self._records = record, search, records

    def record(self, ave_id):
        return self._record

    def search(self, query):
        return self._search

    def records(self):
        return self._records


@pytest.fixture
def use(monkeypatch):
    def _use(**kw):
        monkeypatch.setattr(ave_source, "SOURCE", FakeSource(**kw))

    return _use


def test_lookup_formats_the_record_and_names_the_source(use):
    use(record=Result(data=REC, source=SOURCE_API))
    out = server.lookup_ave("ave-2026-00004")
    assert "AVE-2026-00004  Shell pipe injection" in out
    assert "OWASP ASI:  ASI01" in out and "Remove the pipe." in out
    assert "/records/AVE-2026-00004" in out and "Source: AVE API" in out


def test_lookup_fallback_note_and_errors(use):
    use(record=Result(data=REC, source=SOURCE_CORPUS, note="AVE API unavailable (HTTP 503)"))
    assert "fallback: AVE API unavailable (HTTP 503)" in server.lookup_ave("AVE-2026-00004")
    use(record=Result(error="AVE data unavailable: API (HTTP 503), published corpus (HTTP 503)"))
    assert server.lookup_ave("AVE-2026-00004").startswith("Error: AVE data unavailable")
    assert server.lookup_ave("CVE-1").startswith("Error: AVE ID must be")


def test_search_applies_the_limit_here(use):
    use(search=Result(data=[REC] * 30, source=SOURCE_API))
    out = server.search_ave("pipe", limit=50)
    assert "Found 30 record(s) for 'pipe' (showing 20)" in out
    use(search=Result(data=[], source=SOURCE_API))
    assert "No AVE records found" in server.search_ave("nothing")
    assert server.search_ave("   ").startswith("Error: query must not be empty")


def test_list_filters_locally(use):
    use(records=Result(data=[REC, REC_SKILL], source=SOURCE_CORPUS))
    out = server.list_ave(component_type="mcp")
    assert "AVE-2026-00004" in out and "AVE-2026-00001" not in out
    out = server.list_ave(severity="medium", owasp_mcp="mcp03")
    assert "AVE-2026-00001" in out and "AVE-2026-00004" not in out
    assert "Source: published AVE corpus" in out
    assert "No AVE records found" in server.list_ave(severity="CRITICAL")


def test_stats_counts_and_states_what_is_unavailable(use):
    use(records=Result(data=[REC, REC_SKILL, REC], source=SOURCE_CORPUS))
    out = server.ave_stats()
    assert "AVE Records: 3" in out and "HIGH:     2" in out and "MEDIUM:   1" in out
    assert "Registry scan data: unavailable: PiranhaDB is offline" in out
    use(records=Result(error="AVE records unavailable: published corpus (HTTP 503)"))
    assert server.ave_stats().startswith("Error: AVE records unavailable")
