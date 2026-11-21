"""Configuration: endpoints and limits from the environment, validated."""

import logging

import pytest

from bawbel_mcp.config import AVE_API_URL_DEFAULT, ave_record_url, env_http_url, env_int


def test_defaults():
    assert AVE_API_URL_DEFAULT == "https://api.aveproject.org"
    assert ave_record_url("AVE-2026-00004").endswith("/records/AVE-2026-00004")


def test_env_url_normalised(monkeypatch):
    monkeypatch.setenv("BAWBEL_TEST_URL", " HTTPS://ave.example.org/api/v1/?q=1#f ")
    assert env_http_url("BAWBEL_TEST_URL") == "https://ave.example.org/api/v1"


def test_env_url_unset_is_none(monkeypatch):
    monkeypatch.delenv("BAWBEL_TEST_URL", raising=False)
    assert env_http_url("BAWBEL_TEST_URL") is None


@pytest.mark.parametrize(
    "value",
    ["file:///etc/passwd", "ftp://x.example", "https://", 'https://x" y', "https://u:p@host"],
)
def test_env_url_invalid_is_ignored_with_a_warning(monkeypatch, caplog, value):
    monkeypatch.setenv("BAWBEL_TEST_URL", value)
    with caplog.at_level(logging.WARNING):
        assert env_http_url("BAWBEL_TEST_URL") is None
    assert "BAWBEL_TEST_URL" in caplog.text


@pytest.mark.parametrize("value,expected", [("25", 25), ("", 10), ("abc", 10), ("0", 10)])
def test_env_int(monkeypatch, value, expected):
    monkeypatch.setenv("BAWBEL_TEST_INT", value)
    assert env_int("BAWBEL_TEST_INT", 10) == expected
