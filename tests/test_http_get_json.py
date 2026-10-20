"""http_get_json: bounded reads, timeouts from config, no exceptions."""

import io
import urllib.error
from unittest.mock import MagicMock, patch

from bawbel_mcp import config
from bawbel_mcp.ave_source import http_get_json


def _resp(body: bytes):
    r = MagicMock()
    r.read.side_effect = lambda n: io.BytesIO(body).read(n)
    r.__enter__.return_value = r
    return r


def test_parses_json_with_timeout_and_user_agent():
    with patch(
        "urllib.request.urlopen", return_value=_resp(b'[{"ave_id": "AVE-2026-00001"}]')
    ) as uo:
        data, err = http_get_json("https://api.test/search?q=x", 1000)
    assert err is None and data == [{"ave_id": "AVE-2026-00001"}]
    req = uo.call_args.args[0]
    assert req.get_header("User-agent") == config.USER_AGENT
    assert uo.call_args.kwargs["timeout"] == config.HTTP_TIMEOUT_SEC


def test_oversized_body_is_an_error_not_truncated_json():
    with patch("urllib.request.urlopen", return_value=_resp(b"[" + b"1," * 600 + b"1]")):
        data, err = http_get_json("https://api.test/records", 1000)
    assert data is None and "larger than 1000 bytes" in err.message


def test_http_error_keeps_the_status():
    e = urllib.error.HTTPError("https://api.test", 404, "Not Found", {}, None)
    with patch("urllib.request.urlopen", side_effect=e):
        data, err = http_get_json("https://api.test/records/X", 1000)
    assert data is None and err.status == 404 and err.is_not_found


def test_network_errors_and_bad_json():
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
        assert "network error" in http_get_json("https://api.test", 1000)[1].message
    with patch("urllib.request.urlopen", side_effect=TimeoutError()):
        assert "TimeoutError" in http_get_json("https://api.test", 1000)[1].message
    with patch("urllib.request.urlopen", return_value=_resp(b"<html>503</html>")):
        assert "not valid JSON" in http_get_json("https://api.test", 1000)[1].message
