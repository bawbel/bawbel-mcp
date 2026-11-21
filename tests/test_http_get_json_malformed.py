"""http_get_json and AveSource when the API sends a malformed HTTP reply.

A real urllib request goes to a loopback server that writes bytes no HTTP client accepts.
Nothing leaves 127.0.0.1, so the tests run offline. Without the fix, http.client raises
BadStatusLine or IncompleteRead out of http_get_json and the corpus fallback never runs.
"""

import socketserver
import threading

import pytest

from bawbel_mcp.ave_source import SOURCE_CORPUS, AveSource, http_get_json

REC = {"ave_id": "AVE-2026-00001", "title": "External fetch", "severity": "HIGH"}
CORPUS_BODY = b'[{"ave_id": "AVE-2026-00001", "title": "External fetch", "severity": "HIGH"}]'
CAP = 10_000


class _Handler(socketserver.BaseRequestHandler):
    """Answer by the first path segment: bad-status, bad-chunk or corpus."""

    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        kind = data.split(b" ", 2)[1].decode().split("/")[1]
        if kind == "bad-status":
            reply = b"garbage\r\n\r\n"
        elif kind == "bad-chunk":
            # A chunked body whose first chunk size is not hexadecimal.
            reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nabc\r\n0\r\n\r\n"
        else:
            reply = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(CORPUS_BODY)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + CORPUS_BODY
            )
        self.request.sendall(reply)


class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture
def loopback():
    server = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _check_error_and_fallback(base, kind):
    data, err = http_get_json(f"{base}/{kind}/records/{REC['ave_id']}", CAP)
    assert data is None and err is not None and err.status is None
    assert err.message.startswith("network error:")

    source = AveSource(f"{base}/{kind}", f"{base}/corpus", ttl_sec=60, max_bytes=CAP)
    res = source.record(REC["ave_id"])
    assert res.error is None
    assert res.source == SOURCE_CORPUS and res.data == REC
    assert "AVE API unavailable" in res.note
    return err


def test_invalid_status_line_is_an_error_and_the_corpus_fallback_runs(loopback):
    err = _check_error_and_fallback(loopback, "bad-status")
    assert "BadStatusLine" in err.message


def test_invalid_chunk_size_is_an_error_and_the_corpus_fallback_runs(loopback):
    err = _check_error_and_fallback(loopback, "bad-chunk")
    assert "IncompleteRead" in err.message
