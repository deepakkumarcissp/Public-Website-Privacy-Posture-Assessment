"""Regression tests for the deep security review: CSV/formula injection
defense, response-size/decompression-bomb capping, and the webapp's
header-based auth, Host check, concurrency limit, and overall deadline."""
import gzip
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from privacy_posture.export import findings_to_csv, _defuse


# ── CSV / formula injection (CWE-1236) ──────────────────────────────────────

@pytest.mark.parametrize("trigger", ["=", "+", "-", "@", "\t", "\r"])
def test_defuse_prefixes_formula_trigger_characters(trigger):
    payload = f"{trigger}cmd|' /C calc'!A1"
    assert _defuse(payload) == "'" + payload


def test_defuse_leaves_normal_text_untouched():
    assert _defuse("No privacy policy found/linked") == "No privacy policy found/linked"
    assert _defuse("") == ""
    assert _defuse(None) == ""
    assert _defuse(42) == "42"


def test_findings_to_csv_defuses_malicious_field():
    result = {
        "domain": "example.com", "risk": "High", "score": 50, "scan_mode": "static",
        "findings": [{"sev": "high", "title": "=HYPERLINK(\"http://evil\",\"x\")",
                     "detail": "detail", "evidence": "", "laws": ["GDPR"], "fix": ""}],
    }
    csv_text = findings_to_csv(result)
    # The cell must be prefixed, so the formula-trigger character is never
    # the first character a spreadsheet application sees in that cell.
    assert "'=HYPERLINK" in csv_text


# ── Response-size cap / decompression-bomb guard ────────────────────────────

def test_capped_get_truncates_oversized_body(monkeypatch):
    from privacy_posture import engine

    class _FakeResponse:
        is_redirect = False
        is_permanent_redirect = False
        headers = {}

        def iter_content(self, chunk_size=65536, **kwargs):
            chunk = b"A" * chunk_size
            # Yield far more than the cap so the loop must stop early.
            for _ in range(1000):
                yield chunk

        def close(self):
            pass

    def _fake_get(url, **kwargs):
        assert kwargs.get("headers", {}).get("Accept-Encoding") == "identity"
        assert kwargs.get("stream") is True
        return _FakeResponse()

    monkeypatch.setattr(engine, "_MAX_BODY_BYTES", 100_000)
    monkeypatch.setattr(engine.requests, "get", _fake_get)
    resp = engine._capped_get("https://example.com/")
    assert len(resp._content) <= 100_000 + 65536  # bounded, not unbounded
    assert resp._content_consumed is True


def test_capped_get_refuses_compression_negotiation(monkeypatch):
    from privacy_posture import engine
    seen = {}

    class _FakeResponse:
        is_redirect = False
        is_permanent_redirect = False
        headers = {}

        def iter_content(self, **kwargs):
            return iter([b"hello"])

        def close(self):
            pass

    def _fake_get(url, **kwargs):
        seen["headers"] = kwargs.get("headers")
        return _FakeResponse()

    monkeypatch.setattr(engine.requests, "get", _fake_get)
    engine._capped_get("https://example.com/")
    assert seen["headers"]["Accept-Encoding"] == "identity"


def test_capped_get_refuses_response_with_non_identity_content_encoding(monkeypatch):
    """A malicious server can ignore our Accept-Encoding request and send a
    compressed body anyway. Since urllib3 decompresses internally during
    iter_content(), a single compressed chunk can expand far beyond our
    chunk_size before our byte-counter ever runs — so the only safe response
    is to refuse to read the body at all once Content-Encoding says it's
    compressed, never attempt to decompress it."""
    from privacy_posture import engine

    class _BombResponse:
        is_redirect = False
        is_permanent_redirect = False
        headers = {"Content-Encoding": "gzip"}
        read_attempted = False

        def iter_content(self, **kwargs):
            self.read_attempted = True
            yield b"should never be read"

        def close(self):
            pass

    resp = _BombResponse()
    monkeypatch.setattr(engine.requests, "get", lambda url, **kw: resp)
    result = engine._capped_get("https://example.com/")
    assert result._content == b""
    assert resp.read_attempted is False


# ── Webapp: cookie auth, Host check, concurrency ────────────────────────────

# The webapp's own Host-header allowlist is built from SERVER_PORT, so tests
# must present a consistent, matching (Host, SERVER_PORT) pair to be treated
# as a legitimate local request — exactly what a real browser hitting the
# real server at this port would send.
_PORT = "1009"
_GOOD_HOST = f"127.0.0.1:{_PORT}"


def _get(client, path, host=_GOOD_HOST):
    return client.get(path, headers={"Host": host}, environ_overrides={"SERVER_PORT": _PORT})


def _post(client, path, json_body, host=_GOOD_HOST, token=None):
    headers = {"Host": host}
    if token is not None:
        headers["X-DKCISSP-Token"] = token
    return client.post(path, json=json_body, headers=headers,
                       environ_overrides={"SERVER_PORT": _PORT})


@pytest.fixture
def client():
    pytest.importorskip("flask")
    from privacy_posture import webapp
    webapp.app.testing = True
    return webapp.app.test_client()


def test_index_embeds_token_without_a_cookie(client):
    from privacy_posture import webapp
    resp = _get(client, "/")
    assert "Set-Cookie" not in resp.headers
    assert webapp._SESSION_TOKEN.encode() in resp.data


def test_api_rejects_request_with_no_token(client):
    resp = _post(client, "/api/assess", {"domain": "example.com"})
    assert resp.status_code == 403


def test_api_rejects_wrong_host_header(client):
    resp = _get(client, "/", host=f"evil.example.com:{_PORT}")
    assert resp.status_code == 403


def test_api_accepts_valid_header_token(client, monkeypatch):
    from privacy_posture import webapp

    def _fake_run(domain, no_headless):
        return {"domain": domain, "risk": "Low", "score": 100, "findings": [],
               "third_parties": [], "site": {}, "kpi": {}}

    monkeypatch.setattr(webapp, "_run_analysis", _fake_run)
    resp = _post(client, "/api/assess", {"domain": "example.com"}, token=webapp._SESSION_TOKEN)
    assert resp.status_code == 200


def test_assess_endpoint_rejects_concurrent_second_request(client):
    from privacy_posture import webapp

    # Hold the slot as if a scan were already in progress.
    assert webapp._scan_slot.acquire(blocking=False)
    try:
        resp = _post(client, "/api/assess", {"domain": "example.com"}, token=webapp._SESSION_TOKEN)
        assert resp.status_code == 429
    finally:
        webapp._scan_slot.release()


def test_assess_respects_overall_deadline(client, monkeypatch):
    from privacy_posture import webapp

    def _hang(domain, no_headless):
        time.sleep(10)
        return {"domain": domain, "risk": "Low", "score": 100, "findings": []}

    monkeypatch.setattr(webapp, "_run_analysis", _hang)
    monkeypatch.setattr(webapp, "_ANALYSIS_DEADLINE_S", 0.2)
    resp = _post(client, "/api/assess", {"domain": "example.com"}, token=webapp._SESSION_TOKEN)
    assert resp.status_code == 422
    assert "timed out" in resp.get_json()["error"]
    # The slot must be free again for the next request even though the
    # abandoned analysis thread is (harmlessly) still finishing in the background.
    assert webapp._scan_slot.acquire(blocking=False)
    webapp._scan_slot.release()


def test_assess_error_does_not_leak_exception_text(client, monkeypatch):
    from privacy_posture import webapp

    def _raise(*a, **kw):
        raise RuntimeError("/etc/shadow secret internal path leak")

    monkeypatch.setattr(webapp.PrivacyPostureAssessor, "analyze", _raise)
    resp = _post(client, "/api/assess", {"domain": "example.com"}, token=webapp._SESSION_TOKEN)
    assert b"/etc/shadow" not in resp.data
    assert b"internal error" in resp.data.lower()
