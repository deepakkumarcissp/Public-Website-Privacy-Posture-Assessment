from privacy_posture import engine, headless, vendors

INERT_HTML = ('<html><body><script type="text/plain" class="optanon-category-C0002" '
              'src="https://assets.adobedtm.com/launch.js"></script>'
              '<script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script></body></html>')


def test_detect_fired_ignores_html_and_cmp():
    assert vendors.detect_fired([]) == set()
    assert vendors.detect_fired(["https://cdn.cookielaw.org/consent/x.json"]) == set()
    assert "Adobe Analytics / Experience Cloud" in vendors.detect_fired(["https://x.demdex.net/id"])


def _scan(monkeypatch, requests_seen):
    monkeypatch.setattr(engine, "_resolve_pinned_ip", lambda h: "93.184.216.34")
    monkeypatch.setattr(headless, "available", lambda: True)
    monkeypatch.setattr(headless, "scan", lambda *a, **k: {
        "ok": True, "html": INERT_HTML, "final_url": "https://example.test/",
        "pre_requests": requests_seen, "pre_cookies": [], "consent": {"banner": True,
        "reject_present": True, "granular_present": True}, "doc_headers": {}})
    monkeypatch.setattr(engine.PrivacyPostureAssessor, "_analyze_policy", lambda self, u: {"found": False, "missing": []})
    return engine.PrivacyPostureAssessor({"headless": True}).analyze("example.test")


def test_gated_tracker_in_html_is_not_critical(monkeypatch):
    res = _scan(monkeypatch, ["https://cdn.cookielaw.org/consent/x.json"])
    sevs = {f["sev"] for f in res["findings"] if f["type"] in ("pre_consent_tracking", "trap_trace")}
    assert "critical" not in sevs


def test_tracker_with_real_request_is_critical(monkeypatch):
    res = _scan(monkeypatch, ["https://dpm.demdex.net/id?x=1"])
    assert any(f["sev"] == "critical" and f["type"] == "pre_consent_tracking" for f in res["findings"])
