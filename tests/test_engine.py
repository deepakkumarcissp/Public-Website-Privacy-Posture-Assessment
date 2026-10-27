"""Tests for the DKCISSP Privacy Posture Assessment engine.

Unit tests (vendor detection, clause mapping) run fully offline. The
integration test hits example.com (IANA's reserved documentation/testing
domain — safe to assess, stable, and explicitly meant for this) and is
skipped gracefully if there is no network access in the test environment."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from privacy_posture import PrivacyPostureAssessor
from privacy_posture import vendors as V
from privacy_posture.clauses import enrich
from privacy_posture.engine import _is_safe_target


def test_vendor_detection_google_analytics():
    html = '<script src="https://www.google-analytics.com/analytics.js"></script>'
    hits = V.detect(html)
    names = [h["name"] for h in hits]
    assert "Google Analytics" in names
    ga = next(h for h in hits if h["name"] == "Google Analytics")
    assert ga["trap_trace"] is True
    assert "GDPR" in ga["laws"]


def test_vendor_detection_cmp_not_a_tracker():
    html = '<script src="https://cdn.cookiebot.com/..."></script>'
    hits = V.detect(html)
    cmp_hits = [h for h in hits if h["is_cmp"]]
    assert cmp_hits, "CMP should be detected"
    assert cmp_hits[0]["cmp_label"] == "Cookiebot"


def test_vendor_detection_no_false_positive():
    html = "<p>Just a plain page with no third-party scripts.</p>"
    hits = V.detect(html)
    assert hits == []


def test_clause_enrich_pre_consent_tracking():
    meta = enrich("pre_consent_tracking")
    assert "GDPR" in meta["clauses"]
    assert "CCPA/CPRA" in meta["clauses"]
    assert meta["steps"], "should have remediation steps"


def test_clause_enrich_unknown_type_returns_safe_defaults():
    meta = enrich("not_a_real_finding_type")
    assert meta["clauses"] == {}
    assert meta["steps"] == []


def test_assessor_constructs_without_chromium():
    # In a CI sandbox with no Chrome/Chromium installed, this must not raise
    # and must gracefully fall back to the static scan mode.
    a = PrivacyPostureAssessor(cfg={"headless": True})
    assert isinstance(a.use_headless, bool)


def test_analyze_rejects_empty_input():
    a = PrivacyPostureAssessor()
    result = a.analyze("")
    assert "error" in result


def test_ssrf_blocks_metadata_ip_literal():
    assert _is_safe_target("169.254.169.254") is False


def test_ssrf_blocks_link_local_range():
    assert _is_safe_target("169.254.1.1") is False


def test_ssrf_blocks_userinfo_parser_differential():
    # requests/urllib3 would treat this as a request to 169.254.169.254 with
    # 'evil.com' as discarded userinfo -- our hostname-character check must
    # reject it outright rather than naively resolving 'evil.com'.
    assert _is_safe_target("evil.com@169.254.169.254") is False


def test_ssrf_blocks_unresolvable_host_fail_closed():
    assert _is_safe_target("this-domain-should-never-exist-dkcissp-test.invalid") is False


def test_ssrf_allows_plain_hostname_shape():
    # Shape-only check (no network call needed to prove the regex accepts a
    # normal domain) -- actual resolution is exercised by the network test.
    from privacy_posture.engine import _VALID_HOSTNAME
    assert _VALID_HOSTNAME.match("example.com")
    assert _VALID_HOSTNAME.match("sub.example.co.uk")
    assert not _VALID_HOSTNAME.match("evil.com@169.254.169.254")
    assert not _VALID_HOSTNAME.match("example.com:8080")


@pytest.mark.network
def test_analyze_example_com():
    a = PrivacyPostureAssessor(cfg={"headless": False})
    result = a.analyze("example.com")
    if result.get("error") and not result.get("reachable", True):
        pytest.skip("no network access in this environment")
    assert result["domain"] == "example.com"
    assert "score" in result
    assert "findings" in result
    assert "site" in result
