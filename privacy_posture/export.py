"""CSV export of an assessment result.

A full, multi-section report — summary, compliance-by-law, findings, and
third parties — rather than just a bare findings table, so the exported
file actually reflects everything the dashboard shows."""
from __future__ import annotations

import csv
import io

# Characters that Excel/Sheets/LibreOffice interpret as the start of a formula
# (or, for tab/CR, use to smuggle one past naive checks) when a CSV cell
# begins with one of them. CWE-1236 (CSV/formula injection). No field in this
# export currently CAN start with assessed-site-controlled content — every
# caller prefixes with static text — but that's an emergent property of how
# the fields happen to be built today, not something this function enforces
# on its own, so a future change that stops holding that invariant would
# silently reopen this. Defusing unconditionally costs nothing and doesn't
# rely on every call site staying careful forever.
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _flatten(value) -> str:
    """Collapse embedded newlines to a single-line cell. A finding's evidence
    can legitimately contain a list of beacon URLs, one per line — valid as a
    quoted multi-line CSV cell per RFC 4180, but it makes the file look
    truncated/broken when skimmed in a plain text editor or a spreadsheet
    app that doesn't render tall wrapped cells clearly. One finding = one
    visual row is worth more than preserving the original line breaks."""
    s = "" if value is None else str(value)
    return s.replace("\r\n", " | ").replace("\n", " | ").replace("\r", " | ")


def _cell(value) -> str:
    s = _flatten(value)
    if s.startswith(_FORMULA_TRIGGERS):
        return "'" + s
    return s


def _defuse(value) -> str:
    """Kept for callers/tests that only need the formula-injection guard
    without line-flattening (e.g. a value that's never multi-line)."""
    s = "" if value is None else str(value)
    if s.startswith(_FORMULA_TRIGGERS):
        return "'" + s
    return s


def findings_to_csv(result: dict) -> str:
    """Render a result dict (from PrivacyPostureAssessor.analyze) as a CSV
    report: a one-page summary, compliance-by-law scores, every finding (one
    row each, no exceptions — including when scanning turned up none), and
    the third-party inventory."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    site = result.get("site") or {}
    kpi = result.get("kpi") or {}

    writer.writerow(["DKCISSP Privacy Posture Assessment"])
    writer.writerow(["Domain", _cell(result.get("domain", ""))])
    writer.writerow(["Risk", _cell(result.get("risk", ""))])
    writer.writerow(["Score", _cell(result.get("score", ""))])
    writer.writerow(["Scan Mode", _cell(result.get("scan_mode", ""))])
    writer.writerow(["HTTPS", "Yes" if site.get("https") else "No"])
    writer.writerow(["HSTS", "Yes" if site.get("hsts") else "No"])
    writer.writerow(["Consent Banner", "Yes" if site.get("banner") else "No"])
    writer.writerow(["CMP", _cell(site.get("cmp") or "")])
    writer.writerow(["Third Parties", kpi.get("trackers", 0)])
    writer.writerow(["Pre-consent Cookies", kpi.get("preconsent", 0)])
    writer.writerow(["Forms Found", kpi.get("forms", 0)])
    writer.writerow(["Critical Findings", kpi.get("criticals", 0)])
    writer.writerow([])

    laws = result.get("laws") or []
    law_scores = result.get("law_scores") or {}
    if laws:
        writer.writerow(["Compliance by Law"])
        writer.writerow(["Law", "Score"])
        for law in laws:
            writer.writerow([_cell(law), law_scores.get(law, "")])
        writer.writerow([])

    writer.writerow(["Findings"])
    writer.writerow(["Severity", "Finding", "Detail", "Evidence", "Laws", "Remediation Steps"])
    findings = result.get("findings") or []
    if not findings:
        writer.writerow(["info", "No privacy issues detected", "", "", "", ""])
    else:
        for f in findings:
            writer.writerow([
                _cell(f.get("sev", "")), _cell(f.get("title", "")), _cell(f.get("detail", "")),
                _cell(f.get("evidence", "")), _cell("; ".join(f.get("laws") or [])),
                _cell(f.get("fix", "")),
            ])

    third_parties = result.get("third_parties") or []
    if third_parties:
        writer.writerow([])
        writer.writerow(["Third Parties"])
        writer.writerow(["Name", "Category", "Trap-and-Trace", "Wiretap"])
        for t in third_parties:
            writer.writerow([
                _cell(t.get("name", "")), _cell(t.get("category", "")),
                "Yes" if t.get("trap_trace") else "No",
                "Yes" if t.get("wiretap") else "No",
            ])

    return buf.getvalue()
