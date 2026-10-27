"""CSV export of an assessment result — one row per finding."""
from __future__ import annotations

import csv
import io

_HEADER = ["Domain", "Risk", "Score", "Scan Mode", "Severity", "Finding", "Detail",
          "Evidence", "Laws", "Remediation Steps"]

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


def _defuse(value) -> str:
    s = "" if value is None else str(value)
    if s.startswith(_FORMULA_TRIGGERS):
        return "'" + s
    return s


def findings_to_csv(result: dict) -> str:
    """Render a result dict (from PrivacyPostureAssessor.analyze) as CSV text,
    one row per finding (or a single informational row if there are none)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_HEADER)

    domain = result.get("domain", "")
    risk = result.get("risk", "")
    score = result.get("score", "")
    scan_mode = result.get("scan_mode", "")
    findings = result.get("findings") or []

    if not findings:
        writer.writerow([_defuse(domain), _defuse(risk), _defuse(score), _defuse(scan_mode),
                         "info", "No privacy issues detected", "", "", "", ""])
    else:
        for f in findings:
            writer.writerow([_defuse(v) for v in (
                domain, risk, score, scan_mode,
                f.get("sev", ""), f.get("title", ""), f.get("detail", ""),
                f.get("evidence", ""), "; ".join(f.get("laws") or []), f.get("fix", ""),
            )])
    return buf.getvalue()
