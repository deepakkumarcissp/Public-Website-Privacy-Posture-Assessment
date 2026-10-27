"""CSV export of an assessment result — one row per finding."""
from __future__ import annotations

import csv
import io

_HEADER = ["Domain", "Risk", "Score", "Scan Mode", "Severity", "Finding", "Detail",
          "Evidence", "Laws", "Remediation Steps"]


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
        writer.writerow([domain, risk, score, scan_mode, "info",
                         "No privacy issues detected", "", "", "", ""])
    else:
        for f in findings:
            writer.writerow([
                domain, risk, score, scan_mode,
                f.get("sev", ""), f.get("title", ""), f.get("detail", ""),
                f.get("evidence", ""), "; ".join(f.get("laws") or []), f.get("fix", ""),
            ])
    return buf.getvalue()
