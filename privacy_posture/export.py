"""Report export: a structured, multi-sheet .xlsx report built entirely from
one assessment's result dict -- no company name, branding, or data beyond
what PrivacyPostureAssessor.analyze() already computed for the assessed
domain. Three sheets: a Dashboard (KPIs, compliance-by-law, a live
remediation-progress rollup), a Remediation Tracker (every finding's fix
steps broken into one developer task per row, with Owner/Status/Priority/Due
Date/%Complete/Notes columns left for the user to fill in), and Third
Parties."""
from __future__ import annotations

import datetime
import io

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule, ColorScaleRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

NAVY = "142238"
NAVY_SOFT = "1E2F4D"
ACCENT = "2F5FE0"
CRITICAL = "C0392B"
HIGH = "D97706"
MEDIUM = "D4A72C"
LOW = "2E7D32"
LIGHT_BG = "F4F6FA"
BORDER_CLR = "D7DCE5"
WHITE = "FFFFFF"
TEXT = "15202E"
MUTED = "6B7686"

_THIN = Side(style="thin", color=BORDER_CLR)
_BOX = Border(left=_THIN, right=_THIN, top=_THIN, bottom=_THIN)

_SEV_COLOR = {"critical": CRITICAL, "high": HIGH, "medium": MEDIUM, "low": LOW}
_SEV_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
_STATUS_OPTIONS = ("Not Started", "In Progress", "Blocked", "Completed")
_STATUS_FILL = {"Not Started": "EAECEF", "In Progress": "FEF3C7",
                "Blocked": "FDE2E1", "Completed": "D6F2DD"}

# Characters that Excel/Sheets interpret as the start of a formula (or, for
# tab/CR, use to smuggle one past naive checks) when a cell begins with one
# of them (CWE-1236). Every string written into this report can originate
# from the assessed site's own HTML/headers (finding titles, evidence, CMP
# name, tracker names) -- i.e. attacker-controlled -- so every such string is
# defused before it reaches a cell, regardless of how unlikely a given field
# is to start with one of these today.
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _flatten(value) -> str:
    """Collapse embedded newlines (e.g. a multi-line beacon-URL evidence
    block) to a single-line cell so one finding/task renders as one row."""
    s = "" if value is None else str(value)
    return s.replace("\r\n", " | ").replace("\n", " | ").replace("\r", " | ")


def _cell(value) -> str:
    s = _flatten(value)
    if s.startswith(_FORMULA_TRIGGERS):
        return "'" + s
    return s


def _defuse(value) -> str:
    """Formula-injection guard without line-flattening, for values that are
    never multi-line."""
    s = "" if value is None else str(value)
    if s.startswith(_FORMULA_TRIGGERS):
        return "'" + s
    return s


def _style_header(cell, fill=NAVY):
    cell.font = Font(bold=True, size=10, color=WHITE)
    cell.fill = PatternFill("solid", fgColor=fill)
    cell.border = _BOX
    cell.alignment = Alignment(wrap_text=True, vertical="center")


def _build_dashboard(wb: Workbook, result: dict, report_date: str) -> None:
    ws = wb.active
    ws.title = "Dashboard"
    ws.sheet_view.showGridLines = False
    for col, w in {"A": 2.5, "B": 26, "C": 16, "D": 16, "E": 16, "F": 16, "G": 16}.items():
        ws.column_dimensions[col].width = w

    domain = _defuse(result.get("domain", ""))
    site = result.get("site") or {}
    kpi = result.get("kpi") or {}

    ws.merge_cells("B2:G3")
    c = ws["B2"]
    c.value = "DKCISSP Privacy Posture Assessment — Remediation Tracker"
    c.font = Font(bold=True, size=18, color=WHITE)
    c.fill = PatternFill("solid", fgColor=NAVY)
    c.alignment = Alignment(vertical="center", indent=1)
    for col in "CDEFG":
        ws[f"{col}2"].fill = PatternFill("solid", fgColor=NAVY)
        ws[f"{col}3"].fill = PatternFill("solid", fgColor=NAVY)

    ws.merge_cells("B4:G4")
    c = ws["B4"]
    c.value = (f"Domain: {domain}   |   Scan Mode: {_defuse(result.get('scan_mode', '')).title()}   |   "
               f"Report Date: {report_date}")
    c.font = Font(size=9, color=WHITE)
    c.fill = PatternFill("solid", fgColor=NAVY_SOFT)
    c.alignment = Alignment(vertical="center", indent=1)
    for col in "CDEFG":
        ws[f"{col}4"].fill = PatternFill("solid", fgColor=NAVY_SOFT)

    kpis = [
        ("Overall Risk", _defuse(result.get("risk", "")), CRITICAL),
        ("Risk Score", f"{result.get('score', '')} / 100", NAVY),
        ("Critical Findings", kpi.get("criticals", 0), CRITICAL),
        ("Third Parties", kpi.get("trackers", 0), NAVY),
        ("Pre-consent Cookies", kpi.get("preconsent", 0), HIGH),
        ("Forms Found", kpi.get("forms", 0), NAVY),
    ]
    for i, (label, value, color) in enumerate(kpis):
        col = get_column_letter(2 + i)
        ws.merge_cells(f"{col}6:{col}7")
        lab = ws[f"{col}6"]
        lab.value = label
        lab.font = Font(bold=True, size=9, color=MUTED)
        lab.fill = PatternFill("solid", fgColor=LIGHT_BG)
        lab.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.merge_cells(f"{col}8:{col}9")
        val = ws[f"{col}8"]
        val.value = value
        val.font = Font(bold=True, size=16, color=color)
        val.fill = PatternFill("solid", fgColor=WHITE)
        val.alignment = Alignment(horizontal="center", vertical="center")
        for r in (6, 7, 8, 9):
            ws[f"{col}{r}"].border = _BOX

    row = 11
    ws[f"B{row}"] = "Compliance by Law"
    ws[f"B{row}"].font = Font(bold=True, size=13, color=TEXT)
    row += 1
    ws[f"B{row}"], ws[f"C{row}"] = "Law", "Score"
    _style_header(ws[f"B{row}"], NAVY)
    _style_header(ws[f"C{row}"], NAVY)
    laws = result.get("laws") or []
    law_scores = result.get("law_scores") or {}
    law_start = row + 1
    for i, law in enumerate(laws):
        r = law_start + i
        ws[f"B{r}"] = _defuse(law)
        ws[f"C{r}"] = law_scores.get(law, "")
        ws[f"B{r}"].border = _BOX
        ws[f"C{r}"].border = _BOX
        fill = PatternFill("solid", fgColor=WHITE if i % 2 == 0 else LIGHT_BG)
        ws[f"B{r}"].fill = fill
        ws[f"C{r}"].fill = fill
    law_end = max(law_start + len(laws) - 1, law_start)
    if laws:
        ws.conditional_formatting.add(
            f"C{law_start}:C{law_end}",
            ColorScaleRule(start_type="min", start_color="C0392B", mid_type="percentile",
                            mid_value=50, mid_color="D4A72C", end_type="max", end_color="2E7D32"),
        )

    row2 = 11
    ws[f"E{row2}"] = "Findings by Severity"
    ws[f"E{row2}"].font = Font(bold=True, size=13, color=TEXT)
    row2 += 1
    ws[f"E{row2}"], ws[f"F{row2}"] = "Severity", "Count"
    _style_header(ws[f"E{row2}"], NAVY)
    _style_header(ws[f"F{row2}"], NAVY)
    sev_counts = result.get("sev_counts") or {}
    sev_start = row2 + 1
    for i, sev in enumerate(("Critical", "High", "Medium", "Low")):
        count = sev_counts.get(sev)
        if count is None:
            continue
        r = sev_start + i
        ws[f"E{r}"] = sev
        ws[f"F{r}"] = count
        ws[f"E{r}"].border = _BOX
        ws[f"F{r}"].border = _BOX
        ws[f"E{r}"].font = Font(color=_SEV_COLOR.get(sev.lower(), TEXT), bold=True)
        ws[f"F{r}"].font = Font(bold=True)

    row = law_end + 3
    ws[f"B{row}"] = "Remediation Progress (live from 'Remediation Tracker' sheet)"
    ws[f"B{row}"].font = Font(bold=True, size=13, color=TEXT)
    row += 1
    for i, h in enumerate(("Status", "Count", "% of Total")):
        cc = get_column_letter(2 + i)
        ws[f"{cc}{row}"] = h
        _style_header(ws[f"{cc}{row}"], NAVY)
    status_start = row + 1
    for i, status in enumerate(_STATUS_OPTIONS):
        r = status_start + i
        ws[f"B{r}"] = status
        ws[f"C{r}"] = f"=COUNTIF('Remediation Tracker'!$G$4:$G$1000,B{r})"
        ws[f"D{r}"] = f"=IFERROR(C{r}/SUM($C${status_start}:$C${status_start + 3}),0)"
        ws[f"D{r}"].number_format = "0%"
        for cc in ("B", "C", "D"):
            ws[f"{cc}{r}"].border = _BOX
    total_r = status_start + 4
    ws[f"B{total_r}"] = "Total Tasks"
    ws[f"C{total_r}"] = f"=SUM(C{status_start}:C{status_start + 3})"
    ws[f"B{total_r}"].font = Font(bold=True)
    ws[f"C{total_r}"].font = Font(bold=True)
    pct_r = total_r + 1
    ws[f"B{pct_r}"] = "Overall % Complete"
    ws[f"C{pct_r}"] = f"=IFERROR(C{status_start + 3}/C{total_r},0)"
    ws[f"C{pct_r}"].number_format = "0%"
    ws[f"B{pct_r}"].font = Font(bold=True, color=ACCENT)
    ws[f"C{pct_r}"].font = Font(bold=True, color=ACCENT, size=13)


def _build_remediation_tracker(wb: Workbook, result: dict, report_date: str) -> None:
    rt = wb.create_sheet("Remediation Tracker")
    widths = {"A": 5, "B": 10, "C": 38, "D": 52, "E": 30, "F": 14, "G": 14,
              "H": 10, "I": 14, "J": 12, "K": 10, "L": 28}
    for col, w in widths.items():
        rt.column_dimensions[col].width = w

    domain = _defuse(result.get("domain", ""))
    rt.merge_cells("A1:L1")
    rt["A1"] = f"Developer Remediation Tracker — {domain} Privacy Posture Assessment"
    rt["A1"].font = Font(bold=True, size=14, color=WHITE)
    rt["A1"].fill = PatternFill("solid", fgColor=NAVY)
    rt["A1"].alignment = Alignment(vertical="center", indent=1)
    for col in "BCDEFGHIJKL":
        rt[f"{col}1"].fill = PatternFill("solid", fgColor=NAVY)

    rt.merge_cells("A2:L2")
    rt["A2"] = ("Instructions: update Owner, Status, Priority, Due Date, % Complete and Notes "
                "as work progresses. Dashboard totals update automatically.")
    rt["A2"].font = Font(italic=True, size=9, color=MUTED)

    headers = ["ID", "Severity", "Finding", "Remediation Task", "Related Laws", "Owner", "Status",
               "Priority", "Date Identified", "Due Date", "% Complete", "Notes / Blocker"]
    for i, h in enumerate(headers):
        cc = get_column_letter(1 + i)
        rt[f"{cc}3"] = h
        _style_header(rt[f"{cc}3"], NAVY_SOFT)

    findings = result.get("findings") or []
    r = 4
    task_id = 1
    first_data_row = r
    if not findings:
        rt[f"A{r}"] = task_id
        rt[f"B{r}"] = "Info"
        rt[f"C{r}"] = "No privacy issues detected"
        rt[f"G{r}"] = "Completed"
        rt[f"I{r}"] = report_date
        rt[f"K{r}"] = 1
        for i in range(12):
            rt.cell(row=r, column=1 + i).border = _BOX
        r += 1
    else:
        for f in findings:
            sev_raw = (f.get("sev") or "").lower()
            sev_label = sev_raw.capitalize() or "Info"
            steps = f.get("steps") or ([f.get("fix")] if f.get("fix") else [])
            if not steps:
                steps = [""]
            for step in steps:
                rt[f"A{r}"] = task_id
                rt[f"B{r}"] = sev_label
                rt[f"C{r}"] = _cell(f.get("title", ""))
                rt[f"D{r}"] = _cell(step)
                rt[f"E{r}"] = _cell("; ".join(f.get("laws") or []))
                rt[f"F{r}"] = None
                rt[f"G{r}"] = "Not Started"
                rt[f"H{r}"] = _SEV_PRIORITY.get(sev_raw, "P3")
                rt[f"I{r}"] = report_date
                rt[f"J{r}"] = None
                rt[f"K{r}"] = 0
                rt[f"L{r}"] = None
                rt[f"B{r}"].font = Font(bold=True, color=_SEV_COLOR.get(sev_raw, TEXT))
                for i in range(12):
                    cell = rt.cell(row=r, column=1 + i)
                    cell.border = _BOX
                    cell.alignment = Alignment(wrap_text=i in (2, 3), vertical="top")
                    if task_id % 2 == 0:
                        cell.fill = PatternFill("solid", fgColor=LIGHT_BG)
                rt[f"K{r}"].number_format = "0%"
                task_id += 1
                r += 1
    last_data_row = r - 1

    dv = DataValidation(type="list", formula1=f'"{",".join(_STATUS_OPTIONS)}"', allow_blank=False)
    rt.add_data_validation(dv)
    dv.add(f"G{first_data_row}:G{last_data_row}")
    prio_dv = DataValidation(type="list", formula1='"P1,P2,P3,P4"', allow_blank=False)
    rt.add_data_validation(prio_dv)
    prio_dv.add(f"H{first_data_row}:H{last_data_row}")

    for status, color in _STATUS_FILL.items():
        rt.conditional_formatting.add(
            f"G{first_data_row}:G{last_data_row}",
            CellIsRule(operator="equal", formula=[f'"{status}"'], fill=PatternFill("solid", fgColor=color)),
        )

    rt.merge_cells(f"A{r + 1}:J{r + 1}")
    rt[f"A{r + 1}"] = "Totals"
    rt[f"A{r + 1}"].font = Font(bold=True)
    rt[f"K{r + 1}"] = f"=AVERAGE(K{first_data_row}:K{last_data_row})"
    rt[f"K{r + 1}"].number_format = "0%"
    rt[f"K{r + 1}"].font = Font(bold=True)
    rt.freeze_panes = "A4"


def _build_third_parties(wb: Workbook, result: dict) -> None:
    tp = wb.create_sheet("Third Parties")
    for col, w in {"A": 24, "B": 20, "C": 16, "D": 12, "E": 20}.items():
        tp.column_dimensions[col].width = w

    domain = _defuse(result.get("domain", ""))
    tp.merge_cells("A1:E1")
    tp["A1"] = f"Third-Party Trackers — {domain}"
    tp["A1"].font = Font(bold=True, size=14, color=WHITE)
    tp["A1"].fill = PatternFill("solid", fgColor=NAVY)
    for col in "BCDE":
        tp[f"{col}1"].fill = PatternFill("solid", fgColor=NAVY)

    headers = ["Name", "Category", "Trap-and-Trace", "Wiretap", "Consent Gated? (track)"]
    for i, h in enumerate(headers):
        cc = get_column_letter(1 + i)
        tp[f"{cc}2"] = h
        _style_header(tp[f"{cc}2"], NAVY_SOFT)

    third_parties = result.get("third_parties") or []
    if not third_parties:
        tp["A3"] = "No third-party trackers detected"
        for col in "BCDE":
            tp[f"{col}3"].border = _BOX
        tp["A3"].border = _BOX
        return
    for i, t in enumerate(third_parties):
        r = 3 + i
        tp[f"A{r}"] = _cell(t.get("name", ""))
        tp[f"B{r}"] = _cell(t.get("category", ""))
        tp[f"C{r}"] = "Yes" if t.get("trap_trace") else "No"
        tp[f"D{r}"] = "Yes" if t.get("wiretap") else "No"
        tp[f"E{r}"] = "Not Started"
        fill = PatternFill("solid", fgColor=WHITE if i % 2 == 0 else LIGHT_BG)
        for col in "ABCDE":
            tp[f"{col}{r}"].border = _BOX
            tp[f"{col}{r}"].fill = fill
        if t.get("trap_trace"):
            tp[f"C{r}"].font = Font(color=CRITICAL, bold=True)


def findings_to_xlsx(result: dict) -> bytes:
    """Render a result dict (from PrivacyPostureAssessor.analyze) as a 3-sheet
    .xlsx report: Dashboard, Remediation Tracker (one task row per fix step,
    no exceptions -- including when scanning turned up no findings at all),
    and Third Parties. Contains only the assessed domain's own data -- no
    company name, logo, or confidential data is ever baked into the file
    beyond what the scan itself produced."""
    report_date = datetime.date.today().isoformat()
    wb = Workbook()
    _build_dashboard(wb, result, report_date)
    _build_remediation_tracker(wb, result, report_date)
    _build_third_parties(wb, result)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
