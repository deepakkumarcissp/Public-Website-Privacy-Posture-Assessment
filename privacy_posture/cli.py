"""Command-line interface for the Public Website Privacy Posture Assessment."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import PrivacyPostureAssessor
from .export import findings_to_csv


def _print_human(result: dict) -> None:
    if result.get("error"):
        print(f"error: {result['error']}", file=sys.stderr)
        return
    sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
    print("=" * 72)
    print(f"{result['domain']}  —  risk: {result['risk']}  score: {result['score']}/100  "
          f"scan: {result['scan_mode']}")
    print("=" * 72)
    s = result["site"]
    print(f"HTTPS: {'yes' if s['https'] else 'no'}   HSTS: {'yes' if s['hsts'] else 'no'}   "
          f"Consent banner: {'yes' if s['banner'] else 'no'}   CMP: {s['cmp'] or 'none detected'}")
    print(f"Third-party trackers: {s['trackers']}   Non-essential cookies pre-consent: "
          f"{s['cookies_nonessential']}   Forms: {s['forms']}   Privacy policy found: "
          f"{'yes' if s['policy_found'] else 'no'}")
    print()
    if result["findings"]:
        print(f"Findings ({len(result['findings'])}):")
        for f in result["findings"]:
            icon = sev_icon.get(f["sev"], "•")
            print(f"  {icon} [{f['sev'].upper():8s}] {f['title']}")
            print(f"           {f['detail']}")
            print(f"           Laws: {', '.join(f['laws'])}")
    else:
        print("No privacy issues detected.")
    print()
    if result["third_parties"]:
        print(f"Third parties ({len(result['third_parties'])}):")
        for t in result["third_parties"]:
            flags = []
            if t["trap_trace"]:
                flags.append("trap-and-trace")
            if t["wiretap"]:
                flags.append("wiretap")
            flag_s = f" [{', '.join(flags)}]" if flags else ""
            print(f"  - {t['name']} ({t['category']}){flag_s}")
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="dkcissp-privacy-assessment",
        description="Assess a single website's privacy/cookie-consent posture against "
                    "GDPR, CCPA/CPRA, CIPA, India DPDP, and PDPA (Singapore). "
                    "Only assess domains you own or are authorized to test.")
    parser.add_argument("domain", help="Domain or URL to assess (e.g. example.com)")
    parser.add_argument("--json", action="store_true", help="Print the full result as JSON.")
    parser.add_argument("--csv", metavar="PATH",
                        help="Also write the findings to a CSV file at PATH.")
    parser.add_argument("--no-headless", action="store_true",
                        help="Skip the headless-Chromium dynamic scan even if a browser is available "
                             "(static HTTP-only scan).")
    args = parser.parse_args(argv)

    def log(msg):
        print(f"  … {msg}", file=sys.stderr)

    analyzer = PrivacyPostureAssessor(cfg={"headless": not args.no_headless}, on_progress=log)
    result = analyzer.analyze(args.domain)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_human(result)

    if args.csv and not result.get("error"):
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            fh.write(findings_to_csv(result))
        print(f"Wrote findings to {args.csv}", file=sys.stderr)

    if result.get("error"):
        return 2
    return 0 if result["risk"] == "Low" else 1


if __name__ == "__main__":
    raise SystemExit(main())
