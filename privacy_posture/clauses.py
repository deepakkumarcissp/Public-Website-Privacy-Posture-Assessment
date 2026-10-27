"""
Clause-citation + remediation catalog for the website privacy assessment.

Maps each finding TYPE to: a deep impact description, the SPECIFIC article/
section of each applicable law it violates, and numbered, actionable
remediation steps. This is what turns the tracker from "high-level" into an
audit-grade, per-clause remediation workbook — every finding says exactly which
clause of which regulation is breached, the proof, and how to fix it.

Law keys match assessments.privacy.website_privacy.LAWS so per-law scoring and
report grouping line up.
"""
from __future__ import annotations

# type -> {impact, clauses:{law: "article/section"}, steps:[...]}
CATALOG = {
    "pre_consent_tracking": {
        "impact": ("Analytics/advertising/session-replay trackers execute and set identifiers on the "
                   "visitor's device on page load, before any consent is given. Under EU/UK law storing or "
                   "reading information on a device without prior consent is unlawful, and the resulting "
                   "profiling has no valid legal basis; under US state law the ad/analytics data flow is a "
                   "'sale/share' and a pen-register/trap-and-trace data capture."),
        "clauses": {
            "GDPR": "Art. 6(1) (lawful basis) · Art. 7 (conditions for consent) · Recital 32; ePrivacy Directive 2002/58/EC Art. 5(3)",
            "CCPA/CPRA": "Cal. Civ. Code §1798.120 (right to opt-out of sale/share) · §1798.135 (opt-out link) · §1798.140(ah) (sharing for cross-context behavioural advertising)",
            "CIPA §638.51": "Cal. Penal Code §638.51 (pen register / trap-and-trace device)",
            "India DPDP": "DPDP Act 2023 §5 (notice) · §6 (consent)",
            "PDPA (SG)": "PDPA 2012 §13 (consent) · §14 (appropriate consent)",
        },
        "steps": [
            "Inventory every tag/pixel loaded (Google Tag Manager container + hardcoded scripts).",
            "Classify each into strictly-necessary / analytics / advertising / functional.",
            "Deploy consent gating — Google Consent Mode v2 + the CMP's category blocking — so non-essential tags are BLOCKED until explicit opt-in.",
            "Move all analytics/advertising/session-replay tags to fire only on the 'granted' consent signal.",
            "Re-scan with a headless consent test and confirm ZERO non-essential beacons/cookies before opt-in.",
        ],
    },
    "trap_trace": {
        "impact": ("Third-party trackers capture the visitor's IP address and device/browser fingerprint and "
                   "transmit them off-site. Plaintiffs treat this as an unlawful pen-register / trap-and-trace "
                   "device that records routing/addressing/signalling information without consent or a court order."),
        "clauses": {
            "CIPA §638.51": "Cal. Penal Code §638.51(a) (installing/using a pen register or trap-and-trace device without a court order)",
            "GDPR": "Art. 6(1) (no lawful basis) · ePrivacy Directive Art. 5(3)",
            "CCPA/CPRA": "Cal. Civ. Code §1798.140(ah) (share) · §1798.120",
        },
        "steps": [
            "Identify each tracker capturing IP/device identifiers (network beacons to the third party).",
            "Require prior opt-in consent before these load; block by default in the CMP.",
            "Where the vendor is business-critical, move to server-side / first-party collection so raw client IP is not shared.",
            "Execute a Data Processing Agreement with each vendor and disclose the processing in the privacy policy.",
        ],
    },
    "wiretap": {
        "impact": ("Session-replay or live-chat tooling records the visitor's interaction — including keystrokes "
                   "typed into forms before submission and chat content. This is treated as unauthorised "
                   "interception ('wiretapping') of an electronic communication."),
        "clauses": {
            "CIPA §631": "Cal. Penal Code §631 (wiretapping / unauthorised interception) · §632 (eavesdropping on confidential communication)",
            "GDPR": "Art. 6(1) (lawful basis) · Art. 5(1)(a) (fairness & transparency)",
        },
        "steps": [
            "Enable strict input-masking in the session-replay tool for ALL form fields (mask by default).",
            "Gate the recorder and chat widget behind consent; do not load before opt-in.",
            "Disclose session recording / chat interception explicitly in the privacy policy.",
            "Sign a DPA with the processor and set the shortest viable retention on recordings.",
        ],
    },
    "no_dns_link": {
        "impact": ("Advertising trackers make the site a participant in the 'sale/share' of personal information, "
                   "but no opt-out mechanism is offered to California consumers."),
        "clauses": {
            "CCPA/CPRA": "Cal. Civ. Code §1798.135(a) ('Do Not Sell or Share My Personal Information' link) · §1798.120 (right to opt-out) · §1798.135(b) (honor opt-out preference signals / GPC)",
        },
        "steps": [
            "Add a clear, persistent 'Do Not Sell or Share My Personal Information' link in the global footer (and/or a 'Your Privacy Choices' link + icon).",
            "Wire the link to an opt-out that actually disables advertising/analytics 'sale/share' trackers for that visitor.",
            "Detect and honor the Global Privacy Control (Sec-GPC) signal automatically as a valid opt-out.",
        ],
    },
    "no_banner": {
        "impact": ("Non-essential trackers run but no consent banner/CMP is presented, so consent is neither "
                   "sought nor recorded."),
        "clauses": {
            "GDPR": "Art. 4(11) & Art. 7 (valid, recorded consent); ePrivacy Directive Art. 5(3)",
            "CCPA/CPRA": "Cal. Civ. Code §1798.135",
        },
        "steps": [
            "Deploy a consent management platform (CMP) that blocks non-essential categories until opt-in.",
            "Present the banner on first visit before any non-essential tag fires.",
            "Log consent (who/when/what) for demonstrable proof under accountability.",
        ],
    },
    "consent_no_reject": {
        "impact": ("The consent banner offers 'Accept' without an equally prominent 'Reject All', so consent is "
                   "not freely given — a dark pattern called out by the EDPB."),
        "clauses": {
            "GDPR": "Art. 4(11) (freely given) · Art. 7(3); EDPB Guidelines 03/2022 on deceptive design patterns; ePrivacy Art. 5(3)",
        },
        "steps": [
            "Add a 'Reject All' button on the first layer, equally prominent as 'Accept All'.",
            "Ensure rejecting is one click and leaves all non-essential categories off.",
            "Do not use pre-ticked boxes or make 'reject' harder than 'accept'.",
        ],
    },
    "consent_no_granular": {
        "impact": ("Visitors cannot control analytics / advertising / functional categories individually — "
                   "consent is bundled rather than specific."),
        "clauses": {
            "GDPR": "Art. 6(1)(a) & Art. 7 (specific, granular consent); Recital 43; ePrivacy Art. 5(3)",
        },
        "steps": [
            "Provide a preference centre with a toggle per purpose/category.",
            "Default all non-essential categories to OFF until explicitly enabled.",
            "Persist and re-surface the choices so consent can be changed later.",
        ],
    },
    "nonessential_cookies": {
        "impact": ("Analytics/advertising cookies are written to the device on load, before consent — unlawful "
                   "storage of information on a terminal."),
        "clauses": {
            "GDPR": "ePrivacy Directive Art. 5(3); GDPR Art. 6(1) & Art. 7",
            "CCPA/CPRA": "Cal. Civ. Code §1798.135 (where used for sale/share)",
        },
        "steps": [
            "Suppress all non-strictly-necessary cookies until consent is granted.",
            "Map each cookie to a CMP category and block by category pre-consent.",
            "Re-scan to confirm only strictly-necessary cookies exist before opt-in.",
        ],
    },
    "insecure_cookies": {
        "impact": ("Cookies are set without the Secure and/or HttpOnly attributes, exposing them to interception "
                   "over the network and theft via cross-site scripting."),
        "clauses": {
            "GDPR": "Art. 5(1)(f) (integrity & confidentiality) · Art. 32 (security of processing)",
            "PDPA (SG)": "PDPA §24 (protection of personal data)",
            "India DPDP": "DPDP Act §8(5) (reasonable security safeguards)",
        },
        "steps": [
            "Set Secure on every cookie (HTTPS-only transmission).",
            "Set HttpOnly on cookies not needed by client-side JavaScript.",
            "Set SameSite=Lax or Strict to limit cross-site sending.",
        ],
    },
    "no_policy": {
        "impact": ("No privacy policy is published/linked — the mandatory baseline transparency obligation under "
                   "every regime is unmet."),
        "clauses": {
            "GDPR": "Art. 13 & Art. 14 (information to be provided to data subjects) · Art. 12 (transparency)",
            "CCPA/CPRA": "Cal. Civ. Code §1798.130(a)(5) & §1798.135(c) (privacy policy)",
            "India DPDP": "DPDP Act §5 (notice)",
            "PDPA (SG)": "PDPA §20 (notification of purpose) · §12 (policies)",
        },
        "steps": [
            "Publish a comprehensive privacy policy.",
            "Link it from every page footer and at each point of data collection.",
            "Keep it dated and versioned.",
        ],
    },
    "policy_missing": {
        "impact": ("The privacy policy is missing one or more mandatory disclosures (e.g. retention periods, "
                   "international-transfer safeguards, legal basis, or DPO/contact)."),
        "clauses": {
            "GDPR": "Art. 13(1)(c) (legal basis) · Art. 13(2)(a) (retention) · Art. 13(1)(f) & Arts. 44-49 (international transfers) · Art. 37-39 (DPO)",
            "India DPDP": "DPDP Act §5 (notice contents) · §8(7) (retention) · §10 (grievance/contact)",
            "PDPA (SG)": "PDPA §20 (purpose) · §25 (retention limitation) · §26 (transfer limitation)",
        },
        "steps": [
            "Add a retention schedule per data category.",
            "State the safeguard for cross-border transfers (SCCs / adequacy / consent).",
            "State the legal basis per processing purpose and the DPO / privacy-contact details.",
        ],
    },
    "chat_ai": {
        "impact": ("A chatbot/AI widget processes what visitors type and routes it to a third-party processor; "
                   "without disclosure and consent this is undisclosed processing and potential interception."),
        "clauses": {
            "GDPR": "Art. 6(1) (lawful basis) · Art. 13 (disclosure) · Art. 28 (processor DPA)",
            "CIPA §631": "Cal. Penal Code §631 (interception of the conversation)",
        },
        "steps": [
            "Disclose the chat/AI processor and what it captures in the privacy policy.",
            "Gate the widget behind consent where it sets cookies / records input.",
            "Execute a DPA with the vendor and confirm data-retention / sub-processor terms.",
        ],
    },
    "no_https": {
        "impact": ("The site is served over plaintext HTTP, so any personal data submitted is transmitted "
                   "unencrypted and interceptable."),
        "clauses": {
            "GDPR": "Art. 32 (security of processing) · Art. 5(1)(f)",
            "PDPA (SG)": "PDPA §24",
            "India DPDP": "DPDP Act §8(5) (security safeguards)",
        },
        "steps": [
            "Enforce HTTPS site-wide and redirect all HTTP to HTTPS.",
            "Enable HSTS (Strict-Transport-Security) with a long max-age and includeSubDomains.",
            "Renew/monitor the TLS certificate and disable weak protocols/ciphers.",
        ],
    },
    "fingerprinting": {
        "impact": ("The site probes canvas / WebGL / font-metrics / audio APIs to build a device fingerprint — "
                   "a persistent cross-site identifier created without cookies or consent."),
        "clauses": {
            "GDPR": "ePrivacy Directive Art. 5(3) (accessing information on the device — fingerprinting included, per EDPB) · GDPR Art. 6(1)",
            "CCPA/CPRA": "Cal. Civ. Code §1798.140(v) (unique/probabilistic identifier = personal information)",
            "CIPA §638.51": "Cal. Penal Code §638.51 (device-identifier capture)",
        },
        "steps": [
            "Identify the script performing canvas/WebGL/audio fingerprinting.",
            "Gate it behind consent — fingerprinting needs opt-in like any non-essential tracker.",
            "Prefer privacy-preserving alternatives and disclose any fingerprinting in the policy.",
        ],
    },
    "cmp_reject_ineffective": {
        "impact": ("After the visitor clicks 'Reject All', non-essential trackers STILL fire — the consent banner "
                   "is decorative and does not actually block tracking. Withdrawing consent must be as effective "
                   "as granting it."),
        "clauses": {
            "GDPR": "Art. 7(3) (withdrawing consent as easy as giving it) · Art. 4(11) (freely given); ePrivacy Art. 5(3)",
            "CCPA/CPRA": "Cal. Civ. Code §1798.135 (a submitted opt-out must be honored)",
        },
        "steps": [
            "Configure the CMP to actually BLOCK analytics/advertising tags when consent is rejected (not just dismiss the banner).",
            "Wire every non-essential tag to the CMP's consent signal (e.g. Google Consent Mode 'denied').",
            "Re-test the reject flow and confirm zero non-essential beacons/cookies fire after Reject-All.",
        ],
    },
    "gpc_ignored": {
        "impact": ("With Global Privacy Control signalled by the browser, the site still loads sale/share "
                   "trackers — the legally-binding opt-out preference signal is ignored."),
        "clauses": {
            "CCPA/CPRA": "Cal. Civ. Code §1798.135(b) (honor opt-out preference signals / GPC) · §1798.120",
        },
        "steps": [
            "Detect the Sec-GPC request header and navigator.globalPrivacyControl.",
            "Treat GPC as a valid opt-out of sale/share and suppress those trackers for that visitor.",
            "Reflect the opt-out state in the CMP so it persists.",
        ],
    },
    "forms_no_consent": {
        "impact": ("Forms collect personal data without a separate, unticked consent/marketing opt-in or a "
                   "notice at the point of collection."),
        "clauses": {
            "GDPR": "Art. 6(1)(a) & Art. 7 (consent) · Art. 13 (notice at collection)",
            "India DPDP": "DPDP Act §5 (notice) · §6 (consent)",
            "PDPA (SG)": "PDPA §13 (consent) · §20 (notification of purpose)",
        },
        "steps": [
            "Add a separate, unticked consent checkbox distinct from submitting the request.",
            "Keep marketing consent separate from service-fulfilment consent.",
            "Link the privacy policy at the point of collection and record the consent.",
        ],
    },
}


def enrich(ftype: str) -> dict:
    """Return {clauses, steps, impact, laws} for a finding type (safe defaults)."""
    meta = CATALOG.get(ftype, {})
    clauses = meta.get("clauses", {})
    return {
        "impact": meta.get("impact", ""),
        "clauses": clauses,
        "laws": list(clauses.keys()),
        "steps": meta.get("steps", []),
    }
