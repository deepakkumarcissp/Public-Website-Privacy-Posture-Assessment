"""
Public Website Privacy Posture Assessment — core engine.

Give it one URL/domain; it assesses that site over HTTPS (the no-consent
state — a bare fetch is pre-consent by definition) for:

  * third-party trackers (analytics / advertising / session-replay / chat /
    embeds / CAPTCHA) via the vendor catalog, with CIPA trap-and-trace
    (§638.51) and wiretapping (§631) flags
  * cookies set on load (non-essential-before-consent) + cookie security flags
  * cookie-consent banner / CMP presence, and (with the optional headless
    probe) whether "Reject All" actually blocks trackers
  * privacy-policy presence + required-disclosure coverage
  * "Do Not Sell or Share" link + data-collection forms (PII fields)
  * transport security (HTTPS/HSTS)
  * device fingerprinting (canvas/WebGL/audio probing)

Findings are mapped to specific clauses of GDPR, CCPA/CPRA, CIPA, India DPDP,
and PDPA (Singapore) — not just "this law applies" but the article/section and
concrete remediation steps.

Two scan modes:
  * Dynamic (preferred) — drives a real, locally-installed Chromium/Chrome
    browser via the Chrome DevTools Protocol (no Playwright/Selenium needed)
    to observe actual pre-consent network beacons and test the Reject-All
    flow. Falls back silently if no Chromium is found.
  * Static — a plain HTTPS GET, used when no browser is available.

This tool never submits forms, never logs in, and never does anything other
than load pages a normal visitor's browser would load. Only assess domains
you own or are authorized to test — see README.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:
    _HAVE_REQUESTS = False

from . import vendors as V
from .clauses import enrich as _enrich

_UA = {"User-Agent": "Mozilla/5.0 (compatible; PrivacyPostureAssessment/1.0; "
                     "+https://github.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment)"}
_TIMEOUT = 15

# Non-essential cookie name signatures (analytics/advertising) — presence on a
# bare load = set before consent.
_NONESSENTIAL_COOKIE = re.compile(
    r"^(_ga|_gid|_gat|_gcl_|_fbp|_fbc|fr|_uet|li_|lidc|bcookie|bscookie|_hj|"
    r"_clck|_clsk|IDE|test_cookie|__gads|__gpi|_pin_|_ttp|MUID|ANONCHK|"
    r"personalization_id|guest_id|_scid|sc_at|hubspotutk|__hstc|__hssc|__hssrc)",
    re.I)

# Laws in scope (order = display order).
LAWS = ["GDPR", "CCPA/CPRA", "CIPA §638.51", "CIPA §631", "India DPDP", "PDPA (SG)"]

# The 28-domain control catalog + trap/wiretap. gov=True → governance/attestation
# (no external technical signal — these require documentation review).
CATALOG_CONTROLS = [
    (1, "Privacy Notice", False), (2, "Data Collection", False), (3, "Purpose per field", False),
    (4, "Data Minimization", False), (5, "Consent (explicit/recorded)", False),
    (6, "Cookie Banner", False), (7, "Cookie Preference Center", False),
    (8, "Pre-consent Tracking", False), (9, "Withdraw Consent", False),
    (10, "DSAR / Privacy Rights", False), (11, "Privacy Contact / DPO", False),
    (12, "Forms", False), (13, "Marketing Consent", False), (14, "Children's Data", True),
    (15, "Third Parties", False), (16, "Analytics", False), (17, "Advertising Trackers", False),
    (18, "Embedded Content", False), (19, "CAPTCHA", False), (20, "Chatbot / AI", False),
    (21, "International Transfers", False), (22, "Retention", False),
    (23, "Third-party Contracts (DPA)", True), (24, "Security of Data", False),
    (25, "Breach Handling", True), (26, "Privacy by Design", True),
    (27, "Change Management (drift)", True), (28, "Evidence", False),
]

_DNS_LINK = ["do not sell", "do not share", "your privacy choices", "opt out of sale",
             "do-not-sell", "privacy choices"]

_PII_PARAM = re.compile(
    r"(e?mail|phone|tel|firstname|lastname|fullname|\bname\b|user|uid|userid|customer|account|"
    r"address|street|zip|postal|dob|birth|gender|ssn|token|sessionid|gclid|fbclid|_ga|_fbp|"
    r"\bcid\b|clientid|client_id|\bip\b|geo|latitude|longitude|device)", re.I)


def _sev_rank(s):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((s or "").lower(), 0)


# Cloud-provider instance-metadata endpoints. Never legitimate targets for a
# privacy/cookie-consent assessment; blocking them closes off the clearest
# SSRF-via-this-tool abuse case without restricting legitimate use against a
# company's own internal/private web apps.
_BLOCKED_SSRF_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}
_BLOCKED_SSRF_NETS = [ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("fe80::/10")]
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_VALID_HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,62})?$")


def _embedded_ipv4(ip):
    """Return the IPv4 address embedded in `ip`, if any (IPv4-mapped, NAT64,
    6to4, or Teredo), else None. There are several distinct IPv6 encodings of
    an IPv4 address, each of which must be unwrapped and re-checked — an
    address can otherwise disguise a blocked IPv4 target under a form that
    doesn't match a plain IPv4 blocklist/network check."""
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped:
        return mapped
    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    sixtofour = getattr(ip, "sixtofour", None)
    if sixtofour:
        return sixtofour
    teredo = getattr(ip, "teredo", None)  # (server_ip, client_ip) or None
    if teredo:
        return teredo[0]
    return None


def _is_blocked_ip(ip) -> bool:
    """True if `ip` (or an IPv4 address it embeds, under any of the several
    IPv6 encodings of one) is a cloud-metadata address, or isn't a globally-
    routable address at all. Using `is_global` as the primary gate — rather
    than enumerating every private/link-local/reserved/multicast range by
    hand — means a new or obscure non-global range doesn't silently slip
    through; only addresses affirmatively known to be internet-routable are
    allowed."""
    if str(ip) in _BLOCKED_SSRF_IPS:
        return True
    if any(ip in net for net in _BLOCKED_SSRF_NETS if net.version == ip.version):
        return True
    if not ip.is_global:
        return True
    if ip.version == 6:
        embedded = _embedded_ipv4(ip)
        if embedded is not None and _is_blocked_ip(embedded):
            return True
    return False


def _is_safe_target(host: str) -> bool:
    """True only if `host` is a syntactically plain hostname (no userinfo,
    port, or other characters a URL parser could interpret differently than
    this check does — e.g. 'evil.com@169.254.169.254', which requests/urllib3
    would treat as a request to 169.254.169.254 with 'evil.com@' as userinfo)
    AND it resolves to an address that is not cloud-metadata/link-local
    (including via an IPv4-mapped or NAT64 IPv6 disguise).

    Fails CLOSED: a hostname that doesn't match the allowed character set, or
    that fails to resolve at all, is treated as unsafe rather than allowed
    through. (A genuinely-unreachable domain still gets a clear "could not
    reach" error later — it just never reaches the network layer first.)"""
    if not host or not _VALID_HOSTNAME.match(host):
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        raw_ip = info[4][0].split("%")[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            return False
        if _is_blocked_ip(ip):
            return False
    return True


def _resolve_pinned_ip(host: str) -> str:
    """Return the first safe IP `host` resolves to (for pinning Chromium's
    own DNS resolution to it — see headless.scan's pinned_host/pinned_ip),
    or '' if none. Caller must already have confirmed `_is_safe_target(host)`
    so this never returns a blocked address; it exists to find a SPECIFIC
    validated address to pin to, not to re-validate."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return ""
    for info in infos:
        raw_ip = info[4][0].split("%")[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if ip.version == 4 and not _is_blocked_ip(ip):
            return str(ip)
    return ""


_MAX_REDIRECTS = 5


def _safe_get(url: str, **kwargs):
    """GET with redirects followed manually, re-validating the target host at
    EVERY hop. requests' built-in allow_redirects=True would otherwise let an
    initially-safe host 30x-redirect the request straight to an internal or
    cloud-metadata address without our check ever seeing it."""
    kwargs.setdefault("timeout", _TIMEOUT)
    kwargs["allow_redirects"] = False
    for _ in range(_MAX_REDIRECTS + 1):
        host = urlparse(url).hostname or ""
        if not _is_safe_target(host):
            return None
        r = requests.get(url, **kwargs)
        if r.is_redirect or r.is_permanent_redirect:
            location = r.headers.get("Location")
            if not location:
                return r
            url = urljoin(url, location)
            continue
        return r
    return None  # too many redirects


def _reg_domain(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _transfer_rows(site_host: str, transfers: list) -> list:
    """Third-party data-transfer inventory: for every request to an EXTERNAL
    domain — method, URL, third-party host, and the parameters/fields sent
    (query + POST body + JSON keys, PII flagged)."""
    from urllib.parse import urlparse, parse_qsl
    base = _reg_domain(site_host)
    rows = []
    for t in transfers or []:
        try:
            host = urlparse(t["url"]).hostname or ""
        except Exception:
            host = ""
        if not host or _reg_domain(host) == base:
            continue
        params = []
        try:
            params += [k for k, _ in parse_qsl(urlparse(t["url"]).query)]
        except Exception:
            pass
        pd = t.get("postData") or ""
        if pd:
            try:
                params += [k for k, _ in parse_qsl(pd)]
            except Exception:
                pass
            params += re.findall(r'"([A-Za-z0-9_]{2,40})"\s*:', pd)
        params = list(dict.fromkeys(params))
        pii = [p for p in params if _PII_PARAM.search(p)]
        if pii:
            data = "PII fields: " + ", ".join(pii[:12])
        elif params:
            data = "params: " + ", ".join(params[:12])
        else:
            data = ""
        data = (data + " · " if data else "") + "client IP + User-Agent (inherent to every request)"
        rows.append({"method": t.get("method", "GET"), "url": t["url"][:300],
                     "third_party": host, "data": data,
                     "location": site_host + " · " + (t.get("type") or "request"),
                     "type": t.get("type", ""), "has_pii": bool(pii)})
    return rows


class PrivacyPostureAssessor:
    """Assess ONE website's privacy posture. No subdomain discovery, no
    account, no data sent anywhere except the site being assessed (and, if
    you configure it, nothing — there is no third-party reputation lookup
    in this tool)."""

    def __init__(self, cfg: Optional[dict] = None, on_progress=None):
        self.cfg = cfg or {}
        self._on_progress = on_progress or (lambda msg: None)
        try:
            from . import headless as H
            self.use_headless = bool(self.cfg.get("headless", True)) and H.available()
        except Exception:
            self.use_headless = False

    def _progress(self, msg: str) -> None:
        try:
            self._on_progress(msg)
        except Exception:
            pass

    # ── per-site fetch + checks ───────────────────────────────────────────────
    def _fetch(self, host: str):
        tls_error = False
        for scheme in ("https://", "http://"):
            try:
                r = _safe_get(scheme + host, headers=_UA)
                if r is not None:
                    return r, tls_error
            except requests.exceptions.SSLError:
                tls_error = True
                continue
            except Exception:
                continue
        return None, tls_error

    def _find_policy_url(self, base_url: str, html: str) -> str:
        for m in re.finditer(r'href=["\']([^"\']+)["\'][^>]*>([^<]{0,60})', html, re.I):
            href, text = m.group(1), (m.group(2) or "").lower()
            if any(k in href.lower() or k in text for k in
                   ["privacy", "privacy-policy", "privacypolicy", "data-protection"]):
                return urljoin(base_url, href)
        return ""

    def _analyze_policy(self, url: str) -> dict:
        out = {"url": url, "found": bool(url), "checks": {}, "missing": []}
        if not url:
            return out
        try:
            r = _safe_get(url, headers=_UA)
            if r is None:
                out["found"] = False
                return out
            t = (r.text or "").lower()
        except Exception:
            out["found"] = False
            return out
        req = {
            "Controller identity & contact": ["controller", "we are", "company", "contact us", "registered"],
            "Categories of data collected": ["information we collect", "data we collect", "personal data", "personal information"],
            "Purposes of processing": ["purpose", "how we use", "why we"],
            "Legal basis": ["legal basis", "lawful basis", "legitimate interest", "consent"],
            "Data retention periods": ["retention", "how long", "retain", "retained for"],
            "Third parties / recipients": ["third part", "share", "service providers", "processors"],
            "International transfer safeguards": ["transfer", "outside", "standard contractual", "adequacy", "cross-border"],
            "Data-subject rights": ["your rights", "right to access", "right to erasure", "right to delete", "opt out"],
            "DPO / privacy contact": ["data protection officer", "dpo", "privacy@", "privacy officer", "grievance officer"],
        }
        for label, kws in req.items():
            ok = any(k in t for k in kws)
            out["checks"][label] = ok
            if not ok:
                out["missing"].append(label)
        m = re.search(r"last updated[:\s]+([a-z0-9 ,]+20\d\d)", t)
        out["last_updated"] = m.group(1).strip() if m else ""
        return out

    def _cookie_flags(self, resp) -> dict:
        raw = []
        try:
            raw = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw, "headers") else []
        except Exception:
            raw = []
        if not raw:
            sc = resp.headers.get("Set-Cookie", "")
            raw = [sc] if sc else []
        names, nonessential, insecure = [], [], 0
        for line in raw:
            nm = line.split("=", 1)[0].strip()
            if not nm:
                continue
            names.append(nm)
            low = line.lower()
            if not ("secure" in low and "httponly" in low):
                insecure += 1
            if _NONESSENTIAL_COOKIE.match(nm):
                nonessential.append(nm)
        return {"all": names, "nonessential": nonessential, "insecure": insecure}

    def _forms(self, html: str) -> list:
        forms = []
        for fm in re.finditer(r"<form\b[^>]*>(.*?)</form>", html, re.I | re.S):
            block = fm.group(1)
            fields = re.findall(r'type=["\']?(email|tel|password|text|number)["\']?', block, re.I)
            names = re.findall(r'name=["\']([^"\']+)["\']', block, re.I)
            pii = [n for n in names if re.search(r"email|phone|tel|name|address|dob|birth|zip|postal|company", n, re.I)]
            has_consent = bool(re.search(r'type=["\']?checkbox["\']?', block, re.I)) and \
                          bool(re.search(r"consent|agree|subscribe|opt.?in|privacy|marketing", block, re.I))
            if fields or pii:
                forms.append({"fields": len(set(names)), "pii": sorted(set(pii))[:8],
                              "consent_checkbox": has_consent})
        return forms

    def _assess_site(self, host: str) -> dict:
        site = {"url": host, "reachable": False, "trackers": [], "cmp": "",
                "cookies": {}, "forms": [], "policy": {}, "dns_link": False,
                "https": False, "hsts": False, "findings": [], "score": 0,
                "risk": "Unknown", "scan_mode": "static", "consent_dyn": None,
                "net_requests": []}
        if not _is_safe_target(host):
            site["blocked"] = True
            self._progress(f"Could not safely validate {host} (it did not resolve, or resolves to "
                           "a disallowed cloud-metadata/link-local address) — refusing to assess it.")
            return site
        html = ""; final = "https://" + host
        requests_seen = []; consent_dyn = None; cookies_dyn = None
        doc_headers = {}; fp_dyn = {}; post_reject = None; transfers_dyn = []

        if self.use_headless:
            self._progress(f"Launching local headless Chromium and loading {host}…")
            try:
                from . import headless as H
                pinned_ip = _resolve_pinned_ip(host)
                hs = H.scan("https://" + host, settle=float(self.cfg.get("settle", 4.0)), consent=True,
                           pinned_host=host, pinned_ip=pinned_ip)
                final_host = urlparse(hs.get("final_url") or "").hostname or ""
                if hs.get("ok") and final_host and not _is_safe_target(final_host):
                    # Chromium follows its own navigation/redirects, which our
                    # Python-level _safe_get() hop-by-hop validation never
                    # sees. If the page ended up navigated to a blocked
                    # target, discard the dynamic result entirely rather than
                    # trust anything it captured, and fall back to the static
                    # path (which independently validates the ORIGINAL host).
                    self._progress(f"Headless navigation ended up at a disallowed address "
                                   f"({final_host}) — discarding the dynamic scan.")
                elif hs.get("ok"):
                    site["scan_mode"] = "dynamic"
                    site["reachable"] = True
                    html = hs.get("html") or ""
                    final = hs.get("final_url") or final
                    requests_seen = hs.get("pre_requests") or []
                    cookies_dyn = hs.get("pre_cookies") or []
                    consent_dyn = hs.get("consent") or {}
                    doc_headers = hs.get("doc_headers") or {}
                    fp_dyn = hs.get("fingerprint") or {}
                    post_reject = hs.get("post_reject")
                    transfers_dyn = hs.get("transfers") or []
                    self._progress(f"Captured {len(requests_seen)} network request(s) before any consent was given.")
                    if consent_dyn.get("banner"):
                        self._progress("Cookie-consent banner detected — testing the 'Reject All' flow…")
                else:
                    self._progress("Headless scan did not complete cleanly — falling back to a static HTTP check.")
            except Exception:
                self._progress("Headless scan failed — falling back to a static HTTP check.")
        else:
            self._progress(f"No local Chromium found — running a static HTTP check of {host}…")

        tls_error = False
        if not site["reachable"]:
            r, tls_error = self._fetch(host)
            if r is None:
                if tls_error:
                    site["tls_error"] = True
                    self._progress("HTTPS certificate failed validation and HTTP fallback also failed.")
                else:
                    self._progress(f"Could not reach {host} at all.")
                return site
            site["reachable"] = True
            html = r.text or ""
            final = str(r.url)
            doc_headers = {k.lower(): v for k, v in r.headers.items()}
            site["cookies"] = self._cookie_flags(r)

        site["https"] = final.startswith("https://")
        site["hsts"] = "strict-transport-security" in doc_headers
        site["net_requests"] = requests_seen
        self._progress("Scanning page content and network activity for third-party trackers…")
        vendors_found = V.detect(html, extra_urls=requests_seen, cfg=self.cfg)
        cmp = next((v for v in vendors_found if v["is_cmp"]), None)
        site["cmp"] = cmp["cmp_label"] if cmp else ""
        trackers = [v for v in vendors_found if not v["is_cmp"]]
        site["trackers"] = trackers
        if trackers:
            self._progress(f"Found {len(trackers)} third-party tracker(s): "
                           + ", ".join(t["name"] for t in trackers[:5])
                           + ("…" if len(trackers) > 5 else ""))
        else:
            self._progress("No third-party trackers detected.")

        if cookies_dyn is not None:
            names = [c.get("name") for c in cookies_dyn if c.get("name")]
            nonessential = [n for n in names if _NONESSENTIAL_COOKIE.match(n)]
            insecure = sum(1 for c in cookies_dyn if not (c.get("secure") and c.get("httpOnly")))
            site["cookies"] = {"all": names, "nonessential": nonessential, "insecure": insecure}

        site["forms"] = self._forms(html)
        low = html.lower()
        site["dns_link"] = any(k in low for k in _DNS_LINK)
        if consent_dyn:
            site["consent_dyn"] = consent_dyn
            site["banner"] = bool(consent_dyn.get("banner"))
        else:
            site["banner"] = bool(cmp) or ("cookie" in low and any(k in low for k in
                     ["accept cookies", "we use cookies", "cookie consent", "accept all", "cookie settings"]))

        self._progress("Looking for a linked privacy policy and checking required disclosures…")
        purl = self._find_policy_url(final, html)
        site["policy"] = self._analyze_policy(purl)

        F = site["findings"]
        adv = [t for t in trackers if t["category"] == "Advertising"]
        ana = [t for t in trackers if t["category"] == "Analytics"]
        sess = [t for t in trackers if t["category"] == "Session replay"]
        chat = [t for t in trackers if t["category"] == "Chat / AI"]
        traps = [t for t in trackers if t["trap_trace"]]
        wires = [t for t in trackers if t["wiretap"]]
        dyn = site["scan_mode"] == "dynamic"
        from urllib.parse import urlparse as _up
        base_reg = _reg_domain(host)
        beacons = [u for u in requests_seen if _reg_domain((_up(u).hostname or "")) != base_reg]

        def add(ftype, sev, title, evidence, extra=""):
            m = _enrich(ftype)
            detail = (m["impact"] + ((" " + extra) if extra else "")).strip()
            steps = m["steps"]
            F.append({"type": ftype, "sev": sev, "title": title, "site": host,
                      "laws": m["laws"], "clauses": m["clauses"], "detail": detail,
                      "evidence": evidence, "steps": steps,
                      "fix": "  ".join(f"{i+1}. {s}" for i, s in enumerate(steps))})

        pre = adv + ana + sess
        if pre:
            ev = "Vendors firing pre-consent: " + ", ".join(t["name"] for t in pre[:12])
            if dyn and beacons:
                ev += "\nActual third-party beacons observed on load (NO consent given):\n" + "\n".join(beacons[:8])
            if dyn:
                add("pre_consent_tracking", "critical",
                    f"{len(pre)} non-essential tracker(s) fired BEFORE consent (observed in a real browser load)",
                    ev, extra=(f"A CMP ({site['cmp']}) is present but is NOT blocking them." if site["cmp"]
                               else "No consent manager blocks them."))
            elif not site["cmp"]:
                add("pre_consent_tracking", "critical",
                    f"{len(pre)} non-essential tracker(s) load before any consent", ev)
            else:
                add("pre_consent_tracking", "high",
                    f"{len(pre)} non-essential tracker(s) present with a CMP ({site['cmp']}) — confirm they are blocked pre-consent",
                    ev, extra="Static scan cannot confirm the gate; verify with a consent-flow test.")
        if traps:
            tev = "Trackers capturing IP/device identifiers: " + ", ".join(t["name"] for t in traps[:12])
            if dyn and beacons:
                tev += "\nSample third-party beacons (carry client IP + device data):\n" + "\n".join(beacons[:6])
            add("trap_trace", "critical",
                f"Trap-and-trace exposure — {len(traps)} tracker(s) capture IP/device identifiers", tev)
        if wires:
            add("wiretap", "high",
                f"Wiretapping/interception exposure — {len(wires)} session-replay/chat tool(s)",
                "Tools intercepting interaction/keystrokes: " + ", ".join(t["name"] for t in wires[:12]))
        if not site["dns_link"] and adv:
            add("no_dns_link", "high", "No 'Do Not Sell or Share My Personal Information' link",
                f"{len(adv)} advertising tracker(s) present (" + ", ".join(t["name"] for t in adv[:6])
                + "); no 'Do Not Sell/Share' or 'Your Privacy Choices' link found on the page.")
        if not site["banner"] and pre:
            add("no_banner", "high", "No cookie-consent banner detected",
                "Non-essential trackers are present but no CMP/banner signature was found on the page.")
        if dyn and consent_dyn and consent_dyn.get("banner"):
            if not consent_dyn.get("reject_present"):
                add("consent_no_reject", "high", "Cookie banner has no equally-prominent 'Reject All'",
                    "Banner detected; a 'Reject All' control was NOT found on the first layer.")
            if not consent_dyn.get("granular_present"):
                add("consent_no_granular", "medium", "No granular cookie preference center",
                    "Banner detected; no per-category manage/preferences control was found.")
        site["reject_tested"] = bool(post_reject)
        if dyn and post_reject:
            pv = V.detect("", extra_urls=post_reject.get("requests", []), cfg=self.cfg)
            pv_ne = [t for t in pv if (not t["is_cmp"]) and t["category"] in ("Advertising", "Analytics", "Session replay")]
            if pv_ne:
                pev = "Non-essential trackers STILL firing after clicking Reject-All: " + ", ".join(t["name"] for t in pv_ne[:10])
                rb = [u for u in post_reject.get("requests", []) if _reg_domain((_up(u).hostname or "")) != base_reg][:6]
                if rb:
                    pev += "\nBeacons after reject:\n" + "\n".join(rb)
                add("cmp_reject_ineffective", "high",
                    "Trackers still fire after 'Reject All' — consent rejection is not enforced", pev)
        site["transfers"] = _transfer_rows(host, transfers_dyn)
        site["fingerprint"] = fp_dyn or {}
        fps = [k for k, v in (fp_dyn or {}).items() if v]
        if fps:
            add("fingerprinting", "medium",
                "Device fingerprinting detected (" + ", ".join(fps) + ")",
                "Fingerprinting APIs probed on page load: " + ", ".join(fps)
                + " (canvas/WebGL/font/audio device-identification).")
        if site["cookies"].get("nonessential"):
            add("nonessential_cookies", "high",
                f"{len(site['cookies']['nonessential'])} non-essential cookie(s) set on load",
                "Cookies written before consent: " + ", ".join(site["cookies"]["nonessential"][:15]))
        if site["cookies"].get("insecure"):
            add("insecure_cookies", "medium",
                f"{site['cookies']['insecure']} cookie(s) missing Secure/HttpOnly flags",
                f"{site['cookies']['insecure']} Set-Cookie entr(y/ies) lack the Secure and/or HttpOnly attribute.")
        pol = site["policy"]
        if not pol.get("found"):
            add("no_policy", "high", "No privacy policy found/linked",
                "No privacy/policy link was found in the page body or footer.")
        elif pol.get("missing"):
            add("policy_missing", "medium",
                "Privacy policy missing required disclosures: " + ", ".join(pol["missing"][:5]),
                "Missing disclosures detected in the policy: " + ", ".join(pol["missing"])
                + (f"  (policy: {pol.get('url','')})" if pol.get("url") else ""))
        if chat:
            add("chat_ai", "medium",
                f"Chatbot/AI widget captures user input ({', '.join(c['name'] for c in chat[:4])})",
                "Chat/AI widgets present: " + ", ".join(c["name"] for c in chat))
        if not site["https"] and tls_error:
            add("no_https", "high", "HTTPS certificate failed validation",
                "The site's TLS certificate did not validate (expired, self-signed, or hostname "
                f"mismatch); HTTPS was refused and the page was reachable only over plain HTTP. "
                f"Final URL after redirects: {final}")
        elif not site["https"]:
            add("no_https", "high", "Site not served over HTTPS", f"Final URL after redirects: {final}")
        forms_pii = [f for f in site["forms"] if f["pii"]]
        if forms_pii and not any(f["consent_checkbox"] for f in forms_pii):
            add("forms_no_consent", "medium",
                f"{len(forms_pii)} PII-collecting form(s) without a visible consent checkbox",
                "PII fields collected: " + "; ".join(", ".join(f["pii"]) for f in forms_pii[:4]))

        pen = sum({"critical": 28, "high": 16, "medium": 8, "low": 3}.get(f["sev"], 0) for f in F)
        site["score"] = max(0, 100 - pen)
        site["risk"] = ("Critical" if any(f["sev"] == "critical" for f in F)
                        else "High" if any(f["sev"] == "high" for f in F)
                        else "Medium" if F else "Low")
        self._progress(f"Mapped {len(F)} finding(s) to GDPR / CCPA / CIPA / DPDP / PDPA clauses "
                       f"— score {site['score']}/100 ({site['risk']} risk).")
        return site

    def _catalog_status(self, sites: list) -> list:
        any_adv = any(any(t["category"] == "Advertising" for t in s["trackers"]) for s in sites)
        pre_any = any((not s["cmp"]) and any(t["category"] in ("Advertising", "Analytics", "Session replay") for t in s["trackers"]) for s in sites)
        banner_all = sites and all(s.get("banner") for s in sites)
        cmp_any = any(s["cmp"] for s in sites)
        dns_any = any(s["dns_link"] for s in sites)
        pol_all = sites and all(s["policy"].get("found") for s in sites)
        https_all = sites and all(s["https"] for s in sites)
        chat_any = any(any(t["category"] == "Chat / AI" for t in s["trackers"]) for s in sites)
        embed_any = any(any(t["category"].startswith("Embedded") for t in s["trackers"]) for s in sites)
        cap_any = any(any(t["category"] == "CAPTCHA" for t in s["trackers"]) for s in sites)
        forms_any = any(s["forms"] for s in sites)
        rights_any = any(s["policy"].get("checks", {}).get("Data-subject rights") for s in sites)
        contact_any = any(s["policy"].get("checks", {}).get("DPO / privacy contact") for s in sites)
        ret_any = any(s["policy"].get("checks", {}).get("Data retention periods") for s in sites)
        xfer_any = any(s["policy"].get("checks", {}).get("International transfer safeguards") for s in sites)

        st = {1: "ok" if pol_all else "gap", 2: "ok" if forms_any else "part", 3: "part", 4: "part",
              5: "part" if forms_any else "gap", 6: "ok" if banner_all else ("part" if cmp_any else "gap"),
              7: "part" if cmp_any else "gap", 8: "gap" if pre_any else "ok",
              9: "part" if cmp_any else "gap", 10: "ok" if rights_any else "gap",
              11: "ok" if contact_any else "gap", 12: "ok" if forms_any else "part", 13: "gap",
              14: "att", 15: "ok", 16: "ok", 17: "gap" if any_adv else "ok",
              18: "part" if embed_any else "ok", 19: "part" if cap_any else "ok",
              20: "ok" if chat_any else "ok", 21: "part" if xfer_any else "gap",
              22: "ok" if ret_any else "gap", 23: "att", 24: "ok" if https_all else "gap",
              25: "att", 26: "att", 27: "att", 28: "ok"}
        return [{"id": i, "name": nm, "gov": gov, "status": st.get(i, "part")} for i, nm, gov in CATALOG_CONTROLS]

    def _site_matrix(self, site: dict) -> list:
        fmap = {}
        for f in site.get("findings", []) or []:
            fmap.setdefault(f.get("type"), f)
        trk = site.get("trackers", []) or []
        def cat(c): return any(t["category"] == c for t in trk)
        any_adv = cat("Advertising")
        any_pre = any_adv or cat("Analytics") or cat("Session replay")
        any_chat = cat("Chat / AI")
        cons = site.get("consent_dyn") or {}
        dyn_banner = bool(cons.get("banner"))
        policy = site.get("policy") or {}
        forms_pii = any(f.get("pii") for f in (site.get("forms") or []))
        hsts = site.get("hsts")
        controls = [
            ("pre_consent_tracking", "Non-essential trackers blocked before consent", True,
             "No non-essential trackers fire before consent.", "No pre-consent analytics/advertising/session beacons observed."),
            ("trap_trace", "No trap-and-trace capture of IP/device identifiers", True,
             "No trackers capture IP/device identifiers.", "No trap-and-trace beacons observed."),
            ("wiretap", "No session-replay/chat interception", True,
             "No session-replay or chat-interception tooling.", "None detected."),
            ("no_dns_link", "'Do Not Sell or Share' opt-out provided", any_adv,
             "Opt-out link present.", "'Do Not Sell/Share' / 'Your Privacy Choices' link found."),
            ("no_banner", "Cookie-consent banner presented", any_pre,
             "Consent banner present.", ("CMP: " + site["cmp"]) if site.get("cmp") else "Banner detected."),
            ("consent_no_reject", "'Reject All' offered equally", dyn_banner,
             "'Reject All' control present.", "Reject-all control detected on the banner."),
            ("consent_no_granular", "Granular cookie preference center", dyn_banner,
             "Granular preference center present.", "Per-category manage/preferences control detected."),
            ("cmp_reject_ineffective", "Reject-All actually blocks trackers", bool(site.get("reject_tested")),
             "Rejecting consent stops non-essential trackers.", "No non-essential beacons observed after Reject-All."),
            ("fingerprinting", "No device fingerprinting", True,
             "No canvas/WebGL/audio fingerprinting detected.", "No fingerprinting API probing observed."),
            ("nonessential_cookies", "No non-essential cookies before consent", True,
             "No non-essential cookies set before consent.", "Only strictly-necessary cookies observed on load."),
            ("insecure_cookies", "Cookies carry Secure/HttpOnly", True,
             "Cookies carry Secure/HttpOnly.", "No insecure Set-Cookie observed."),
            ("no_policy", "Privacy policy published & linked", True,
             "Privacy policy present and linked.", ("Policy: " + policy.get("url", "")) if policy.get("url") else "Policy link found."),
            ("policy_missing", "Privacy policy discloses required items", bool(policy.get("found")),
             "Policy discloses the required items.", "All checked disclosures present."),
            ("chat_ai", "Chatbot/AI processing disclosed & consented", any_chat, "", ""),
            ("no_https", "HTTPS/TLS enforced in transit", True,
             "HTTPS enforced" + (" with HSTS." if hsts else "."),
             ("HSTS header present." if hsts else "Served over HTTPS.")),
            ("forms_no_consent", "Forms capture consent at collection", forms_pii,
             "PII forms include a consent checkbox.", "Consent checkbox present on PII-collecting forms."),
        ]
        matrix_laws = ["GDPR", "CCPA/CPRA", "CIPA", "India DPDP", "PDPA (SG)"]
        def _ml(ml, key):
            return key.startswith("CIPA") if ml == "CIPA" else key == ml
        rows = []
        for ftype, name, applicable, pass_desc, pass_ev in controls:
            clauses = _enrich(ftype)["clauses"]
            fail = fmap.get(ftype)
            if fail:
                status = "fail"; desc = fail.get("detail", ""); ev = fail.get("evidence", "")
                rem = "\n".join(f"{i+1}. {s}" for i, s in enumerate(fail.get("steps", [])))
            elif not applicable:
                status = "na"; desc = "Not applicable to this site."; ev = ""; rem = ""
            else:
                status = "pass"; desc = pass_desc; ev = pass_ev; rem = ""
            per_law = {}; clause_cell = {}
            for ml in matrix_laws:
                matched = [(k, v) for k, v in clauses.items() if _ml(ml, k)]
                if not matched or status == "na":
                    per_law[ml] = "na"; clause_cell[ml] = ""
                else:
                    per_law[ml] = status
                    clause_cell[ml] = "; ".join(v for _, v in matched)
            rows.append({"control": name, "ftype": ftype, "status": status,
                         "per_law": per_law, "clause_cell": clause_cell,
                         "description": desc, "evidence": ev, "remediation": rem})
        return rows

    # ── Public API ─────────────────────────────────────────────────────────
    def analyze(self, url_or_domain: str) -> dict:
        """Assess exactly ONE site. No subdomain discovery, no crawling beyond
        the page itself and its linked privacy policy."""
        if not _HAVE_REQUESTS:
            return {"error": "The 'requests' library is required but not installed."}
        domain = (url_or_domain or "").strip().lower()
        domain = re.sub(r"^https?://", "", domain).split("/")[0]
        if not domain:
            return {"error": "Enter a domain or URL to assess (e.g. example.com)."}

        self._progress(f"Starting privacy posture assessment of {domain}…")
        site = self._assess_site(domain)
        reachable = [site] if site["reachable"] else []
        if not reachable:
            if site.get("blocked"):
                return {"domain": domain, "reachable": False,
                       "error": (f"Could not safely validate {domain} — it either did not resolve, "
                                "contains characters not allowed in a plain hostname, or resolves "
                                "to a cloud instance-metadata/link-local address.")}
            if site.get("tls_error"):
                return {"domain": domain, "reachable": False,
                       "error": (f"{domain}'s HTTPS certificate failed validation and the site "
                                "could not be reached over plain HTTP either.")}
            return {"domain": domain, "reachable": False,
                   "error": f"Could not reach {domain} over HTTPS or HTTP."}

        allf = sorted(site["findings"], key=lambda f: -_sev_rank(f["sev"]))

        tp = {}
        for t in site["trackers"]:
            if t["name"] not in tp:
                tp[t["name"]] = {"name": t["name"], "category": t["category"], "data": t["data"],
                                 "laws": t["laws"], "trap_trace": t["trap_trace"],
                                 "wiretap": t["wiretap"], "sites": 1}
        third_parties = sorted(tp.values(), key=lambda x: (x["category"], x["name"]))

        law_scores = {}
        for law in LAWS:
            pen = 0
            for f in allf:
                if any(law.split(" ")[0] in l or law in l for l in f["laws"]):
                    pen += {"critical": 22, "high": 13, "medium": 6, "low": 2}.get(f["sev"], 0)
            law_scores[law] = max(0, 100 - pen)

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in allf:
            k = f["sev"].capitalize()
            if k in sev_counts:
                sev_counts[k] += 1

        catalog = self._catalog_status(reachable)
        cat_sum = {"ok": 0, "gap": 0, "part": 0, "att": 0}
        for c in catalog:
            cat_sum[c["status"]] = cat_sum.get(c["status"], 0) + 1

        overall_risk = ("Critical" if sev_counts["Critical"] else "High" if sev_counts["High"]
                        else "Medium" if allf else "Low")
        traps = [t for t in third_parties if t["trap_trace"]]
        wires = [t for t in third_parties if t["wiretap"]]

        return {
            "domain": domain, "reachable": True,
            "scan_mode": site.get("scan_mode", "static"),
            "score": site["score"], "risk": overall_risk,
            "sev_counts": sev_counts,
            "law_scores": law_scores, "laws": LAWS,
            "catalog": catalog, "catalog_summary": cat_sum,
            "third_parties": third_parties,
            "trap_trace": traps, "wiretap": wires,
            "kpi": {
                "trackers": len(third_parties),
                "preconsent": len(site["cookies"].get("nonessential", [])),
                "thirdparties": len(third_parties),
                "forms": len(site["forms"]),
                "criticals": sev_counts["Critical"],
            },
            "findings": allf,
            "site": {
                "url": site["url"], "score": site["score"], "risk": site["risk"],
                "https": site["https"], "hsts": site["hsts"], "cmp": site["cmp"],
                "banner": site.get("banner", False), "scan_mode": site.get("scan_mode", "static"),
                "net_requests": len(site.get("net_requests", [])), "dns_link": site["dns_link"],
                "trackers": len(site["trackers"]),
                "cookies_nonessential": len(site["cookies"].get("nonessential", [])),
                "forms": len(site["forms"]), "policy_found": site["policy"].get("found", False),
                "policy_missing": site["policy"].get("missing", []),
                "findings": site["findings"], "tracker_list": site["trackers"],
                "matrix": self._site_matrix(site),
            },
            "matrix_laws": ["GDPR", "CCPA/CPRA", "CIPA", "India DPDP", "PDPA (SG)"],
            "data_transfers": sorted(site.get("transfers", []),
                                     key=lambda x: (not x.get("has_pii"), x.get("third_party", "")))[:200],
        }


def assess_website(url_or_domain: str, cfg: Optional[dict] = None) -> dict:
    """Convenience function: PrivacyPostureAssessor(cfg).analyze(url_or_domain)."""
    return PrivacyPostureAssessor(cfg or {}).analyze(url_or_domain)
