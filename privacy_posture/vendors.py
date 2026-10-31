"""
Third-party tracker / vendor catalog for the website privacy assessment.

Each entry maps a host/URL substring found in a page's scripts, pixels, iframes
or cookies to a named vendor with its category, the personal data it typically
captures, and the privacy laws it implicates. Two flags carry the CIPA
litigation theories:
  • trap_trace  — captures visitor IP / device / routing identifiers and sends
                  them to a third party (CIPA §638.51 "pen register / trap and
                  trace" theory).
  • wiretap     — intercepts the visitor's interaction/communication, e.g.
                  session-replay or live-chat capture (CIPA §631 wiretapping).

Config-extendable via cfg["privacy_vendor_extra"] (same shape as _CATALOG rows).
"""
from __future__ import annotations

# (host_substrings, name, category, data_captured, laws, trap_trace, wiretap)
_CATALOG = [
    # ── Analytics ────────────────────────────────────────────────────────────
    (["google-analytics.com", "googletagmanager.com/gtag", "/gtag/js", "analytics.google.com"],
     "Google Analytics", "Analytics", "IP, client ID, page & behaviour",
     ["GDPR", "CIPA §638.51"], True, False),
    (["googletagmanager.com"], "Google Tag Manager", "Tag manager",
     "loads other tags (container)", ["GDPR"], False, False),
    (["stats.g.doubleclick.net"], "Google DoubleClick (analytics)", "Analytics",
     "IP, ad/cookie IDs", ["GDPR", "CCPA/CPRA", "CIPA §638.51"], True, False),
    (["adobe.com/b/ss", "omtrdc.net", "demdex.net", "adobedtm.com"],
     "Adobe Analytics / Experience Cloud", "Analytics", "IP, visitor ID, behaviour",
     ["GDPR", "CIPA §638.51"], True, False),
    (["plausible.io", "matomo", "piwik"], "Privacy-analytics (Plausible/Matomo)",
     "Analytics", "aggregated (often cookieless)", ["GDPR"], False, False),
    (["cdn.segment.com", "segment.io"], "Segment (CDP)", "Analytics / CDP",
     "IP, traits, events routed to many tools", ["GDPR", "CCPA/CPRA"], True, False),
    (["static.hotjar.com", "hotjar.com"], "Hotjar", "Session replay",
     "session recording, mouse, form input", ["GDPR", "CIPA §631"], True, True),
    (["clarity.ms"], "Microsoft Clarity", "Session replay",
     "keystrokes, mouse, form input", ["GDPR", "CIPA §631"], True, True),
    (["fullstory.com", "fs.js"], "FullStory", "Session replay",
     "full session incl. inputs", ["GDPR", "CIPA §631"], True, True),
    (["mouseflow.com"], "Mouseflow", "Session replay",
     "session recording, forms", ["GDPR", "CIPA §631"], True, True),
    (["luckyorange.com"], "Lucky Orange", "Session replay",
     "session recording, chat", ["GDPR", "CIPA §631"], True, True),
    (["smartlook.com"], "Smartlook", "Session replay",
     "session recording", ["GDPR", "CIPA §631"], True, True),
    # ── Advertising / retargeting ────────────────────────────────────────────
    (["connect.facebook.net", "facebook.com/tr", "fbevents.js", "fbq("],
     "Meta Pixel", "Advertising", "IP, device fingerprint, events, form data",
     ["GDPR", "CCPA/CPRA", "CIPA §638.51"], True, False),
    (["analytics.tiktok.com", "tiktok.com/i18n/pixel"], "TikTok Pixel", "Advertising",
     "IP, device, events", ["CCPA/CPRA", "CIPA §638.51"], True, False),
    (["snap.licdn.com", "px.ads.linkedin.com", "linkedin.com/li"], "LinkedIn Insight Tag",
     "Advertising", "IP, member ID, company", ["GDPR", "CCPA/CPRA"], True, False),
    (["googleadservices.com", "googlesyndication.com", "doubleclick.net", "google.com/ads",
      "/pagead/"], "Google Ads / DoubleClick", "Advertising", "IP, ad IDs, conversions",
     ["CCPA/CPRA", "CIPA §638.51"], True, False),
    (["bat.bing.com", "clarity.ms/bat"], "Microsoft/Bing Ads (UET)", "Advertising",
     "IP, click IDs", ["CCPA/CPRA", "CIPA §638.51"], True, False),
    (["ads.twitter.com", "static.ads-twitter.com", "t.co/i/adsct"], "X/Twitter Ads Pixel",
     "Advertising", "IP, device, events", ["CCPA/CPRA", "CIPA §638.51"], True, False),
    (["pinterest.com/ct", "pintrk"], "Pinterest Tag", "Advertising",
     "IP, events", ["CCPA/CPRA"], True, False),
    (["reddit.com/pixel", "redditstatic.com/ads"], "Reddit Pixel", "Advertising",
     "IP, events", ["CCPA/CPRA"], True, False),
    (["quantserve.com", "scorecardresearch.com"], "Quantcast / Comscore", "Advertising",
     "IP, cross-site profile", ["GDPR", "CCPA/CPRA", "CIPA §638.51"], True, False),
    (["criteo.com", "criteo.net"], "Criteo", "Advertising", "IP, retargeting profile",
     ["GDPR", "CCPA/CPRA"], True, False),
    (["taboola.com"], "Taboola", "Advertising", "IP, behaviour", ["CCPA/CPRA"], True, False),
    (["outbrain.com"], "Outbrain", "Advertising", "IP, behaviour", ["CCPA/CPRA"], True, False),
    # ── Marketing / CRM ──────────────────────────────────────────────────────
    (["js.hs-scripts.com", "hs-analytics.net", "hubspot.com", "hsforms"], "HubSpot",
     "Marketing / CRM", "IP, cookie, form data", ["GDPR", "CCPA/CPRA"], True, False),
    (["munchkin.js", "marketo.net", "mktoresp"], "Marketo", "Marketing / CRM",
     "IP, lead activity", ["GDPR"], True, False),
    (["pardot.com", "pi.pardot"], "Salesforce Pardot", "Marketing / CRM",
     "IP, prospect activity", ["GDPR"], True, False),
    (["salesforce.com", "force.com", "pardot"], "Salesforce", "Marketing / CRM",
     "IP, lead/contact data", ["GDPR"], False, False),
    (["6sc.co", "6sense"], "6sense", "Marketing / ABM", "IP → company de-anonymisation",
     ["GDPR", "CCPA/CPRA"], True, False),
    (["leadfeeder", "dealfront"], "Leadfeeder/Dealfront", "Marketing / ABM",
     "IP → company de-anonymisation", ["GDPR", "CCPA/CPRA"], True, False),
    # ── Chat / AI ────────────────────────────────────────────────────────────
    (["widget.intercom.io", "intercom.com", "intercomcdn"], "Intercom", "Chat / AI",
     "chat content, email, IP", ["GDPR", "CIPA §631"], False, True),
    (["js.driftt.com", "drift.com"], "Drift", "Chat / AI", "chat content, IP",
     ["GDPR", "CIPA §631"], False, True),
    (["static.zdassets.com", "zendesk", "zopim"], "Zendesk / Zopim Chat", "Chat / AI",
     "chat content, IP", ["GDPR", "CIPA §631"], False, True),
    (["tawk.to"], "Tawk.to", "Chat / AI", "chat content, IP", ["GDPR", "CIPA §631"], False, True),
    (["livechatinc.com", "livechat"], "LiveChat", "Chat / AI", "chat content, IP",
     ["GDPR", "CIPA §631"], False, True),
    (["crisp.chat"], "Crisp Chat", "Chat / AI", "chat content, IP", ["GDPR", "CIPA §631"], False, True),
    # ── CAPTCHA ──────────────────────────────────────────────────────────────
    (["google.com/recaptcha", "gstatic.com/recaptcha", "recaptcha.net"], "Google reCAPTCHA",
     "CAPTCHA", "IP, device, behavioural signals", ["GDPR", "CIPA §638.51"], True, False),
    (["hcaptcha.com"], "hCaptcha", "CAPTCHA", "IP, device", ["GDPR"], True, False),
    (["challenges.cloudflare.com", "turnstile"], "Cloudflare Turnstile", "CAPTCHA",
     "IP, device (privacy-preserving)", ["GDPR"], False, False),
    # ── Embedded content / social ────────────────────────────────────────────
    (["youtube.com/embed", "youtube-nocookie.com", "ytimg.com"], "YouTube (embed)",
     "Embedded content", "IP, device (cookies unless -nocookie)", ["GDPR"], True, False),
    (["player.vimeo.com", "vimeo.com"], "Vimeo (embed)", "Embedded content",
     "IP, device", ["GDPR"], True, False),
    (["google.com/maps", "maps.googleapis.com", "maps.gstatic.com"], "Google Maps (embed)",
     "Embedded content", "IP, approx location", ["GDPR"], True, False),
    (["platform.twitter.com", "syndication.twitter.com"], "X/Twitter (embed)",
     "Embedded content / social", "IP, device", ["GDPR"], True, False),
    (["instagram.com/embed", "cdninstagram"], "Instagram (embed)", "Embedded content / social",
     "IP, device", ["GDPR"], True, False),
    (["platform.linkedin.com"], "LinkedIn (embed)", "Embedded content / social",
     "IP, device", ["GDPR"], True, False),
    (["disqus.com"], "Disqus", "Embedded content / social", "IP, profile, comments",
     ["GDPR", "CCPA/CPRA"], True, False),
    (["addthis.com", "sharethis.com"], "AddThis / ShareThis", "Social sharing",
     "IP, cross-site profile", ["GDPR", "CCPA/CPRA", "CIPA §638.51"], True, False),
    # ── Consent managers (presence = good signal, not a tracker) ──────────────
    (["cookieyes.com", "cookie-law-info", "cookieconsent", "cookiebot", "onetrust",
      "cookielaw.org", "usercentrics", "termly.io", "iubenda", "osano.com",
      "trustarc", "quantcast.mgr.consensu", "cmp.osano"], "__CMP__", "Consent manager",
     "consent management platform", [], False, False),
]

# CMP detector names (a subset of _CATALOG whose name is __CMP__) mapped to a
# friendly label for the consent check.
_CMP_HOSTS = {
    "cookieyes": "CookieYes", "cookie-law-info": "CookieYes",
    "onetrust": "OneTrust", "cookielaw.org": "OneTrust",
    "cookiebot": "Cookiebot", "usercentrics": "Usercentrics",
    "termly.io": "Termly", "iubenda": "Iubenda", "osano": "Osano",
    "trustarc": "TrustArc", "cookieconsent": "CookieConsent", "quantcast.mgr": "Quantcast CMP",
}


def _cfg_extra(cfg: dict):
    rows = (cfg or {}).get("privacy_vendor_extra") or []
    out = []
    for r in rows:
        try:
            out.append((r["hosts"], r["name"], r.get("category", "Other"),
                        r.get("data", ""), r.get("laws", []),
                        bool(r.get("trap_trace")), bool(r.get("wiretap"))))
        except Exception:
            continue
    return out


def detect(html: str, extra_urls=None, cfg: dict = None) -> list[dict]:
    """Return the list of third-party vendors detected in a page.

    Scans the raw HTML (script/img/iframe srcs + inline snippets) plus any extra
    resource URLs the caller captured. Each hit → one dict with vendor metadata.
    The consent-manager entry (__CMP__) is returned separately-flagged so the
    caller can treat it as a control, not a tracker."""
    hay = (html or "").lower()
    extra = " ".join(extra_urls or []).lower()
    hay_all = hay + " " + extra
    seen = set()
    out = []
    for hosts, name, cat, data, laws, trap, wire in (_CATALOG + _cfg_extra(cfg)):
        if name in seen:
            continue
        if any(h.lower() in hay_all for h in hosts):
            seen.add(name)
            is_cmp = (name == "__CMP__")
            cmp_label = ""
            if is_cmp:
                for k, lbl in _CMP_HOSTS.items():
                    if k in hay_all:
                        cmp_label = lbl
                        break
                cmp_label = cmp_label or "a consent platform"
            out.append({
                "name": name, "category": cat, "data": data, "laws": list(laws),
                "trap_trace": trap, "wiretap": wire,
                "is_cmp": is_cmp, "cmp_label": cmp_label,
            })
    return out


def detect_fired(request_urls, cfg: dict = None) -> set:
    """Names of non-CMP vendors with at least one OBSERVED network request.

    Unlike detect(), this ignores page HTML: a script tag that is present but
    inert (e.g. held back by a consent manager with type="text/plain") is not
    a tracker that fired."""
    return {v["name"] for v in detect("", extra_urls=request_urls, cfg=cfg) if not v["is_cmp"]}


def is_ai_or_chat(vendor: dict) -> bool:
    return vendor.get("category") == "Chat / AI"
