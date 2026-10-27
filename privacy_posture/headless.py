"""
Headless-Chromium privacy probe over the Chrome DevTools Protocol (CDP).

No Playwright/Selenium dependency (the platform venv is root-owned and can't be
pip-installed into) — this drives the system Chromium binary directly via CDP
over a WebSocket (websocket-client, which IS available). It measures what a
static fetch cannot:

  • network beacons actually fired (incl. dynamically-injected trackers)
  • cookies set BEFORE any consent (the no-interaction state)
  • the consent flow: find & click "Reject All", then "Accept All", and diff the
    cookie/beacon state → proves whether the CMP truly blocks trackers pre-consent
  • GPC honoring (loads with Sec-GPC and compares)

Returns a dict the assessor merges with its static detection. Fully guarded:
any failure returns {"ok": False, "error": ...} so the assessor falls back to
the static path — the dynamic scan is an enhancement, never a hard dependency.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlparse
from urllib.request import urlopen

try:
    import websocket  # websocket-client (sync)
    _HAVE_WS = True
except Exception:
    _HAVE_WS = False


def _chromium_bin() -> str:
    for b in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"):
        p = shutil.which(b)
        if p:
            return p
    for p in ("/usr/bin/chromium", "/usr/bin/google-chrome"):
        if os.path.exists(p):
            return p
    return ""


def available() -> bool:
    return _HAVE_WS and bool(_chromium_bin())


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _CDP:
    """Minimal CDP client: one browser, one page target (flatten sessions)."""
    def __init__(self, port: int):
        self._id = 0
        self.port = port
        self.session_id = None
        self.ws = None

    def _browser_ws(self, tries=40):
        for _ in range(tries):
            try:
                with urlopen(f"http://127.0.0.1:{self.port}/json/version", timeout=1) as r:
                    return json.loads(r.read()).get("webSocketDebuggerUrl")
            except Exception:
                time.sleep(0.25)
        return None

    def connect(self) -> bool:
        url = self._browser_ws()
        if not url:
            return False
        # Chromium >=111 rejects the WS upgrade if an Origin header is present
        # (hardening against websites poking the debug port) → suppress_origin.
        self.ws = websocket.create_connection(url, max_size=None,
                                               enable_multithread=True, timeout=30,
                                               suppress_origin=True)
        tid = self.send("Target.createTarget", {"url": "about:blank"}).get("targetId")
        if not tid:
            return False
        self.session_id = self.send("Target.attachToTarget",
                                    {"targetId": tid, "flatten": True}).get("sessionId")
        return bool(self.session_id)

    def send(self, method, params=None, session=True, timeout=30):
        self._id += 1
        mid = self._id
        msg = {"id": mid, "method": method, "params": params or {}}
        if session and self.session_id:
            msg["sessionId"] = self.session_id
        self.ws.send(json.dumps(msg))
        end = time.time() + timeout
        while time.time() < end:
            self.ws.settimeout(max(0.1, end - time.time()))
            try:
                raw = self.ws.recv()
            except Exception:
                break
            try:
                m = json.loads(raw)
            except Exception:
                continue
            if m.get("id") == mid:
                return m.get("result", {}) or {}
            self._events.append(m)
        return {}

    _events: list = None

    def drain_events(self, seconds: float):
        """Collect CDP events for a settle window."""
        end = time.time() + seconds
        while time.time() < end:
            self.ws.settimeout(max(0.05, end - time.time()))
            try:
                raw = self.ws.recv()
            except Exception:
                break
            try:
                self._events.append(json.loads(raw))
            except Exception:
                continue

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def _requests_from(events: list) -> list:
    out = []
    for e in events:
        if e.get("method") == "Network.requestWillBeSent":
            u = ((e.get("params") or {}).get("request") or {}).get("url", "")
            if u.startswith("http"):
                out.append(u)
    return out


def _transfers_from(events: list) -> list:
    """Structured outbound requests: method, url, POST body (truncated), resource
    type, and the initiator (script/page that triggered it) — the raw material
    for the third-party data-transfer inventory."""
    out, seen = [], set()
    for e in events:
        if e.get("method") != "Network.requestWillBeSent":
            continue
        p = e.get("params") or {}
        req = p.get("request") or {}
        u = req.get("url", "")
        if not u.startswith("http"):
            continue
        method = req.get("method", "GET")
        key = (method, u[:300])
        if key in seen:
            continue
        seen.add(key)
        init = p.get("initiator") or {}
        out.append({
            "method": method, "url": u,
            "postData": (req.get("postData") or "")[:600],
            "type": p.get("type", ""),
            "doc": p.get("documentURL", ""),
            "initiator": init.get("url") or init.get("type") or "",
        })
    return out


def _doc_headers(events: list) -> dict:
    """Response headers of the first main-document response (for HSTS/CSP)."""
    for e in events:
        if e.get("method") == "Network.responseReceived":
            p = e.get("params") or {}
            if p.get("type") == "Document":
                hdrs = (p.get("response") or {}).get("headers") or {}
                return {k.lower(): v for k, v in hdrs.items()}
    return {}


def scan(url: str, settle: float = 4.0, consent: bool = True, gpc: bool = False,
         timeout: int = 45) -> dict:
    """Load `url` in headless Chromium and measure privacy behaviour."""
    if not available():
        return {"ok": False, "error": "headless chromium/websocket unavailable"}
    binp = _chromium_bin()
    port = _free_port()
    tmp = tempfile.mkdtemp(prefix="privscan_")
    args = [binp, "--headless=new", "--disable-gpu", "--no-sandbox",
            "--disable-dev-shm-usage", "--disable-extensions", "--mute-audio",
            "--disable-background-networking", "--no-first-run", "--no-default-browser-check",
            "--disable-features=Translate,BackForwardCache",
            f"--remote-debugging-port={port}", f"--user-data-dir={tmp}", "about:blank"]
    proc = None
    cdp = _CDP(port)
    cdp._events = []
    try:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not cdp.connect():
            return {"ok": False, "error": "could not attach to chromium"}
        cdp.send("Network.enable")
        cdp.send("Page.enable")
        if gpc:
            cdp.send("Network.setExtraHTTPHeaders", {"headers": {"Sec-GPC": "1", "DNT": "1"}})
        # instrument device-fingerprinting APIs BEFORE any page script runs, so we
        # can tell if the site probes canvas/WebGL/font-metrics/audio for a device id.
        fp_hook = (
            "window.__fp={canvas:false,webgl:false,fonts:false,audio:false};"
            "try{var _t=HTMLCanvasElement.prototype.toDataURL;HTMLCanvasElement.prototype.toDataURL=function(){window.__fp.canvas=true;return _t.apply(this,arguments)};"
            "var _g=CanvasRenderingContext2D.prototype.getImageData;CanvasRenderingContext2D.prototype.getImageData=function(){window.__fp.canvas=true;return _g.apply(this,arguments)};}catch(e){}"
            "try{var _w=WebGLRenderingContext.prototype.getParameter;WebGLRenderingContext.prototype.getParameter=function(p){if(p===37445||p===37446)window.__fp.webgl=true;return _w.apply(this,arguments)};}catch(e){}"
            "try{var _m=CanvasRenderingContext2D.prototype.measureText;CanvasRenderingContext2D.prototype.measureText=function(){window.__fp.fonts=true;return _m.apply(this,arguments)};}catch(e){}"
            "try{var _A=window.AudioContext||window.webkitAudioContext;if(_A){var _o=_A.prototype.createOscillator;_A.prototype.createOscillator=function(){window.__fp.audio=true;return _o.apply(this,arguments)};}}catch(e){}"
        )
        try:
            cdp.send("Page.addScriptToEvaluateOnNewDocument", {"source": fp_hook})
        except Exception:
            pass
        # ── pre-consent load ──
        cdp._events = []
        cdp.send("Page.navigate", {"url": url}, timeout=timeout)
        cdp.drain_events(settle)
        pre_requests = _requests_from(cdp._events)
        pre_cookies = (cdp.send("Network.getAllCookies") or {}).get("cookies", [])
        html = ""
        try:
            r = cdp.send("Runtime.evaluate",
                         {"expression": "document.documentElement.outerHTML", "returnByValue": True})
            html = ((r.get("result") or {}).get("value") or "")
        except Exception:
            pass
        final_url = url
        try:
            r = cdp.send("Runtime.evaluate", {"expression": "location.href", "returnByValue": True})
            final_url = ((r.get("result") or {}).get("value") or url)
        except Exception:
            pass
        fingerprint = {}
        try:
            r = cdp.send("Runtime.evaluate", {"expression": "JSON.stringify(window.__fp||{})", "returnByValue": True})
            fingerprint = json.loads(((r.get("result") or {}).get("value")) or "{}")
        except Exception:
            fingerprint = {}

        def _cookie_names(cks):
            return [{"name": c.get("name"), "domain": c.get("domain"),
                     "secure": c.get("secure"), "httpOnly": c.get("httpOnly"),
                     "sameSite": c.get("sameSite")} for c in cks]

        result = {
            "ok": True, "final_url": final_url,
            "doc_headers": _doc_headers(cdp._events),
            "pre_requests": sorted(set(pre_requests)),
            "transfers": _transfers_from(cdp._events),
            "pre_cookies": _cookie_names(pre_cookies),
            "fingerprint": {k: bool(v) for k, v in fingerprint.items()},
            "html": html,
            "consent": {"tested": False},
        }

        if consent:
            # find a consent banner + reject/accept controls
            probe = r"""(function(){
              var t=(document.body?document.body.innerText:'')||'';
              function findBtn(words){
                var els=[].slice.call(document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit],span,div'));
                for(var i=0;i<els.length;i++){var s=(els[i].innerText||els[i].value||'').trim().toLowerCase();
                  if(!s||s.length>40)continue;
                  for(var j=0;j<words.length;j++){if(s.indexOf(words[j])!==-1)return true;}}
                return false;}
              return JSON.stringify({
                banner: /cookie|consent|privacy|gdpr|ccpa/i.test(t) && /accept|agree|reject|manage|preferences/i.test(t),
                reject: findBtn(['reject all','reject','decline','refuse','deny','necessary only','essential only']),
                accept: findBtn(['accept all','accept','agree','allow all','got it','i agree']),
                manage: findBtn(['manage','preferences','settings','customi','choices'])
              });})()"""
            try:
                pr = cdp.send("Runtime.evaluate", {"expression": probe, "returnByValue": True})
                info = json.loads(((pr.get("result") or {}).get("value")) or "{}")
            except Exception:
                info = {}
            result["consent"] = {"tested": True, "banner": bool(info.get("banner")),
                                 "reject_present": bool(info.get("reject")),
                                 "accept_present": bool(info.get("accept")),
                                 "granular_present": bool(info.get("manage"))}
            # ── reject-flow: click 'Reject All' and re-measure to PROVE the CMP blocks ──
            if info.get("reject"):
                clicker = (
                    "(function(){var w=['reject all','reject','decline','refuse','deny','necessary only','essential only'];"
                    "var els=[].slice.call(document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]'));"
                    "for(var i=0;i<els.length;i++){var s=(els[i].innerText||els[i].value||'').trim().toLowerCase();"
                    "if(!s||s.length>40)continue;for(var j=0;j<w.length;j++){if(s.indexOf(w[j])!==-1){try{els[i].click();return true;}catch(e){}}}}return false;})()"
                )
                try:
                    cdp._events = []
                    cr = cdp.send("Runtime.evaluate", {"expression": clicker, "returnByValue": True})
                    clicked = bool((cr.get("result") or {}).get("value"))
                    cdp.drain_events(3.0)
                    post_reject_requests = _requests_from(cdp._events)
                    post_reject_cookies = (cdp.send("Network.getAllCookies") or {}).get("cookies", [])
                    result["consent"]["reject_clicked"] = clicked
                    result["post_reject"] = {"requests": sorted(set(post_reject_requests)),
                                             "cookies": _cookie_names(post_reject_cookies)}
                except Exception:
                    pass
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:160]}"}
    finally:
        cdp.close()
        if proc:
            try:
                proc.terminate(); proc.wait(timeout=5)
            except Exception:
                try: proc.kill()
                except Exception: pass
        shutil.rmtree(tmp, ignore_errors=True)
    return result


def third_party_hosts(requests: list, site_host: str) -> list:
    """Distinct third-party (different registrable domain) hosts from request URLs."""
    def reg(host):
        parts = (host or "").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    base = reg(site_host)
    out = {}
    for u in requests:
        try:
            h = urlparse(u).hostname or ""
        except Exception:
            continue
        if h and reg(h) != base:
            out[h] = out.get(h, 0) + 1
    return sorted(out.keys())
