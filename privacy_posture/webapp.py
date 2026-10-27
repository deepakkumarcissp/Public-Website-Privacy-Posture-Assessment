"""Minimal local web UI for the Public Website Privacy Posture Assessment.

Run with:
    dkcissp-privacy-assessment-web
or:
    python -m privacy_posture.webapp

Then open http://127.0.0.1:1009 and enter a domain you own or are authorized
to assess. The scan only loads pages the site serves to any ordinary visitor
— it never submits forms, logs in, or does anything beyond what a browser
visiting the page would do.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import secrets
import threading

from flask import Flask, Response, abort, jsonify, render_template, request

from .engine import PrivacyPostureAssessor

app = Flask(__name__)
_log = logging.getLogger("dkcissp.privacy_posture")

_TOKEN_COOKIE = "dkcissp_token"

# Per-process secret, known only to pages this server itself rendered. Every
# state-changing/scan-triggering request must present it. This is the primary
# defense against a malicious page in another tab (or a DNS-rebinding attack)
# using this unauthenticated localhost server as a blind request proxy —
# without the token, a cross-origin page cannot trigger a scan even though
# the server listens on 127.0.0.1 with no login.
#
# Delivered as an HttpOnly, SameSite=Strict cookie (set when "/" loads)
# rather than a URL query parameter: a token in a URL ends up in the
# webserver's own access log — which, run under systemd, is persisted
# indefinitely in the journal — and in browser history. A cookie is sent
# automatically by the browser on same-origin requests (including the
# EventSource call, which cannot set custom headers) without ever appearing
# in a URL. A request header is still accepted too, for non-browser/API use.
_SESSION_TOKEN = secrets.token_urlsafe(24)

# At most one scan running at a time. This is a single-user local tool with
# no account system; unbounded concurrent scans (each potentially spawning
# its own Chromium process) have no natural backpressure otherwise.
_scan_slot = threading.Semaphore(1)


@app.before_request
def _restrict_to_local_browser():
    # Reject any request whose Host header isn't this exact local address —
    # this is what defeats DNS rebinding (an external domain that resolves to
    # 127.0.0.1): the browser's Host header still carries the external name,
    # which won't match here even though the IP is local.
    allowed_hosts = {f"127.0.0.1:{request.environ.get('SERVER_PORT', '')}",
                     f"localhost:{request.environ.get('SERVER_PORT', '')}"}
    if request.host not in allowed_hosts:
        abort(403)


def _check_token():
    token = (request.headers.get("X-DKCISSP-Token")
             or request.cookies.get(_TOKEN_COOKIE)
             or request.args.get("token"))
    if not token or not secrets.compare_digest(token, _SESSION_TOKEN):
        abort(403)


@app.route("/")
def index():
    resp = Response(render_template("index.html"))
    # HttpOnly: inaccessible to page JavaScript (nothing needs to read it —
    # the browser just needs to send it back). SameSite=Strict: never sent
    # on a cross-site request, a second layer behind the Host-header check
    # above. Not Secure since this is plain-HTTP loopback-only by design.
    resp.set_cookie(_TOKEN_COOKIE, _SESSION_TOKEN, httponly=True, samesite="Strict")
    return resp


def _run_analysis(domain: str, no_headless: bool, on_progress=None) -> dict:
    """Shared analysis runner with a generic error message for the caller —
    the real exception is logged server-side only, never echoed back, so an
    unexpected internal failure can't leak file paths or internal state."""
    analyzer = PrivacyPostureAssessor(cfg={"headless": not no_headless}, on_progress=on_progress)
    try:
        return analyzer.analyze(domain)
    except Exception:
        _log.exception("Assessment of %r failed", domain)
        return {"error": "Assessment failed due to an internal error. See the server log for details."}


@app.route("/api/assess", methods=["POST"])
def api_assess():
    _check_token()
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "Enter a domain or URL to assess."}), 400

    no_headless = bool(data.get("no_headless"))
    if not _scan_slot.acquire(blocking=False):
        return jsonify({"error": "Another assessment is already running — wait for it to finish."}), 429
    try:
        result = _run_analysis(domain, no_headless)
    finally:
        _scan_slot.release()
    if result.get("error"):
        return jsonify(result), 422
    return jsonify(result)


@app.route("/api/assess-stream")
def api_assess_stream():
    """Server-Sent Events: live progress lines while the scan runs, ending
    with one 'result' event carrying the full JSON result."""
    _check_token()
    domain = (request.args.get("domain") or "").strip()
    no_headless = request.args.get("no_headless") == "1"
    if not domain:
        return jsonify({"error": "Enter a domain or URL to assess."}), 400

    if not _scan_slot.acquire(blocking=False):
        return jsonify({"error": "Another assessment is already running — wait for it to finish."}), 429

    q: "queue.Queue" = queue.Queue()

    def worker():
        try:
            result = _run_analysis(domain, no_headless, on_progress=lambda msg: q.put(("progress", msg)))
        finally:
            _scan_slot.release()
        q.put(("result", result))

    threading.Thread(target=worker, daemon=True).start()

    def stream():
        while True:
            kind, payload = q.get()
            if kind == "progress":
                yield f"event: progress\ndata: {json.dumps(payload)}\n\n"
            else:
                yield f"event: result\ndata: {json.dumps(payload, default=str)}\n\n"
                break

    return Response(stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def main():
    port = int(os.environ.get("PORT", "1009"))
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
