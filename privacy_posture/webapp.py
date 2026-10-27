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

import concurrent.futures
import json
import logging
import os
import queue
import secrets
import threading
import time

from flask import Flask, Response, abort, jsonify, render_template, request

from .engine import PrivacyPostureAssessor

app = Flask(__name__)
_log = logging.getLogger("dkcissp.privacy_posture")

# Per-process secret, known only to pages this server itself rendered (never
# a cookie): every scan-triggering request must present it in a header. A
# cookie would be sent by the browser AMBIENTLY — automatically, on any
# matching request, without the calling script needing to know its value —
# which is exactly the property CSRF defenses must avoid relying on alone.
# A header must be set explicitly by JavaScript that has actually read this
# value, which a cross-origin page cannot do. It's embedded directly in the
# rendered page (never a URL) so it never reaches a browser history entry or
# the webserver's own access log (which, run under systemd, journald
# persists indefinitely).
_SESSION_TOKEN = secrets.token_urlsafe(24)

# At most one scan running at a time. This is a single-user local tool with
# no account system; unbounded concurrent scans (each potentially spawning
# its own Chromium process) have no natural backpressure otherwise.
_scan_slot = threading.Semaphore(1)

# Hard ceiling on how long any single assessment is allowed to make a caller
# wait. Every individual network/CDP call inside the engine already carries
# its own timeout, but there was no TOP-LEVEL deadline tying them together —
# a pathological stacking of several near-worst-case waits could still leave
# a request (and the scan slot above) hanging far longer than any one
# component's own timeout suggests. Exceeding this deadline gives the caller
# a definitive answer and frees the scan slot for the next request; it does
# not forcibly kill the still-running analysis thread, which is expected to
# finish on its own shortly after via its own nested timeouts.
_ANALYSIS_DEADLINE_S = 120

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="dkcissp-scan")


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
    token = request.headers.get("X-DKCISSP-Token")
    if not token or not secrets.compare_digest(token, _SESSION_TOKEN):
        abort(403)


@app.route("/")
def index():
    return render_template("index.html", session_token=_SESSION_TOKEN)


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
        future = _executor.submit(_run_analysis, domain, no_headless)
        try:
            result = future.result(timeout=_ANALYSIS_DEADLINE_S)
        except concurrent.futures.TimeoutError:
            _log.error("Assessment of %r exceeded the %ss deadline", domain, _ANALYSIS_DEADLINE_S)
            result = {"error": f"Assessment timed out after {_ANALYSIS_DEADLINE_S}s."}
    finally:
        _scan_slot.release()
    if result.get("error"):
        return jsonify(result), 422
    return jsonify(result)


@app.route("/api/assess-stream", methods=["POST"])
def api_assess_stream():
    """Server-Sent-Events-style stream (read with fetch(), not EventSource —
    EventSource can only ever issue GET with no custom headers, which would
    force the auth token back into the URL/query string). Live progress
    lines while the scan runs, ending with one 'result' event carrying the
    full JSON result."""
    _check_token()
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    no_headless = bool(data.get("no_headless"))
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
        deadline = time.monotonic() + _ANALYSIS_DEADLINE_S
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _log.error("Assessment of %r exceeded the %ss deadline", domain, _ANALYSIS_DEADLINE_S)
                payload = {"error": f"Assessment timed out after {_ANALYSIS_DEADLINE_S}s."}
                yield f"event: result\ndata: {json.dumps(payload)}\n\n"
                return
            try:
                kind, payload = q.get(timeout=remaining)
            except queue.Empty:
                continue
            if kind == "progress":
                yield f"event: progress\ndata: {json.dumps(payload)}\n\n"
            else:
                yield f"event: result\ndata: {json.dumps(payload, default=str)}\n\n"
                return

    return Response(stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def main():
    port = int(os.environ.get("PORT", "1009"))
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
