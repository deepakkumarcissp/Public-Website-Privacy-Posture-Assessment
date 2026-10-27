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
import os
import queue
import secrets
import threading

from flask import Flask, Response, abort, jsonify, render_template, request

from .engine import PrivacyPostureAssessor

app = Flask(__name__)

# Per-process secret, known only to pages this server itself rendered. Every
# state-changing/scan-triggering request must present it. This is the primary
# defense against a malicious page in another tab (or a DNS-rebinding attack)
# using this unauthenticated localhost server as a blind request proxy —
# without the token, a cross-origin page cannot trigger a scan even though
# the server listens on 127.0.0.1 with no login.
_SESSION_TOKEN = secrets.token_urlsafe(24)


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
    token = request.headers.get("X-DKCISSP-Token") or request.args.get("token")
    if not token or not secrets.compare_digest(token, _SESSION_TOKEN):
        abort(403)


@app.route("/")
def index():
    return render_template("index.html", session_token=_SESSION_TOKEN)


@app.route("/api/assess", methods=["POST"])
def api_assess():
    _check_token()
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "Enter a domain or URL to assess."}), 400

    no_headless = bool(data.get("no_headless"))
    analyzer = PrivacyPostureAssessor(cfg={"headless": not no_headless})
    try:
        result = analyzer.analyze(domain)
    except Exception as e:
        return jsonify({"error": f"Assessment failed: {e}"}), 500
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

    q: "queue.Queue" = queue.Queue()

    def worker():
        analyzer = PrivacyPostureAssessor(cfg={"headless": not no_headless},
                                          on_progress=lambda msg: q.put(("progress", msg)))
        try:
            result = analyzer.analyze(domain)
        except Exception as e:
            result = {"error": f"Assessment failed: {e}"}
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
