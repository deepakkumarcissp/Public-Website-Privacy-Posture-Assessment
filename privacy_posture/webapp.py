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
import threading

from flask import Flask, Response, jsonify, render_template, request

from .engine import PrivacyPostureAssessor

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/assess", methods=["POST"])
def api_assess():
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
