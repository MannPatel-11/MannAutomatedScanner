#!/usr/bin/env python3
"""
MannAutomatedScanner — Flask API Server
Exposes the scanner as a REST endpoint for the frontend.

Endpoints:
  GET  /            → serves index.html
  POST /scan        → {"url": "https://..."} → JSON scan report
  GET  /health      → {"status": "ok"}
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

from MannAutomatedScanner import scan

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)  # Allow the frontend to call the API from any origin during development


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "MannAutomatedScanner"})


@app.route("/scan", methods=["POST"])
def scan_url():
    body = request.get_json(silent=True)
    if not body or not body.get("url"):
        return jsonify({"error": "Missing 'url' field in request body."}), 400

    url = body["url"].strip()
    if not url:
        return jsonify({"error": "URL must not be empty."}), 400

    # Basic sanity check — must be an HTTP/HTTPS URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = scan(url)
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "true").lower() == "true"
    print(f"  MannAutomatedScanner server starting on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
