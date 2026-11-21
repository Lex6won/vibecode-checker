from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.go.kr"}

@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        return "forbidden", 403
    resp = requests.get("https://api.example.go.kr/status", timeout=5)
    return resp.text
