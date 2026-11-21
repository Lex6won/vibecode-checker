from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import requests

@app.route("/preview")
def preview():
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return resp.text
