from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import subprocess

@app.route("/ping")
def ping():
    host = request.args["host"]
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return out.stdout
