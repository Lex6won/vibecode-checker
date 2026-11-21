from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import subprocess
import ipaddress

@app.route("/ping")
def ping():
    host = str(ipaddress.ip_address(request.args["host"]))
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return out.stdout
