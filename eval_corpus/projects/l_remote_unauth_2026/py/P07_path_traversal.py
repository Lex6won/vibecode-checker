from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import os

BASE = "/srv/app/files"

@app.route("/download")
def download():
    name = request.args.get("name")
    return send_file(os.path.join(BASE, name))
