from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

from werkzeug.utils import secure_filename

BASE = "/srv/app/files"

@app.route("/download")
def download():
    name = secure_filename(request.args.get("name", ""))
    return send_from_directory(BASE, name)
