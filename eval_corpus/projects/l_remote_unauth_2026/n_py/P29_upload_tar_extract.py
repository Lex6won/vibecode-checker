from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import tarfile

@app.route("/import-archive", methods=["POST"])
def import_archive():
    upload = request.files["archive"]
    with tarfile.open(fileobj=upload.stream) as tar:
        tar.extractall("/srv/app/data", filter="data")
    return "ok"
