from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import os
import uuid
from werkzeug.utils import secure_filename

UPLOAD = "/srv/app/private/uploads"
ALLOWED = {".png", ".jpg", ".pdf"}

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in ALLOWED:
        return "bad type", 400
    f.save(os.path.join(UPLOAD, uuid.uuid4().hex + ext))
    return "ok"
