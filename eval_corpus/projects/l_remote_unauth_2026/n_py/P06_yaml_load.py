from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import yaml

@app.route("/preview-yaml", methods=["POST"])
def preview_yaml():
    data = yaml.safe_load(request.data)
    return jsonify(data)
