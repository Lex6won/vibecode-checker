from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import json

@app.route("/restore", methods=["POST"])
def restore():
    state = json.loads(request.data)
    return jsonify(state)
