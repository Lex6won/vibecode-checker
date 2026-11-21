from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import pickle

@app.route("/restore", methods=["POST"])
def restore():
    state = pickle.loads(request.data)
    return jsonify(state)
