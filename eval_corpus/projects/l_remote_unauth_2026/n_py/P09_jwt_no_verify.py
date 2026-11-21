from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import os
import jwt

KEY = os.environ["JWT_KEY"]

@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    claims = jwt.decode(token, KEY, algorithms=["HS256"])
    return jsonify({"user": claims.get("sub")})
