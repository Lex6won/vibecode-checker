from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import jwt

@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    claims = jwt.decode(token, options={"verify_signature": False})
    if claims.get("role") == "admin":
        return jsonify(all_users())
    return jsonify({"user": claims.get("sub")})
