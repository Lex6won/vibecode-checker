from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

from werkzeug.security import check_password_hash

@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(username=request.form["username"]).first()
    if user and check_password_hash(user.password_hash, request.form["password"]):
        session["user_id"] = user.id
        return redirect("/")
    return "invalid", 401
