from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    if request.form["username"] == "admin" and request.form["password"] == "P@ssw0rd":
        session["is_admin"] = True
        return redirect("/admin")
    return "invalid", 401
