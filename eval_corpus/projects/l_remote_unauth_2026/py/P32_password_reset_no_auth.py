from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    user = User.query.get(request.json["user_id"])
    user.set_password(request.json["new_password"])
    db.session.commit()
    return jsonify({"ok": True})
