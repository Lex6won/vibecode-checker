from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

from flask_login import login_required, current_user

@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return "forbidden", 403
    db.session.query(User).filter_by(id=user_id).delete()
    db.session.commit()
    return "", 204
