from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    db.session.query(User).filter_by(id=user_id).delete()
    db.session.commit()
    return "", 204

@app.route("/admin/export")
def export_all():
    return jsonify([u.to_dict() for u in User.query.all()])
