from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

@app.route("/api/documents/<int:doc_id>")
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    return jsonify(doc.to_dict())
