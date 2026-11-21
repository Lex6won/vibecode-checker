from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

from defusedxml import ElementTree

@app.route("/import", methods=["POST"])
def import_xml():
    doc = ElementTree.fromstring(request.data)
    return doc.findtext("name")
