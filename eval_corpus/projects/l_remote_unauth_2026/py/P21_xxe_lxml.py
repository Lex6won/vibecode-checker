from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

from lxml import etree

@app.route("/import", methods=["POST"])
def import_xml():
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    doc = etree.fromstring(request.data, parser)
    return doc.findtext("name")
