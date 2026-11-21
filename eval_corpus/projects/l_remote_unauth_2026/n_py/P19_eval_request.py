from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import ast

@app.route("/calc")
def calc():
    return str(ast.literal_eval(request.args.get("expr", "0")))
