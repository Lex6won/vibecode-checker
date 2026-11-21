from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "0")))
