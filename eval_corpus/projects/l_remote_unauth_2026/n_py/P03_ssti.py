from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
