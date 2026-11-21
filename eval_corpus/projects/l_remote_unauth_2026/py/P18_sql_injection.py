from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import sqlite3

@app.route("/user")
def user():
    name = request.args.get("name")
    con = sqlite3.connect("app.db")
    rows = con.execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()
    return jsonify(rows)
