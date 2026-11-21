from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

from pymongo import MongoClient

users = MongoClient()["app"]["users"]

@app.route("/find")
def find():
    name = request.args.get("name")
    return jsonify(list(users.find({"$where": "this.name == '" + name + "'"})))

@app.route("/login", methods=["POST"])
def login():
    user = users.find_one({"username": request.json["username"], "password": request.json["password"]})
    return jsonify({"ok": bool(user)})
