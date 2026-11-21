from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

from pymongo import MongoClient

users = MongoClient()["app"]["users"]

@app.route("/find")
def find():
    name = str(request.args.get("name", ""))
    return jsonify(list(users.find({"name": name}, {"_id": 0, "name": 1})))
