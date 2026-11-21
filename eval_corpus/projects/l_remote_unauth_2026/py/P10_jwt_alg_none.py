from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import jwt

KEY = "k"

def current_user():
    token = request.cookies.get("token", "")
    return jwt.decode(token, KEY, algorithms=["none", "HS256"])
