from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

import os

app.secret_key = os.environ["FLASK_SECRET_KEY"]
