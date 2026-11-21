from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

app.secret_key = "dev"
app.config["SECRET_KEY"] = "changeme"
