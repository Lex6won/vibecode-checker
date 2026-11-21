from flask import Flask, request, redirect, send_file, send_from_directory, render_template_string, session, jsonify
app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
