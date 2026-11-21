from flask import Flask, request, redirect, send_file, render_template_string
import requests, subprocess, os
app = Flask(__name__)

@app.route('/x')
def x():
    return str(requests.get(request.args.get('url'), timeout=5))
