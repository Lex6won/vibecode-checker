from flask import Flask, request, redirect, send_file, render_template_string
import requests, subprocess, os
app = Flask(__name__)

@app.route('/x')
def x():
    value = request.args.get('host')
    return str(subprocess.run('ping ' + value, shell=True))
