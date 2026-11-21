from flask import Flask, request, redirect, send_file, render_template_string
import requests, subprocess, os
app = Flask(__name__)

@app.route('/x')
def x():
    return str(subprocess.run('ping ' + request.args.get('host'), shell=True))
