from flask import Flask, request, redirect, send_file, render_template_string
import requests, subprocess, os
app = Flask(__name__)

@app.route('/x')
def x():
    return str(db.execute("SELECT * FROM t WHERE n='" + request.args.get('n') + "'"))
