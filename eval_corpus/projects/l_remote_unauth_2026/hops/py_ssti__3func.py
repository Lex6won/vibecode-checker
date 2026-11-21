from flask import Flask, request, redirect, send_file, render_template_string
import requests, subprocess, os
app = Flask(__name__)

def helper(value):
    return str(render_template_string('<h1>' + value + '</h1>'))

@app.route('/x')
def x():
    value = request.args.get('name')
    return helper(value)
