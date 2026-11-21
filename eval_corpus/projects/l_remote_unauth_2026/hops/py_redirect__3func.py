from flask import Flask, request, redirect, send_file, render_template_string
import requests, subprocess, os
app = Flask(__name__)

def helper(value):
    return str(redirect(value))

@app.route('/x')
def x():
    value = request.args.get('next')
    return helper(value)
