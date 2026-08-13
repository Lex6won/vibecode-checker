import logging
from flask import request

def login():
    pw = request.form["password"]
    logging.info("login attempt pw=%s", pw)
    logging.debug(f"주민번호={request.form['rrn']}")
