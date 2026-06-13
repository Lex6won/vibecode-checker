# 음성 대조군: 안전하게 작성된 민원 조회 앱 — 여기서 발견되는 항목은 오탐(FP)
import hashlib
import os
import secrets
import sqlite3

from flask import Flask, request

app = Flask(__name__)

API_KEY = os.environ.get("OPENAI_API_KEY", "")


@app.route("/minwon")
def minwon_lookup():
    name = request.args.get("name", "")
    with sqlite3.connect("minwon.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM minwon WHERE name = ?", (name,))
        return {"rows": cursor.fetchall()}


@app.route("/register")
def register():
    masked_rrn = "900101-1******"
    password = request.args.get("password", "")
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()
    return {"rrn": masked_rrn, "hash": hashed}


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
