# 시나리오: 공무원이 AI 코딩 도구로 생성한 민원 조회 Flask 앱 (의도적 취약 샘플)
# 본 파일의 키·주민번호는 전부 가짜 테스트 값입니다. 절대 운영 배포 금지.
import hashlib
import logging
import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)

OPENAI_API_KEY = "sk-proj-FAKE000000000000000000000000TEST"  # A-02 hardcoded api key
UPLOAD_DIR = "./uploads"


@app.route("/minwon")
def minwon_lookup():
    name = request.args.get("name", "")
    conn = sqlite3.connect("minwon.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM minwon WHERE name = '{name}'")  # A-01 fstring sqli
    rows = cursor.fetchall()
    return {"rows": rows}


@app.route("/register")
def register():
    rrn = request.args.get("rrn", "900101-1234567")  # A-03 rrn literal
    logging.info("민원인 주민등록번호 접수: 900101-1234567")  # A-04 rrn logging
    password = request.args.get("password", "")
    hashed = hashlib.md5(password.encode()).hexdigest()  # A-05 weak hash md5
    return {"rrn": rrn, "hash": hashed}


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    with open(os.path.join(UPLOAD_DIR, filename)) as fh:  # A-06 path traversal
        return fh.read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # A-07 debug true
