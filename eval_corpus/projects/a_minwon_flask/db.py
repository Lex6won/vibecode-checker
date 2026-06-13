# 의도적 취약 샘플 — 가짜 비밀번호. 운영 배포 금지.
import sqlite3

DB_PASSWORD = "P@ssw0rd123!fake"  # A-08 hardcoded db password


def find_user(user_id: str):
    conn = sqlite3.connect("minwon.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # A-09 concat sqli
    return cursor.fetchall()
