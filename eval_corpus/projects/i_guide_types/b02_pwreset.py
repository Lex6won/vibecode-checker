import random
from flask import request

def issue_reset_token(email):
    # 예측 가능한 토큰
    token = str(random.randint(100000, 999999))
    save_token(email, token)
    send_mail(email, token)

def do_reset():
    token = request.form["token"]
    new_pw = request.form["new_pw"]
    row = find_token(token)
    # 만료·일회성 확인 없음
    set_password(row["email"], new_pw)
