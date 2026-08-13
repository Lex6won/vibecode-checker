from flask import request

def login():
    # 시도 횟수 제한 없음
    if check_password(request.form["id"], request.form["pw"]):
        return "ok"
    return "fail"
