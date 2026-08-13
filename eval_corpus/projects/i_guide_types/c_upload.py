from flask import request

def upload():
    f = request.files["file"]
    # 확장자·MIME 검증 없음
    f.save("/var/www/html/uploads/" + f.filename)
