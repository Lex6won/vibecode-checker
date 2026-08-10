from flask import Flask, request, session, redirect
app = Flask(__name__)

@app.route("/admin/users")
def admin_users():
    # 인가 확인 없이 관리자 기능 노출
    return list_all_users()

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    user_id = request.form["user_id"]
    new_pw = request.form["new_pw"]
    # 재인증 없이 비밀번호 변경
    save_password(user_id, new_pw)
    return "ok"

@app.route("/login", methods=["POST"])
def login():
    if request.form.get("bypass") == "1":
        session["is_admin"] = True
        return redirect("/admin/users")
    return "no"
