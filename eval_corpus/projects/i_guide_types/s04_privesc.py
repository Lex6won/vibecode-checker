from flask import request, session

def update_profile():
    data = request.get_json()
    user = load_user(session["uid"])
    # 클라이언트가 보낸 필드를 그대로 반영 — role 승격 가능
    for k, v in data.items():
        setattr(user, k, v)
    user.save()

def run_as_root(cmd):
    import subprocess
    subprocess.run(["sudo", "-u", "root", "sh", "-c", cmd])
