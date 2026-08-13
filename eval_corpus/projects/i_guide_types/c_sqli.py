from flask import request

def search():
    kw = request.args.get("kw")
    cur.execute("SELECT * FROM 민원 WHERE 제목 LIKE '%" + kw + "%'")
    q = f"SELECT * FROM users WHERE name = '{kw}'"
    cur.execute(q)
