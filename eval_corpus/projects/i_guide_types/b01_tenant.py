from flask import request, session

def list_events():
    # 기관(테넌트) 식별자를 요청에서 받아 그대로 신뢰
    org = request.args.get("org_id")
    return db.query("SELECT * FROM events WHERE org_id=?", (org,))

def export_all():
    # 테넌트 조건 자체가 없음
    return db.query("SELECT * FROM events")
