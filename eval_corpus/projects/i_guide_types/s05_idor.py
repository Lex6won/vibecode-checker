from flask import request, jsonify, session

def get_document():
    doc_id = request.args.get("id")
    # 소유자 확인 없이 식별자만으로 조회
    doc = db.query("SELECT * FROM documents WHERE id=?", (doc_id,))
    return jsonify(doc)

def download_민원파일():
    fid = request.args["file_id"]
    row = db.query("SELECT path FROM files WHERE id=?", (fid,))
    return send_file(row["path"])
