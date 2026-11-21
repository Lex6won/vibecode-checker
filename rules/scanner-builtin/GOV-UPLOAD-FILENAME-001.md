---
id: GOV-UPLOAD-FILENAME-001
title_ko: 올린 파일을 보낸 이름 그대로 저장 - 경로 조작·실행 파일 업로드
title_en: Uploaded file saved under the client-supplied filename
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: 위험한 형식 파일 업로드
  - publisher: OWASP
    document: File Upload Cheat Sheet
cwe: [CWE-434, CWE-22]
severity: high
decision_default: warn
domains: [web-appsec]
languages: [python, javascript, typescript]
scenarios: [web-app, backend-node]
related_baseline: [MOIS-49-INPUT-15]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    # Flask·Django·FastAPI — 저장 경로에 업로드 객체의 filename·name 을 그대로 사용
    # 업로드 객체가 **자기 filename** 으로 저장할 때만 — `workbook.save(self.filename)` 같은 일반 저장은 대상이 아니다.
    - '\b(\w+)\.save\s*\([^)\n]*\b\1\.filename\b'
    - 'request\.files\s*\[[^\]\n]+\]\.save\s*\([^)\n]*\.filename\b'
    - 'open\s*\(\s*(?:os\.path\.join\s*\([^)\n]*,\s*)?\w+\.filename\b[^)\n]*\)?\s*,\s*["'']wb'
    # multer — 보낸 이름을 저장 이름으로
    - 'cb\s*\(\s*null\s*,\s*(?:[^)\n]*\+\s*)?file\.originalname\s*\)'
    - '(?:path\.join|fs\.(?:writeFile|writeFileSync|createWriteStream|rename|renameSync))\s*\([^)\n]*\.originalname\b'
  # 이름을 정리한 뒤 쓰는 경우는 대상이 아니다
  exclude_patterns:
    - 'secure_filename\s*\(|path\.basename\s*\(|sanitize(?:Filename|_filename)?\s*\('
  confidence: likely
  category: file-upload
  why_it_matters: >-
    업로드할 때 보내는 파일 이름은 공격자가 정합니다. 그 이름을 그대로 저장 경로에 쓰면 `../../` 로 다른 폴더의
    파일을 덮어쓰거나, 웹에서 실행되는 확장자(.php·.jsp·.html)로 올려 서버나 다른 사용자의 브라우저에서 코드를
    실행시킬 수 있습니다. 같은 이름으로 다른 사람의 파일을 덮어쓰는 것도 가능합니다.
  public_sector_impact:
    - 서버 파일 덮어쓰기·웹셸 업로드
    - 다른 사용자가 올린 민원 첨부 파일 덮어쓰기
    - 공개 폴더에 악성 문서 게시
  safe_fix: |
    저장 이름은 서버가 만들고, 확장자는 허용 목록으로 확인하세요.
        ext = os.path.splitext(secure_filename(f.filename))[1].lower()
        if ext not in ALLOWED: abort(400)
        f.save(os.path.join(UPLOAD_DIR, uuid.uuid4().hex + ext))
    업로드 폴더는 웹에서 직접 실행·열람되지 않는 위치에 두세요.
  references:
    - CWE-434 Unrestricted Upload of File with Dangerous Type
    - OWASP File Upload Cheat Sheet
  can_auto_fix: false
examples:
  language: python
  positive:
    - "f.save(os.path.join(UPLOAD, f.filename))"
    - "f.save(\"/var/www/html/uploads/\" + f.filename)"
    - "filename: (req, file, cb) => cb(null, file.originalname),"
    - "const target = path.join(UPLOAD_DIR, req.file.originalname);"
  negative:
    - "f.save(os.path.join(UPLOAD, uuid.uuid4().hex + ext))"
    - "f.save(os.path.join(UPLOAD, secure_filename(f.filename)))"
    - "workbook.save(self.filename)"
    - "image.save(output_path)"
    - "filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname)),"
    - "const target = path.join(UPLOAD_DIR, path.basename(req.file.originalname));"
---

## 무엇이 위험한가
파일 이름은 본문과 마찬가지로 요청의 일부입니다. 검증 없이 경로에 넣으면 저장 위치와 확장자를 공격자가 고릅니다.

## 안전한 패턴
```python
ext = os.path.splitext(secure_filename(f.filename))[1].lower()
if ext not in {".png", ".jpg", ".pdf"}:
    abort(400)
f.save(os.path.join(UPLOAD_DIR, uuid.uuid4().hex + ext))
```
