---
id: KISA-PY-INPUT-06
title_ko: Python 위험한 형식 파일 업로드 - 확장자·MIME 미검증
title_en: Unrestricted file upload in Python web frameworks
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 6. 위험한 형식 파일 업로드
cwe: [CWE-434]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, file-upload]
related_baseline: [MOIS-49-INPUT-06]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "\\.save\\s*\\([^)]*file\\.filename"
    - "\\.save\\s*\\([^)]*request\\.files\\["
    - "shutil\\.copyfileobj\\s*\\([^,)]*\\.file\\s*,"
    - "open\\s*\\([^)]*file\\.filename"
  category: kisa-secure-coding
  why_it_matters: >-
    업로드된 파일을 확장자·MIME·매직넘버 검증 없이 저장하면 webshell(.php·.jsp·
    .aspx) 또는 실행 가능한 스크립트를 올려 서버 권한을 탈취할 수 있습니다.
    공공기관 민원 첨부, 결재 시스템 첨부에서 빈번한 약점입니다.
  public_sector_impact:
    - 웹쉘 업로드로 서버 RCE
    - 행정 자료 변조
    - 악성코드 유포 채널 악용
  safe_fix: |
    1) 화이트리스트 확장자만 허용 (.pdf .hwp .docx .xlsx 등)
    2) MIME 매직넘버 검증 (python-magic)
    3) 저장 디렉터리는 웹 루트 외부에 두고 X-Content-Type-Options: nosniff
    4) 파일명은 secure_filename + 고유 ID 부여
    ALLOWED = {".pdf", ".hwp", ".docx"}
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED: abort(400)
  references:
    - KISA Python 가이드 제2절 6
    - MOIS-49-INPUT-06
    - CWE-434
  can_auto_fix: false
---

## 무엇이 위험한가
`file.save(os.path.join(UPLOAD_DIR, file.filename))` 한 줄로 끝내는 코드가 가장 위험합니다. `.php`/`.jsp` 같은 확장자가 그대로 저장되면 웹쉘이 됩니다.

## 안전한 패턴
```python
from pathlib import Path
import magic, uuid
ALLOWED_EXTS = {".pdf", ".hwp", ".docx", ".xlsx", ".png", ".jpg"}
ALLOWED_MIME = {"application/pdf", "image/png", "image/jpeg", ...}

ext = Path(file.filename).suffix.lower()
if ext not in ALLOWED_EXTS: abort(400)
header = file.read(2048); file.seek(0)
if magic.from_buffer(header, mime=True) not in ALLOWED_MIME: abort(400)
safe_name = f"{uuid.uuid4().hex}{ext}"
file.save(Path("/var/uploads") / safe_name)
```
