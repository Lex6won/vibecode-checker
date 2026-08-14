---
id: KISA-PY-SEC-05
title_ko: Python 중요정보 평문 저장·전송 (DB 비밀번호 평문 저장 / 평문 소켓 전송)
title_en: Cleartext storage or transmission of sensitive information in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 5. 암호화되지 않은 중요정보
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-38
cwe: [CWE-312, CWE-319]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline, auth]
related_baseline: [MOIS-49-SEC-05]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?i)UPDATE\\s+\\w+\\s+SET\\s+PASSWORD\\s*=\\s*['\"]?%s['\"]?"
    - "(?i)INSERT\\s+INTO\\s+\\w+[^;]*\\(\\s*[^)]*password[^)]*\\)\\s*VALUES"
    - "s\\.sendall\\s*\\(\\s*(?:password|passwd|pwd|token|secret|api_key)[A-Za-z0-9_]*\\.encode"
    - "s\\.send\\s*\\(\\s*(?:password|passwd|pwd|token|secret|api_key)[A-Za-z0-9_]*\\.encode"
    - "requests\\.(?:get|post|put|delete|patch)\\s*\\(\\s*['\"]http://"
    - "urllib\\.request\\.urlopen\\s*\\(\\s*['\"]http://"
  # 맥락 제외 — **루프백 목적지**(localhost·127.0.0.0/8·::1)는 취소한다.
  # 이 발견의 근거는 CWE-319(평문 *전송*)인데, 루프백 트래픽은 NIC 를 타지 않아
  # 네트워크에 나가지 않는다. 패킷 캡처로 가로챌 구간 자체가 없으므로 근거가
  # 성립하지 않는다. 실측 오탐: `r = requests.get("http://localhost:3000", timeout=5)`
  # (개발 서버 헬스체크 — 민감정보가 실리지도 않는다). 이 구분이 없으면 로컬
  # 개발 스크립트·평가 하네스가 전부 high 로 잡힌다.
  # 한계: 루프백이 외부로 중계하는 프록시인 경우는 이 제외로 놓친다. 다만 그
  # 위험은 프록시 쪽 설정 문제라 이 룰(소스의 평문 전송)의 사정권이 아니다.
  exclude_patterns:
    - "(?i)https?://(?:localhost|127(?:\\.\\d{1,3}){3}|\\[::1\\]|::1)(?::\\d+)?\\b"
  category: kisa-secure-coding
  why_it_matters: >-
    개인정보·인증정보·금융정보를 *평문*으로 DB에 저장하거나 네트워크로 전송하면
    DB 덤프 한 번, 패킷 캡처 한 번에 즉시 노출됩니다. KISA 가이드는 저장 시
    안전한 해시(KDF)·암호화, 전송 시 HTTPS/TLS·필드 단위 암호화를 요구합니다.
    공공기관에서는 개인정보보호법 *안전성 확보조치 기준*과 직결됩니다.
  public_sector_impact:
    - 개인정보·인증정보 평문 유출
    - 패킷 스니핑으로 비밀번호·토큰 탈취
    - 개인정보보호법 안전성 확보조치 위반
  safe_fix: |
    저장: 비밀번호는 bcrypt/argon2 KDF, 그 외 중요정보는 AES-256-GCM.
        from passlib.hash import bcrypt
        cur.execute("UPDATE USERS SET PASSWORD=%s WHERE USER_ID=%s",
                    (bcrypt.hash(password), user_id))
    전송: HTTPS/TLS 강제, 평문 소켓 전송 금지.
        requests.post("https://api.example.go.kr/...", json={"token": token})
    어떤 경우에도 비밀번호·토큰을 그대로 `s.send()`·`http://`로 흘려보내지 마세요.
  references:
    - KISA Python 가이드 제2절 5
    - MOIS-49-SEC-05
    - CWE-312
    - CWE-319
    - 개인정보의 안전성 확보조치 기준 (개인정보보호위원회 고시)
  can_auto_fix: false
examples:
  language: python
  positive:
    - "cur.execute('UPDATE USERS SET PASSWORD=%s WHERE USER_ID=%s', (password, user_id))"
    - "s.sendall(password.encode('utf-8'))"
    - "requests.post('http://api.example.com/login', data={'pw': pw})"
  negative:
    - "cur.execute('UPDATE USERS SET HASHED_PWD=%s WHERE USER_ID=%s', (hashed, user_id))"
    - "requests.post('https://api.example.go.kr/login', json={'token': token})"
    - "s.sendall(enc_payload.encode('utf-8'))"
    # 루프백 목적지 — 네트워크를 벗어나지 않으므로 CWE-319 가 성립하지 않는다
    - "r = requests.get('http://localhost:3000', timeout=5)"
    - "requests.get('http://127.0.0.1:8000/healthz', timeout=2)"
    - "urllib.request.urlopen('http://[::1]:9000/ping')"
---

## 무엇이 위험한가
공공기관에서 가장 흔한 1차 사고 원인입니다. DB에 비밀번호를 그대로 저장한 시스템이 유출되면, 다른 사이트에서 같은 비밀번호를 쓰는 모든 사용자가 즉시 위험에 빠집니다(자격증명 스터핑). 평문 HTTP/소켓 전송은 동일 네트워크의 누구나 캡처할 수 있고, 망분리 환경의 내부 패킷 캡처에도 그대로 노출됩니다.

## 안전한 패턴 (가이드 원문 인용)
```python
# 저장: KDF로 해싱 후 저장
from passlib.hash import bcrypt
hashed = bcrypt.hash(password)
cur.execute(
    "UPDATE USERS SET PASSWORD=%s WHERE USER_ID=%s",
    (hashed, user_id),
)

# 전송: HTTPS만 사용
import requests
requests.post(
    "https://api.example.go.kr/login",
    json={"user_id": uid, "token": token},
    timeout=5,
)

# 부득이 raw 소켓이면 TLS 래핑
import ssl, socket
ctx = ssl.create_default_context()
with socket.create_connection((HOST, PORT)) as raw, \
     ctx.wrap_socket(raw, server_hostname=HOST) as s:
    s.sendall(enc_payload)
```

## False positive 주의
- `UPDATE ... SET PASSWORD=%s` 패턴은 *인자화된 쿼리*도 매칭됩니다. KDF 해시 결과를 바인딩한다면 안전하지만 패턴은 그것을 구분하지 못합니다. 같은 라인 또는 직전 줄에 `bcrypt.hash` / `argon2.hash` / `hashlib.pbkdf2_hmac` 호출이 보이면 코드 리뷰로 확인하고 `# gvskb: ignore KISA-PY-SEC-05`로 억제하세요.
- 내부 폐쇄망 IPC에서 의도적으로 평문을 쓰는 경우(예: 같은 호스트 내 유닉스 도메인 소켓)는 별도 위협 모델 문서화 후 무시 주석으로 처리합니다.
- `http://localhost` / `http://127.0.0.1` 같은 루프백 URL도 현재 패턴에 잡힙니다. 개발용 코드라면 환경별 분기로 분리하세요.
