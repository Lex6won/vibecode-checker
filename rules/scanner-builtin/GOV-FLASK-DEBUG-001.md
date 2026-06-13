---
id: GOV-FLASK-DEBUG-001
title_ko: Flask 디버그 모드 활성화 - 운영 배포 시 RCE/정보 노출
title_en: Flask debug mode enabled (RCE / info disclosure in production)
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 2021
    item: A05 Security Misconfiguration
  - publisher: Flask
    document: Flask Security Considerations
severity: high
decision_default: block
domains: [web-appsec]
languages: [python]
scenarios: [web-app]
related_baseline: [CWE-489]
verified_at: 2026-06-13
review_due: 2026-12-13
detection:
  patterns:
    # app.run(..., debug=True) 한정 — 일반 debug=True는 과탐이라 제외한다.
    - 'app\.run\s*\([^)]*debug\s*=\s*True'
  category: misconfig
  why_it_matters: >-
    Flask를 debug=True로 운영 배포하면 Werkzeug 인터랙티브 디버거가 활성화되어
    PIN 우회 시 임의 코드 실행(RCE)이 가능하고, 처리되지 않은 예외에서 스택
    트레이스로 내부 경로·환경변수·소스가 노출됩니다. 개발 편의 설정이 그대로
    배포되는 사고가 빈번합니다.
  public_sector_impact:
    - 운영 서버 원격 코드 실행
    - 내부 경로·환경변수·소스 노출
    - 행정 시스템 침해 기점
  safe_fix: |
    운영은 debug=False로 두고, 디버그는 환경변수로 분리하세요.
        app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
    운영 배포는 gunicorn/uwsgi 같은 WSGI 서버를 사용하고 debug를 켜지 마세요.
  references:
    - CWE-489 Active Debug Code
    - OWASP A05 Security Misconfiguration
  can_auto_fix: false
examples:
  language: python
  positive:
    - "app.run(host='0.0.0.0', debug=True)"
    - "app.run(debug=True)"
  negative:
    - "app.run(host='127.0.0.1', debug=False)"
    - "app.run()"
---

## 무엇이 위험한가
`app.run(debug=True)`로 배포하면 Werkzeug 디버거가 켜집니다. 공격자가 디버거 PIN을 우회하면 브라우저에서 임의의 Python 코드를 실행할 수 있고(RCE), 예외 발생 시 스택 트레이스로 서버 내부 정보가 그대로 노출됩니다.

## 안전한 패턴
```python
import os
# 디버그는 환경변수로 분리하고, 운영 기본값은 False
app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
```
운영 환경은 `gunicorn app:app` 처럼 WSGI 서버로 구동하고 디버그 모드를 켜지 않습니다.
