---
id: GOV-DEBUG-ENV-EXPOSE-001
title_ko: 환경변수 전체를 응답으로 반환 - 비밀값 일괄 노출
title_en: Whole process environment returned in an HTTP response
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 2021
    item: A05 Security Misconfiguration
cwe: [CWE-200, CWE-489]
severity: high
decision_default: block
domains: [web-appsec]
languages: [python, javascript, typescript]
scenarios: [web-app, backend-node]
related_baseline: [CWE-489]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    - 'res\.(?:json|send|end|write)\s*\(\s*(?:JSON\.stringify\s*\(\s*)?process\.env\s*[,)]'
    - '(?:NextResponse|Response)\.json\s*\(\s*process\.env\s*[,)]'
    - '(?:jsonify|JSONResponse|JsonResponse)\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b'
    - '\breturn\s+dict\s*\(\s*os\.environ\s*\)'
  confidence: confirmed
  category: misconfig
  why_it_matters: >-
    환경변수에는 DB 비밀번호, API 키, 서명 키가 들어 있습니다. 디버그용으로 만든 "환경 보기" 주소가 배포본에 남으면
    그 주소를 한 번 여는 것만으로 서비스의 비밀값이 전부 나갑니다.
  public_sector_impact:
    - DB·외부 API·서명 키 일괄 유출
    - 유출된 키로 로그인 없이 데이터 접근
  safe_fix: |
    환경변수를 응답에 싣지 마세요. 상태 확인이 필요하면 값이 아니라 설정 여부만 돌려주세요.
        res.json({ db_configured: Boolean(process.env.DATABASE_URL) })
    디버그 주소는 배포본에서 지우거나 관리자 인증 뒤에 두세요.
  references:
    - CWE-200 Exposure of Sensitive Information
    - OWASP A05 Security Misconfiguration
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "app.get('/debug/env', (req, res) => res.json(process.env));"
    - "return NextResponse.json(process.env);"
    - "return jsonify(dict(os.environ))"
  negative:
    - "res.json({ db_configured: Boolean(process.env.DATABASE_URL) });"
    - "const port = process.env.PORT || 3000;"
    - "return jsonify({\"mode\": os.environ.get(\"APP_MODE\")})"
---

## 무엇이 위험한가
환경변수 전체를 돌려주는 주소는 비밀값 목록을 공개하는 것과 같습니다.

## 안전한 패턴
```javascript
res.json({ db_configured: Boolean(process.env.DATABASE_URL) });
```
