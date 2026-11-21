---
id: GOV-CORS-CREDENTIALS-001
title_ko: CORS 전체 허용(또는 요청 출처 그대로 허용) + 자격증명 허용 - 다른 사이트가 로그인 상태로 응답을 읽음
title_en: CORS allows any (or reflected) origin together with credentials
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 2021
    item: A05 Security Misconfiguration
  - publisher: OWASP
    document: HTML5 Security Cheat Sheet
    item: Cross Origin Resource Sharing
cwe: [CWE-942, CWE-346]
severity: high
decision_default: block
domains: [web-appsec]
languages: [python, javascript, typescript]
scenarios: [web-app, backend-node, auth]
related_baseline: [CWE-942]
verified_at: 2026-11-21
review_due: 2027-05-21
detection:
  patterns:
    # FastAPI·Starlette CORSMiddleware — 한 호출 안의 두 인자(순서 무관)
    - 'allow_origins\s*=\s*\[\s*["'']\*["'']\s*\][\s\S]{0,300}?allow_credentials\s*=\s*True'
    - 'allow_credentials\s*=\s*True[\s\S]{0,300}?allow_origins\s*=\s*\[\s*["'']\*["'']\s*\]'
    # flask-cors
    - '["'']?origins["'']?\s*[:=]\s*["'']\*["''][\s\S]{0,300}?supports_credentials\s*=\s*True'
    - 'supports_credentials\s*=\s*True[\s\S]{0,300}?["'']?origins["'']?\s*[:=]\s*["'']\*["'']'
    # django-cors-headers
    - 'CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True[\s\S]{0,3000}?CORS_ALLOW_CREDENTIALS\s*=\s*True'
    - 'CORS_ALLOW_CREDENTIALS\s*=\s*True[\s\S]{0,3000}?CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True'
    # Express cors() — origin: true 는 요청 출처를 그대로 돌려준다
    - 'cors\s*\(\s*\{[^}]*\borigin\s*:\s*(?:true|["'']\*["''])[^}]*\bcredentials\s*:\s*true'
    - 'cors\s*\(\s*\{[^}]*\bcredentials\s*:\s*true[^}]*\borigin\s*:\s*(?:true|["'']\*["''])'
    # 헤더를 직접 쓰는 형태 — 요청의 Origin 을 그대로 돌려주고 자격증명을 허용
    - 'Access-Control-Allow-Origin["'']\s*(?:,|\]\s*=)\s*(?:req|request)\.headers[\s\S]{0,400}?Access-Control-Allow-Credentials["'']\s*(?:,|\]\s*=)\s*["'']true["'']'
  string_arguments: true
  confidence: likely
  category: misconfig
  why_it_matters: >-
    CORS 는 다른 사이트의 스크립트가 이 서버의 응답을 읽어도 되는지를 정합니다. 출처를 전부 허용하거나 요청의
    Origin 을 그대로 돌려주면서 자격증명(쿠키·인증 헤더)까지 허용하면, 사용자가 로그인한 채 다른 사이트를 열기만 해도
    그 사이트가 사용자 권한으로 API 를 호출하고 응답을 읽을 수 있습니다. 개발 중 오류를 없애려고 넣은 설정이 그대로
    배포되는 경우가 많습니다.
  public_sector_impact:
    - 로그인한 직원의 권한으로 외부 사이트가 내부 API 응답을 읽음
    - 개인정보·행정 데이터 유출
    - 사용자가 모르는 사이에 변경 요청 실행
  safe_fix: |
    허용할 출처를 정확히 적으세요.
        allow_origins=["https://portal.example.go.kr"], allow_credentials=True     # FastAPI
        cors({ origin: ["https://portal.example.go.kr"], credentials: true })       // Express
    여러 출처가 필요하면 허용 목록과 대조한 뒤에만 Access-Control-Allow-Origin 을 돌려주세요.
  references:
    - CWE-942 Permissive Cross-domain Policy with Untrusted Domains
    - OWASP A05 Security Misconfiguration
  can_auto_fix: false
examples:
  language: python
  positive:
    - "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"], allow_credentials=True, allow_methods=[\"*\"])"
    - "CORS(app, resources={r\"/api/*\": {\"origins\": \"*\"}}, supports_credentials=True)"
    - "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True"
    - "app.use(cors({ origin: true, credentials: true }));"
    - "res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');\nres.setHeader('Access-Control-Allow-Credentials', 'true');"
    - "resp.headers[\"Access-Control-Allow-Origin\"] = request.headers.get(\"Origin\", \"*\")\nresp.headers[\"Access-Control-Allow-Credentials\"] = \"true\""
  negative:
    - "app.add_middleware(CORSMiddleware, allow_origins=[\"https://portal.example.go.kr\"], allow_credentials=True)"
    - "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"], allow_methods=[\"GET\"])"
    - "app.use(cors({ origin: ['https://portal.example.go.kr'], credentials: true }));"
    - "app.use(cors({ origin: '*' }));"
    - "CORS_ALLOWED_ORIGINS = [\"https://portal.example.go.kr\"]\nCORS_ALLOW_CREDENTIALS = True"
---

## 무엇이 위험한가
출처를 가리지 않고 자격증명까지 허용하면, 사용자가 로그인한 브라우저로 아무 사이트나 방문했을 때 그 사이트의
스크립트가 사용자 쿠키를 실은 요청을 보내고 응답을 읽을 수 있습니다. 자격증명 없이 전체 허용(`*`)만 한 공개 API 는
이 룰의 대상이 아닙니다.

## 안전한 패턴
```python
app.add_middleware(CORSMiddleware, allow_origins=["https://portal.example.go.kr"], allow_credentials=True)
```
```javascript
app.use(cors({ origin: ["https://portal.example.go.kr"], credentials: true }));
```
