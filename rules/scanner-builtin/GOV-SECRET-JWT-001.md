---
id: GOV-SECRET-JWT-001
title_ko: JWT 토큰 하드코드 - 소스에 박힌 JSON Web Token
title_en: Hardcoded JWT - JSON Web Token embedded in source
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: Secrets Management Cheat Sheet
  - publisher: 한국인터넷진흥원
    document: JavaScript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 6. 중요정보 하드코드
severity: critical
decision_default: block
domains: [secret-management]
languages: []
scenarios: [web-app, llm-integration, data-pipeline]
related_baseline: [CWE-798]
verified_at: 2026-06-13
review_due: 2026-12-13
detection:
  patterns:
    # 3-세그먼트 JWT: 헤더(eyJ...) . 페이로드(eyJ...) . 서명. eyJ 접두는
    # {" 의 base64url 로 사실상 JWT/JWE 전용이라 오탐이 거의 없다.
    - 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}'
  category: secret-scanning
  why_it_matters: >-
    소스나 설정에 JWT를 그대로 박으면, 저장소 접근자나 유출 시 즉시 인증 토큰이
    탈취됩니다. JWT는 만료 전까지 그대로 재사용 가능하고, 서명 키가 노출되면
    임의 토큰을 위조할 수 있습니다. 코드 주석에 둔 토큰도 동일하게 위험합니다.
  public_sector_impact:
    - 인증 토큰 탈취로 무단 접근
    - 행정 API 권한 도용
    - 토큰 위조(서명 키 동반 노출 시)
  safe_fix: |
    토큰을 소스에서 제거하고 환경변수·시크릿 매니저(Vault, KMS)에서 주입하세요.
    이미 커밋된 토큰은 즉시 폐기(rotate)하고, 짧은 만료시간 + 갱신 토큰 구조로
    바꾸세요.
        token = os.environ["SERVICE_JWT"]
  references:
    - OWASP Secrets Management Cheat Sheet
    - CWE-798 Use of Hard-coded Credentials
  can_auto_fix: false
examples:
  positive:
    - "TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.ABCDEFGH12345678'"
  negative:
    - "token = os.environ['SERVICE_JWT']"
    - "comment = 'eyJ is the base64 prefix of a brace-quote'"
---

## 무엇이 위험한가
JWT(`eyJ...` 로 시작하는 점 2개로 나뉜 토큰)를 소스에 박으면, 저장소에 접근하는 누구나 그 토큰으로 인증을 통과할 수 있습니다. JWT는 만료 전까지 재사용되며, 서명 키까지 함께 노출되면 임의 토큰을 위조할 수 있습니다.

## 안전한 패턴
```python
import os
token = os.environ["SERVICE_JWT"]   # 환경변수·시크릿 매니저에서 주입
```
이미 커밋된 토큰은 반드시 폐기(rotate)하고, 짧은 만료시간과 갱신 토큰 구조로 전환하세요.
