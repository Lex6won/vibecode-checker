---
id: KISA-PY-INPUT-11
title_ko: Python CSRF 보호 우회 - csrf_exempt / WTF_CSRF_ENABLED=False
title_en: CSRF protection disabled in Python web frameworks
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 11. 크로스사이트 요청 위조 (CSRF)
cwe: [CWE-352]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app]
related_baseline: [MOIS-49-INPUT-11]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '@csrf_exempt'
    - 'csrf_exempt\s*\('
    - "WTF_CSRF_ENABLED\\s*=\\s*False"
    - "CSRF_TRUSTED_ORIGINS\\s*=\\s*\\[\\s*['\"]\\*"
  category: kisa-secure-coding
  why_it_matters: >-
    Django의 `@csrf_exempt`, Flask-WTF의 `WTF_CSRF_ENABLED=False`로 CSRF
    보호를 끄면 공격자가 만든 페이지에서 사용자 권한으로 임의 요청이 가능
    합니다. 민원 처리·결재 시스템에서는 결재 변조·민원 위조로 이어집니다.
  public_sector_impact:
    - 결재 위조
    - 민원 변조
    - 권한 상승 우회
  safe_fix: |
    CSRF 보호는 끄지 말고, 토큰 검증이 어려운 API는 다른 인증(JWT + SameSite
    cookie 등)으로 설계하세요. 임시 예외가 필요하면 별도 endpoint로 분리하고
    승인된 origin 화이트리스트만 허용.
  references:
    - KISA Python 가이드 제2절 11
    - MOIS-49-INPUT-11
    - CWE-352
    - OWASP ASVS V7
  can_auto_fix: false
examples:
  language: python
  positive:
    - "@csrf_exempt"
    - "WTF_CSRF_ENABLED = False"
  negative:
    - "WTF_CSRF_ENABLED = True"
    - "CSRF_TRUSTED_ORIGINS = [\"https://portal.acme.invalid\"]"
---

## 무엇이 위험한가
공공 사이트의 결재·민원 폼은 *반드시* CSRF 토큰 검증을 거쳐야 합니다. `@csrf_exempt`는 그 보호를 한 줄로 무효화합니다.

## 안전한 패턴
```python
# Django - 기본 enabled 유지
@require_POST
def update_complaint(request):
    ...  # csrf middleware가 자동 검증

# Flask-WTF - 폼 + csrf_token 사용
class ComplaintForm(FlaskForm):
    ...  # {{ form.csrf_token }} 자동 렌더
```
