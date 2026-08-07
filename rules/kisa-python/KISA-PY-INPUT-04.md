---
id: KISA-PY-INPUT-04
title_ko: Python XSS - Jinja2 |safe / Markup / autoescape=False / mark_safe 사용
title_en: XSS via template auto-escape disabled in Python web frameworks
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 4. 크로스사이트 스크립트(XSS)
cwe: [CWE-79]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app]
related_baseline: [MOIS-49-INPUT-04]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '\|\s*safe\s*(?:\}|\s)'
    - '(?:flask\.)?Markup\s*\([^)]*request\.'
    - 'autoescape\s*=\s*False'
    - '(?<![A-Za-z0-9_.])mark_safe\s*\('
    - "render_template_string\\s*\\([^)]*request\\."
  category: kisa-secure-coding
  why_it_matters: >-
    Flask·Django 템플릿의 자동 escape를 우회(`|safe`, `Markup()`, `mark_safe()`,
    `autoescape=False`)하면 사용자 입력이 HTML로 렌더링되어 XSS가 발생합니다.
    AI가 생성한 챗봇·민원 응답에 직접 적용하면 즉시 사고로 이어집니다.
  public_sector_impact:
    - 민원인 세션·CSRF 토큰 탈취
    - 공공 사이트 신뢰 손상
    - LLM 응답 HTML 렌더 시 즉시 XSS
  safe_fix: |
    autoescape는 켠 채로 두고 사용자 입력을 변수로만 넘기세요.
    return render_template("page.html", text=user_text)  # 자동 escape
    HTML이 정말 필요하면 bleach.clean(user_html, tags=ALLOWED) 으로 정제.
  references:
    - KISA Python 가이드 제2절 4
    - MOIS-49-INPUT-04
    - CWE-79
    - OWASP ASVS V1.3
  can_auto_fix: false
examples:
  language: python
  positive:
    - "return render_template_string(request.args[\"tpl\"])"
    - "body = mark_safe(user_supplied_html)"
  negative:
    - "return render_template(\"page.html\", body=user_supplied_html)"
    - "body = escape(user_supplied_html)"
---

## 무엇이 위험한가
Jinja2와 Django 템플릿은 기본 autoescape로 XSS를 막지만, `|safe` 필터, `Markup()` 래퍼, `mark_safe()` 함수가 이를 *명시적으로 우회*합니다. 신뢰할 수 없는 입력에 적용하면 즉시 XSS입니다.

## 안전한 패턴
```python
# Flask + Jinja2: 자동 escape 유지
return render_template("comment.html", body=user_text)

# 그래도 HTML이 필요하면 화이트리스트 sanitize
import bleach
safe = bleach.clean(user_html, tags=["b", "i", "p"], strip=True)
```
