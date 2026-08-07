---
id: KISA-PY-INPUT-01
title_ko: Python 원시 SQL에 외부 입력값이 직접 결합되어 SQL 삽입 위험이 있습니다
title_en: SQL injection via raw SQL string concatenation in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 1. SQL 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-17
cwe: [CWE-89]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline]
related_baseline: [MOIS-49-INPUT-01, GOV-SQL-INJECTION-001]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - 'cursor\.execute\s*\(\s*["''][^"'']*["'']\s*%\s*'
    - "Manager\\.raw\\s*\\(\\s*[fF]?[\"']"
    - "\\.raw\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\+\\s*"
  category: kisa-secure-coding
  why_it_matters: >-
    Python에서 cursor.execute나 ORM의 .raw() 메서드에 사용자 입력을 문자열로
    이어붙이거나 % 연산자로 끼워 넣으면 공격자가 쿼리 구조 자체를 바꿀 수 있습니다.
    Django querysets도 raw SQL을 쓰면 같은 위험에 노출됩니다.
  public_sector_impact:
    - 민원·통계 DB 전체 조회·변조
    - 개인정보 유출
    - 행정 시스템 신뢰 손상
  safe_fix: |
    DB-API 매개변수 바인딩(%s 또는 named placeholder)을 사용하세요.
    cursor.execute("UPDATE board SET name=%s WHERE content_id=%s", (name, content_id))
    Django ORM은 querysets로 충분합니다: Board.objects.filter(content_id=content_id).update(name=name)
  references:
    - KISA Python 가이드 제2절 1
    - MOIS-49-INPUT-01
    - CWE-89
  can_auto_fix: false
examples:
  language: python
  positive:
    - "cursor.execute(\"SELECT * FROM users WHERE id = %s\" % user_id)"
    - "rows = User.objects.raw(\"SELECT * FROM users WHERE name = \" + name)"
  negative:
    - "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
    - "rows = User.objects.filter(name=name)"
---

## 무엇이 위험한가
KISA Python 가이드는 `cursor.execute("..." % (name, ...))` 또는 `Manager.raw(f"...{var}")`처럼 외부 입력을 *문자열로 SQL에 끼우는 패턴* 모두를 SQL 삽입 1순위 사례로 들고 있습니다.

## 안전한 패턴 (가이드 원문 인용)
- DB-API 매개변수 바인딩: `curs.execute(sql_query, (name, content_id))`
- SQLite Placeholder: `?` 또는 `:name`
- Django ORM querysets 우선, `Manager.raw()` 사용 시에도 바인딩 변수 사용

## 관련
이 룰은 [GOV-SQL-INJECTION-001](../scanner-builtin/GOV-SQL-INJECTION-001.md)이 잡지 못하는 *원시 SQL · ORM raw 우회* 케이스를 보완합니다.
