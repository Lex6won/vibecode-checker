---
id: GOV-SQL-INJECTION-001
title_ko: 사용자 입력이 SQL 문장에 직접 들어갈 수 있습니다
title_en: Possible SQL injection
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-17
  - publisher: OWASP
    document: ASVS 5.0
    item: V5 Validation Sanitization Encoding
cwe: [CWE-89]
severity: critical
decision_default: block
domains: [gov-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline]
related_baseline: [MOIS-49-SW-17]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "execute\\s*\\(\\s*f[\"']"
    - 'execute\s*\([^)]*\.format\s*\('
    - 'execute\s*\([^)]*\+[^)]*\)'
  category: gov-secure-coding
  why_it_matters: 공격자가 검색어를 조작하면 민원 DB 전체 조회, 변경, 삭제가 가능해질 수 있습니다.
  public_sector_impact:
    - 개인정보 유출
    - 행정 DB 변조
    - 서비스 중단
  safe_fix: |
    SQL은 문자열 조합 대신 파라미터 바인딩을 사용하세요.
    cursor.execute("SELECT * FROM t WHERE name=%s", (name,))
  references:
    - MOIS-49-SW-17
    - CWE-89
    - OWASP ASVS V5
  can_auto_fix: true
examples:
  language: python
  positive:
    - 'cursor.execute(f"SELECT * FROM citizens WHERE name = ''{name}''")'
    - 'cursor.execute("SELECT * FROM t WHERE n = ''{}''".format(name))'
    - "cursor.execute('SELECT * FROM t WHERE n = ' + name)"
  negative:
    - 'cursor.execute("SELECT * FROM t WHERE n = %s", (name,))'
    - 'cursor.execute("SELECT 1")'
---

## 무엇이 위험한가
사용자 입력을 f-string·`.format()`·문자열 연결로 SQL에 끼우면 SQL 인젝션이 발생합니다. 민원 처리 시스템에선 *전 민원인 정보 일괄 유출* 또는 데이터 변조로 직결됩니다.

## 안전한 패턴
```python
cursor.execute("SELECT * FROM citizens WHERE name = %s", (name,))
# ORM 사용 시: model.filter(name=name)
```
