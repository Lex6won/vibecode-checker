---
id: GOV-SQL-INJECTION-001
title_ko: SQL 문장을 문자열로 조립합니다 - 사용자 입력이 닿으면 위험합니다
title_en: SQL statement assembled by string building (verify the data source)
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
  # 정규식 패턴은 **Python AST 파싱이 실패한 경우의 예비 수단**입니다.
  # 파싱에 성공하면 scanner.py 가 이 regex 결과를 버리고 python-ast 결과만
  # 씁니다 — 줄 단위 regex 는 삽입 값의 출처(사용자 입력 vs 개발자 상수)를
  # 알 수 없어, 상수 기반 조립을 치명 위험으로 잘못 올리기 때문입니다.
  # DDL(ALTER/CREATE/PRAGMA…)은 여기서 제외합니다 — GOV-SQL-DDL-DYNAMIC-001 담당.
  patterns:
    - "execute\\s*\\(\\s*f[\"'](?!\\s*(?:ALTER|CREATE|DROP|TRUNCATE|RENAME|PRAGMA|ATTACH|DETACH|REINDEX|VACUUM|ANALYZE)\\b)"
    - 'execute\s*\([^)]*\.format\s*\('
    - 'execute\s*\([^)]*\+[^)]*\)'
  category: gov-secure-coding
  why_it_matters: >-
    SQL 을 문자열로 조립하면, 그 조각에 사용자 입력이 닿는 순간 SQL 삽입이
    됩니다. 공격자가 검색어를 조작해 민원 DB 전체를 조회·변경·삭제할 수
    있습니다. **삽입되는 값이 어디서 오는지 먼저 확인하세요** — 코드에 박힌
    상수·허용 목록에서만 온다면 위험이 없지만, 요청 파라미터·업로드 파일·
    외부 API 응답이 섞이면 즉시 조치해야 합니다.
  public_sector_impact:
    - 개인정보 유출
    - 행정 DB 변조
    - 서비스 중단
  safe_fix: |
    값은 문자열에 끼우지 말고 파라미터 바인딩으로 넘기세요.
    cursor.execute("SELECT * FROM t WHERE name=%s", (name,))   # 안전
    cursor.execute(f"SELECT * FROM t WHERE name='{name}'")     # 위험

    테이블·컬럼 이름처럼 바인딩이 불가능한 자리는 허용 목록(화이트리스트)으로
    검증한 뒤 사용하세요(GOV-SQL-DDL-DYNAMIC-001 참고).
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
