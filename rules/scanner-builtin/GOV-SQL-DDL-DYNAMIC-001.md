---
id: GOV-SQL-DDL-DYNAMIC-001
title_ko: DDL·PRAGMA 문을 문자열로 조립합니다 - 값의 출처를 확인하세요
title_en: Dynamically assembled DDL/PRAGMA statement
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
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline]
related_baseline: [GOV-SQL-INJECTION-001, MOIS-49-SW-17]
verified_at: 2026-07-31
review_due: 2027-01-31
detection:
  # 이 룰은 AST 엔진(python-ast)이 DDL 접두사를 확인한 뒤에만 발행합니다.
  # 정규식 패턴을 두지 않는 이유: 줄 단위 regex 로는 삽입 값의 출처를 알 수
  # 없어 정상 마이그레이션 코드를 전부 오탐으로 만들기 때문입니다.
  patterns: []
  category: gov-secure-coding
  why_it_matters: >-
    ALTER TABLE·CREATE·DROP·PRAGMA 같은 DDL 문은 테이블·컬럼 이름을 파라미터
    placeholder(?, %s)로 넘길 수 **없습니다**. 그래서 문자열 조립 자체는
    불가피하며, 그 사실만으로 SQL 삽입이라고 단정할 수 없습니다. 다만 조립에
    쓰이는 이름이 사용자 입력·외부 설정에서 올 수 있다면 스키마 변조·데이터
    삭제로 이어지므로, **값의 출처가 개발자가 정한 목록인지**를 확인해야 합니다.
  public_sector_impact:
    - 스키마 변조로 인한 서비스 중단
    - 테이블 삭제·데이터 손실
    - 감사 추적 무력화
  safe_fix: |
    DDL 은 파라미터 바인딩이 불가능하므로 **화이트리스트 검증**으로 방어합니다.

    # 안전: 허용 목록에서만 이름을 가져온다(개발자 상수)
    ALLOWED = {"응소코드": "TEXT", "자유출석": "INTEGER DEFAULT 0"}
    for col, dfn in ALLOWED.items():
        cur.execute(f"ALTER TABLE 이벤트 ADD COLUMN {col} {dfn}")

    # 위험: 요청 값이 그대로 들어간다
    col = request.args["col"]
    cur.execute(f"ALTER TABLE 이벤트 ADD COLUMN {col} TEXT")   # ← 반드시 검증

    외부 입력을 써야 한다면 정규식(^[A-Za-z_][A-Za-z0-9_]*$)으로 식별자 형식을
    강제하고, 허용 목록에 있는지 대조한 뒤에만 사용하세요.
  references:
    - MOIS-49-SW-17
    - CWE-89
    - OWASP ASVS V5
  can_auto_fix: false
examples:
  language: python
  positive:
    - 'cur.execute(f"ALTER TABLE t ADD COLUMN {col} TEXT")'
    - 'cur.execute(f"PRAGMA table_info({tbl})")'
  negative:
    - 'cur.execute("ALTER TABLE t ADD COLUMN memo TEXT")'
    - 'cur.execute("SELECT * FROM t WHERE n = ?", (name,))'
---

## 무엇이 위험한가
DDL(ALTER/CREATE/DROP/TRUNCATE)과 PRAGMA 는 **식별자(테이블·컬럼명)를 파라미터로 바인딩할 수 없습니다.** 따라서 문자열 조립은 문법적으로 불가피하고, 조립했다는 사실만으로 취약점이라고 볼 수 없습니다.

진짜 위험은 **조립에 들어가는 이름이 어디서 왔는가**입니다.

| 값의 출처 | 위험도 | 조치 |
|---|---|---|
| 코드에 박힌 리터럴·상수 목록 | 낮음 | 그대로 사용 가능 |
| 설정 파일·DB 조회 결과 | 중간 | 허용 목록 대조 권장 |
| HTTP 요청·업로드 파일·환경변수 | **높음** | 반드시 화이트리스트 검증 |

## 안전한 패턴
```python
ALLOWED_COLUMNS = {"응소코드": "TEXT", "자유출석": "INTEGER DEFAULT 0"}

def add_column(cur, name: str) -> None:
    if name not in ALLOWED_COLUMNS:          # 화이트리스트 대조
        raise ValueError(f"허용되지 않은 컬럼: {name}")
    cur.execute(f"ALTER TABLE 이벤트 ADD COLUMN {name} {ALLOWED_COLUMNS[name]}")
```

## 왜 별도 룰인가
이 검사기는 과거 DDL 조립을 `GOV-SQL-INJECTION-001`(치명)로 판정해, 정상적인 스키마 마이그레이션 코드를 전부 차단 대상으로 올렸습니다. 실제 공공 프로젝트 점검에서 이 형태의 오탐이 다수 확인되어, **파라미터 바인딩이 가능한 DML(SELECT/INSERT/UPDATE/DELETE)** 과 분리했습니다.
