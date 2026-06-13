---
id: MOIS-49-INPUT-17
title_ko: 포맷 스트링 삽입
title_en: Format String Injection
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-17
cwe: [CWE-134]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [c, cpp, python]
scenarios: [data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
사용자 입력이 *포맷 문자열*로 사용되어 임의 메모리 읽기·쓰기. C `printf(user_input)`·Python `"%s" % user_input` 위험.

## 안전한 패턴
- 포맷 문자열은 *상수*만 사용: `printf("%s", user_input)`
- Python `format()`·f-string 사용 (안전)

## 매핑
- CWE-134
