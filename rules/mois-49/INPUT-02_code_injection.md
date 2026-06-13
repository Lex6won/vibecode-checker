---
id: MOIS-49-INPUT-02
title_ko: 코드 삽입
title_en: Code Injection
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-2
cwe: [CWE-94]
severity: critical
decision_default: block
domains: [gov-secure-coding]
languages: [python, javascript]
scenarios: [web-app, llm-integration]
related_baseline: [GOV-CODE-EXEC-001]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
외부 입력값이 코드 일부로 *실행*될 수 있는 약점. `eval()`·`exec()` 등 동적 코드 실행 함수의 위험 사용.

## 안전한 패턴
- `eval`/`exec` 사용 금지
- 안전한 대안: `ast.literal_eval`, JSON 파싱, whitelist parser

## 매핑
- 본 리포 [GOV-CODE-EXEC-001](../scanner-builtin/GOV-CODE-EXEC-001.md) — 실시간 검사 가능
- CWE-94
