---
id: MOIS-49-TIME-02
title_ko: 종료되지 않는 반복문 또는 재귀함수
title_en: Loop with Unreachable Exit Condition
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제3절-2
cwe: [CWE-835, CWE-674]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, agent, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
종료 조건이 *실행 불가*한 반복문 또는 깊이 제한 없는 재귀함수 → CPU 100% / 스택 오버플로우 / DoS. AI 에이전트의 무한 루프도 동일 위험.

## 안전한 패턴
- 반복 한도 (`max_iterations`)
- 재귀 깊이 제한 (`sys.setrecursionlimit`)
- 타임아웃 강제

## 매핑
- CWE-835, OWASP Agentic 2026 ASI08 (Cascading Failures)
