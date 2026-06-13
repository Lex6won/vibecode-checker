---
id: MOIS-49-INPUT-05
title_ko: 운영체제 명령어 삽입
title_en: OS Command Injection
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-5
cwe: [CWE-78]
severity: critical
decision_default: block
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, agent, data-pipeline]
related_baseline: [GOV-CMD-INJECTION-001, MOIS-49-SW-17]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
외부 입력이 *OS 명령*으로 실행되는 약점. `os.system`·`subprocess(shell=True)` 패턴의 위험 사용.

## 안전한 패턴
- `subprocess.run([...], shell=False)` — 인자 리스트 + shell 비활성
- 입력 화이트리스트 검증

## 매핑
- 본 리포 [GOV-CMD-INJECTION-001](../scanner-builtin/GOV-CMD-INJECTION-001.md) — 실시간 검사
- CWE-78
