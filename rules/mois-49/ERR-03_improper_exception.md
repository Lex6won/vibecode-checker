---
id: MOIS-49-ERR-03
title_ko: 부적절한 예외 처리
title_en: Improper Exception Handling
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제4절-3
cwe: [CWE-396, CWE-397]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*Throwable catch* / *Pokemon catch* (`except:` 또는 `catch (Exception e)`) → 보안 예외(*Permission*, *Auth*)까지 silent.

## 안전한 패턴
- *구체적 예외 클래스* 명시 (`except ValueError:`)
- 보안 예외는 *반드시 fail-safe* (deny)
- 일반 Exception은 *재발생* (`raise`)

## 매핑
- CWE-396
