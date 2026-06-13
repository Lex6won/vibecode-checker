---
id: MOIS-49-API-02
title_ko: 취약한 API 사용
title_en: Use of Vulnerable or Risky API
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제7절-2
cwe: [CWE-676, CWE-242]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [c, cpp, java, python, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*deprecated*되거나 *취약*하다고 알려진 API 사용. 예: C `gets()`, `strcpy()`, Java `Runtime.exec()`, JS `document.write()`.

## 안전한 패턴
- *현대적 대체 API* 사용 (각 언어별 권장)
- 정적 분석 도구 (Bandit, Semgrep, SonarQube)로 자동 검출
- 컴파일러 deprecation 경고를 *에러로* 승격

## 매핑
- CWE-676
