---
id: MOIS-49-ENCAP-02
title_ko: 제거되지 않고 남은 디버그 코드
title_en: Leftover Debug Code
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제6절-2
cwe: [CWE-489]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*디버그 페이지·디버그 엔드포인트*가 프로덕션에 남아 *우회 인증* 가능. 예: `/debug`, `/admin/sql`, `console.log(...)`.

## 안전한 패턴
- 빌드 단계에서 *디버그 코드 제거* (esbuild·Webpack 환경별 빌드)
- 환경변수로 toggle (`DEBUG=False` in prod)
- 정기 *코드 리뷰* + 정적 분석

## 매핑
- CWE-489
