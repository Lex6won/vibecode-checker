---
id: MOIS-49-ERR-01
title_ko: 오류 메시지 정보노출
title_en: Information Exposure Through Error Messages
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제4절-1
cwe: [CWE-209]
severity: medium
decision_default: warn
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
*스택 트레이스*·*DB 오류*가 사용자에게 그대로 노출 → 내부 구조 정찰 가능.

## 안전한 패턴
- 프로덕션은 *일반화된 오류 메시지*만 반환 ("처리 중 오류가 발생했습니다")
- 상세 오류는 *로그*에만 기록
- Django `DEBUG = False`, Flask 프로덕션 모드

## 매핑
- CWE-209
