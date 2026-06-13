---
id: MOIS-49-CODE-05
title_ko: 신뢰할 수 없는 데이터의 역직렬화
title_en: Deserialization of Untrusted Data
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제5절-5
cwe: [CWE-502]
severity: critical
decision_default: block
domains: [gov-secure-coding]
languages: [python, java, javascript]
scenarios: [web-app, data-pipeline]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
외부에서 받은 데이터를 *역직렬화*(`pickle`·`yaml.load`·Java `ObjectInputStream`) 시 임의 코드 실행. **2021 신규 추가 항목**.

## 안전한 패턴
- `pickle` 대신 *JSON* 사용
- `yaml.safe_load()` (yaml.load 금지)
- Java: `ObjectInputFilter` 적용
- ML 모델: ONNX 등 안전 포맷 우선 (.pkl 회피)

## 매핑
- CWE-502, OWASP Top 10 (A08)
