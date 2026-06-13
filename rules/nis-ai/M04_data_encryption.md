---
id: NIS-AI-M04
title_ko: 데이터 암호화
title_en: Data Encryption
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M04
severity: high
decision_default: warn
domains: [llm-appsec, privacy-public-sector]
languages: [python]
scenarios: [data-pipeline]
related_baseline: [NIS-AI-T05]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
*공개 등급* 데이터는 암호화 대상에서 제외. 기밀이 포함되지 않은 원시·학습데이터 저장소는 **국가정보원장이 개발하거나 안전성을 확인한 암호 알고리즘**으로 암호화. **기밀 포함 시 국정원장이 개발하거나 안전성을 확인한 암호자재 활용이 필요하며 사전 협의 필수**. 암호키는 HSM 또는 KMS로 중앙 관리.

## 공공 환경 적용
- 학습 데이터 저장소 등급 분류 (기밀/민감/공개)
- 등급별 암호화 정책 차등화
- 키 관리: 하드웨어 보안 모듈(HSM) 또는 KMS

## 매핑
- 「국가 정보보안 기본지침」
- OWASP ASVS V6 (Cryptography)
