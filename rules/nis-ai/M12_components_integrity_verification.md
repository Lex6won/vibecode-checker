---
id: NIS-AI-M12
title_ko: AI시스템 구성요소 무결성 검증
title_en: AI System Components Integrity Verification
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M12
severity: high
decision_default: warn
domains: [llm-appsec]
languages: [python]
scenarios: [llm-integration]
related_baseline: [NIS-AI-T03, NIS-AI-T14, NIS-AI-M11]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI모델·학습데이터·라이브러리 등 구성요소가 *원본과 동일한지* 검증. 전자서명과 해시값 *정기 검증*으로 위변조 탐지 시 차단 및 복원.

## 안전한 패턴
- 빌드/배포 시 sigstore 서명 + Rekor 투명 로그
- 운영 시 정기 해시 비교 (cron)
- 위변조 탐지 → 자동 차단 + 백업 복원 + 알람

## 공공 환경 적용
- 모델 가중치 파일의 sha256 *주 1회* 비교
- 침해 의심 시 즉시 *백업본 복원* (M26 연계)

## 매핑
- 본 리포 [GOV-SECRET-PRIVATEKEY-001](../scanner-builtin/GOV-SECRET-PRIVATEKEY-001.md)
- Sigstore (cosign)
