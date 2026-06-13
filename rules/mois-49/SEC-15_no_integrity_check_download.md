---
id: MOIS-49-SEC-15
title_ko: 무결성 검사 없는 코드 다운로드
title_en: Download of Code Without Integrity Check
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-15
cwe: [CWE-494]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [python, javascript, shell]
scenarios: [package-install, data-pipeline]
related_baseline: [NIS-AI-M12, OWASP-LLM-2025-03, INTEL-2026-SLOPSQUATTING]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
외부에서 다운로드한 코드·라이브러리·바이너리에 *무결성 검사* 없이 실행. 공급망 공격 진입점.

## 안전한 패턴
- SHA-256 해시 사전 검증
- 디지털 서명 검증 (GPG, sigstore)
- 신뢰된 미러만 사용 (NIS-AI-M02 연계)
- requirements.txt에 hash 포함 (`pip --require-hashes`)

## 매핑
- 본 리포 [INTEL-2026-SLOPSQUATTING](../intel/INTEL-2026-SLOPSQUATTING.md)
- NIS-AI-M12 (구성요소 무결성 검증)
- OWASP LLM 2025 LLM03, CWE-494
