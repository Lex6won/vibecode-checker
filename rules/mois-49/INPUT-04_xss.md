---
id: MOIS-49-INPUT-04
title_ko: 크로스사이트 스크립트 (XSS)
title_en: Cross-Site Scripting
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제1절-4
cwe: [CWE-79]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [javascript, java, python]
scenarios: [web-app, llm-integration]
related_baseline: [GOV-LLM-OUTPUT-HANDLING-001, OWASP-LLM-2025-05]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 약점 정의 (가이드 인용)
외부 입력 또는 *LLM 출력*이 HTML/JS 컨텍스트에 검증 없이 들어가 클라이언트 측 스크립트 실행. **2026 실측**: AI 생성 코드의 XSS 차단 실패 86%.

## 안전한 패턴
- 출력 인코딩: HTML escape, attribute escape, JS escape, URL escape (컨텍스트별)
- 라이브러리: DOMPurify, OWASP Java HTML Sanitizer, bleach
- CSP (Content Security Policy) 적용

## 매핑
- 본 리포 [GOV-LLM-OUTPUT-HANDLING-001](../scanner-builtin/GOV-LLM-OUTPUT-HANDLING-001.md)
- OWASP LLM Top 10 2025 LLM05, CWE-79
