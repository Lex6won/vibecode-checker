---
id: NIS-AI-M19
title_ko: 과도한 권한 부여 제한
title_en: Excessive Privilege Restriction
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M19
severity: critical
decision_default: warn
domains: [agent-safety]
languages: [python, javascript]
scenarios: [agent]
related_baseline: [NIS-AI-T13, NIS-AI-M20, OWASP-LLM-2025-06, GOV-AGENT-EXCESSIVE-AUTHORITY-001]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI시스템의 활용 목적에 따라 *필요한 최소한의 권한*만 부여. 접근 가능 시스템·데이터 제한. 데이터 수정·시스템 제어 등 민감 작업에는 *사람의 검토와 승인* 절차. **제어 영역과 제어값의 상·하한선** 마련.

## 안전한 패턴
- 도구별 권한 등급화 (read-only / state-change / destructive)
- 안전 경계 설정: 값 상·하한선 (예: 약품 주입량 0~10ml)
- 외부 연계 시 *내부 제어시스템* 임의 조작 불가

## 공공 환경 적용
- AI 정수장: 약품 주입 *상한선* 코드로 강제
- AI 결재 보조: *조회만* 가능, 작성·승인은 사람

## 매핑
- 본 리포 [GOV-AGENT-EXCESSIVE-AUTHORITY-001](../scanner-builtin/GOV-AGENT-EXCESSIVE-AUTHORITY-001.md) — 실시간 검사
- OWASP LLM Top 10 2025 LLM06
- OWASP Agentic 2026 ASI02, ASI03
