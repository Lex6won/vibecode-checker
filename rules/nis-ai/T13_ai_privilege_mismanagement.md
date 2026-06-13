---
id: NIS-AI-T13
title_ko: AI시스템 권한관리 부실
title_en: AI System Privilege Mismanagement
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: T13
severity: critical
decision_default: warn
domains: [agent-safety, llm-appsec]
languages: [python, javascript]
scenarios: [agent]
related_baseline: [NIS-AI-M19, NIS-AI-M20, NIS-AI-M21, OWASP-LLM-2025-06, GOV-AGENT-EXCESSIVE-AUTHORITY-001]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 위협 정의 (가이드북 인용)
AI시스템에 과도한 권한을 부여하여 AI시스템이 사용자의 의사결정 없이 임의로 다른 시스템을 제어 혹은 데이터를 수정하거나, 운영 목적을 벗어나 예기치 않게 동작하며 사용자가 즉시 제어 혹은 중단할 수 없는 상황 발생. AI시스템이 전력·교통·정수 등 주요 제어시스템을 임의로 조작하여 정전·교통사고·식수오염 등 피해가 발생하거나, 민감정보 삭제 혹은 개인정보 임의전송 등 악성행위 수행.

## 공공 환경 시나리오
- **실측 사례**: Replit AI가 사용자 허락 없이 DB 삭제 후 "참사 실패" 자인 (2025.7)
- AI 정수장 시스템이 *임의로* 약품 주입량 조정 → 식수 안전 위협
- 결재 보조 AI가 *임의로* 전자결재 시스템 호출

## 대응 (M19, M20, M21)
- 과도한 권한 부여 제한 (M19) — 최소 권한 + 안전 경계 설정
- 민감 명령 승인 절차 마련 (M20) — HITL 필수
- 비상대응 체계 마련 (M21) — kill switch

## 매핑
- OWASP LLM Top 10 2025 LLM06 (Excessive Agency)
- OWASP Agentic Top 10 2026 ASI02 (Tool Misuse)
- 본 리포 [GOV-AGENT-EXCESSIVE-AUTHORITY-001](../scanner-builtin/GOV-AGENT-EXCESSIVE-AUTHORITY-001.md) — 실시간 검사 가능
