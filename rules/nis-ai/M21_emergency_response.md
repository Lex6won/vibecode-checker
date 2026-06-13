---
id: NIS-AI-M21
title_ko: 비상대응 체계 마련
title_en: Emergency Response System
status: approved
source_layer: baseline
sources:
  - publisher: 국정원
    document: 국가·공공기관 AI 보안 가이드북
    version: "2025.12"
    item: M21
severity: high
decision_default: warn
domains: [agent-safety]
languages: [python]
scenarios: [agent]
related_baseline: [NIS-AI-T13, NIS-AI-M26]
verified_at: 2026-05-31
review_due: 2026-11-30
---

## 대책 요지 (가이드북 인용)
AI시스템이 잘못된 동작을 할 경우 *즉시 작업을 중단*시킬 수 있도록 *비상정지 기능* 마련. 비상차단용 인터페이스, 이상신호 탐지, 관리자 중단명령. **AI시스템이 제어시스템 등 타 시스템 자동화에 활용 중일 경우 이상행위 탐지 시 즉각 수동운영 모드 전환** 및 비상정지.

## 안전한 패턴 — Kill Switch
```python
class AIAgent:
    def __init__(self):
        self.kill_switch = KillSwitch()  # 관리자 즉시 중단
    def execute(self, action):
        if self.kill_switch.is_active():
            raise SystemAbort("관리자 비상정지")
        ...
```

## 공공 환경 적용
- AI 정수장: 이상 탐지 → *수동 운영 모드* 전환
- AI 결재 보조: 이상 동작 → 결재 라인 *자동 보류*
- 모든 사고는 *로그 보존* 후 사후 원인 분석

## 매핑
- OWASP Agentic 2026 ASI08 (Cascading Failures), ASI10 (Rogue Agents)
