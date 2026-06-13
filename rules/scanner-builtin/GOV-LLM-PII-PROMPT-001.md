---
id: GOV-LLM-PII-PROMPT-001
title_ko: 개인정보 또는 내부정보가 AI 프롬프트로 전송될 수 있습니다
title_en: Possible sensitive data sent to an LLM
status: approved
source_layer: baseline
sources:
  - publisher: OWASP
    document: OWASP Top 10 for LLM Applications 2025
    item: LLM02
  - publisher: NIST
    document: SP 800-218A GenAI Profile
  - publisher: 개인정보보호위원회
    document: 생성형 AI 개발·활용을 위한 개인정보 처리 안내서
    version: "2025.8"
severity: critical
decision_default: block
domains: [llm-appsec]
languages: [python, javascript]
scenarios: [llm-integration, rag, agent]
related_baseline: [OWASP-LLM-2025-02]
verified_at: 2026-05-31
review_due: 2026-08-31
detection:
  patterns:
    # 환경변수 읽기(os.environ / process.env / getenv)는 안전하므로 제외한다.
    # 그 외 LLM 전송 컨텍스트에 민감값이 결합된 라인만 탐지한다.
    - '(?i)^(?!.*(?:os\.environ|process\.env|os\.getenv|getenv))(?=.*(openai|chat\.completions|messages\s*=|prompt\s*=)).*(resident|rrn|주민|민원|phone|전화|password|secret|api_key)'
  category: llm-appsec
  why_it_matters: 프롬프트는 외부 서비스, 로그, 모니터링, trace에 남을 수 있어 개인정보와 내부정보를 그대로 넣으면 안 됩니다.
  public_sector_impact:
    - 개인정보 유출
    - 내부 업무자료 유출
    - LLM 로그 잔존
  safe_fix: LLM 호출 전 개인정보를 제거·마스킹하고, 기관이 허용한 모델과 redaction gateway만 사용하세요.
  references:
    - OWASP-LLM-2025-LLM02
    - NIST AI 600-1
    - 개인정보 보호법
  can_auto_fix: false
examples:
  language: python
  positive:
    - "prompt = f\"민원인 주민번호는 {rrn} 입니다\""
    - "messages = [{\"role\": \"user\", \"content\": f\"전화 {phone}\"}]"
  negative:
    - "host = os.environ.get(\"OPENAI_API_KEY\")"
    - "api_key = os.environ[\"OPENAI_API_KEY\"]"
    - "messages = build_safe_messages(user_id)"
---

## 무엇이 위험한가
LLM API 호출 시 프롬프트에 주민번호·전화번호·비밀·민원 정보가 그대로 들어가면 외부 서비스 로그·trace·학습 후보 데이터에 남을 수 있습니다. 공공기관은 *원칙적으로 외부 LLM에 업무 데이터 전송 금지*입니다.

## 안전한 패턴
- redaction gateway (Presidio, 자체 마스킹) 통과
- 기관 허용 모델만 사용 (내부 sLLM 또는 승인된 외부)
- 프롬프트 로깅 시 PII 자동 마스킹
