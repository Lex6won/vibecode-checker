---
id: GOV-SECRET-APIKEY-001
title_ko: API 키 또는 비밀번호로 보이는 값이 코드에 포함되어 있습니다
title_en: Secret or API key detected
status: approved
source_layer: baseline
sources:
  - publisher: NIST
    document: SP 800-218 SSDF
  - publisher: OWASP
    document: ASVS 5.0
    item: V6 Authentication and Session Management
severity: critical
decision_default: block
domains: [secret-scanning]
languages: [python, javascript, java, yaml, toml]
scenarios: [llm-integration, web-app, data-pipeline, agent]
related_baseline: [OWASP-LLM-2025-02]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    # 값이 명백한 플레이스홀더(YOUR_KEY_HERE, XXXX…, <your-token>, CHANGEME, 예시 등)면
    # 실제 시크릿이 아니므로 부정 전방탐색으로 제외한다. 실제 키 값에는 이 토큰들이
    # 사실상 나타나지 않으므로 미탐 위험은 무시할 수 있다.
    - '(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*["''](?![^"'']*(?:YOUR[_-]|[_-]HERE|X{6,}|CHANGE[_-]?ME|PLACEHOLDER|<[A-Za-z]|\*\*\*|예시|여기))[^"'']{8,}["'']'
    - 'sk-[A-Za-z0-9_-]{20,}'
    - 'AKIA[0-9A-Z]{16}'
  category: secret-scanning
  why_it_matters: 키가 저장소나 LLM 프롬프트에 노출되면 행정시스템, 클라우드, 외부 API가 탈취될 수 있습니다.
  public_sector_impact:
    - 계정 탈취
    - 비용 발생
    - 내부 시스템 침해
  safe_fix: 키는 환경변수, 기관 secret manager, 배포 시스템의 안전한 비밀 저장소로 옮기세요.
  references:
    - NIST SSDF
    - OWASP ASVS V6
  can_auto_fix: false
examples:
  language: python
  positive:
    - 'OPENAI_API_KEY = "sk-proj-aaabbbcccdddeeefffggghhhiiijjj"'
    - 'password = "supersecretvalue123"'
    - 'token = "AKIAABCDEFGHIJKLMNOP"'
  negative:
    - "pi = 3.14"
    - 'greeting = "hello world"'
    - "api_key = 'YOUR_KEY_HERE'"
    - 'api_key = "<your-api-key>"'
    - 'password = "XXXXXXXXXXXX"'
---

## 무엇이 위험한가
하드코딩된 API 키·비밀번호·토큰은 Git history에 영구 보존되며, LLM 프롬프트로 흘러가면 외부 서비스 로그에도 남습니다. 한 번 노출된 자격증명은 *즉시 폐기·재발급*이 원칙입니다.

## 안전한 패턴
```python
import os
api_key = os.environ["OPENAI_API_KEY"]  # 환경변수
# 또는 secret manager (AWS Secrets Manager / Azure Key Vault / 기관 내부 vault)
```
