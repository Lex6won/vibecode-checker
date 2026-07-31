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
    # sk_<벤더>_<본문> 형태 — Stripe(sk_live_·sk_test_), 기관 발급 키 등.
    # `sk_` 만으로는 잡지 않는다: 하이픈과 달리 언더스코어는 식별자에 흔해
    # sk_some_long_variable_name 같은 정상 코드가 오탐이 된다. 그래서
    #   ① 벤더 구절(sk_xxx_)을 요구하고
    #   ② 본문에 숫자나 대문자가 최소 1개 있을 것을 요구한다(전부 소문자면
    #      키가 아니라 식별자일 가능성이 높다. 32자 난수 키가 숫자·대문자를
    #      하나도 안 가질 확률은 무시할 수준).
    - 'sk_[A-Za-z0-9]{2,}_(?=[A-Za-z0-9]*[0-9A-Z])[A-Za-z0-9]{16,}'
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
    # 변수명 없이 값만 인자로 넘기는 형태 — 변수명 기반 패턴이 놓치는 자리
    - 'client = RegistryClient(base_url, "sk_ggtrust_Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ")'
    # 실제 벤더 접두사(sk_live_·sk_test_ 등)는 예시에도 쓰지 않는다 — GitHub
    # 푸시 보호가 이 파일을 실제 유출로 판단해 푸시를 거부한다(실측). 형태만
    # 같으면 패턴 검증에는 충분하다.
    - 'client = VendorSDK(api_key="sk_vendor_Ab3xK9mQ2pR7sT1uV5wY8zC4")'
  negative:
    - "pi = 3.14"
    - 'greeting = "hello world"'
    - "api_key = 'YOUR_KEY_HERE'"
    - 'api_key = "<your-api-key>"'
    - 'password = "XXXXXXXXXXXX"'
    # 언더스코어 식별자는 키가 아니다 — 벤더 구절이 있어도 본문이 전부 소문자면 제외
    - "sk_model_pipeline_transformer = build()"
---

## 무엇이 위험한가
하드코딩된 API 키·비밀번호·토큰은 Git history에 영구 보존되며, LLM 프롬프트로 흘러가면 외부 서비스 로그에도 남습니다. 한 번 노출된 자격증명은 *즉시 폐기·재발급*이 원칙입니다.

## 안전한 패턴
```python
import os
api_key = os.environ["OPENAI_API_KEY"]  # 환경변수
# 또는 secret manager (AWS Secrets Manager / Azure Key Vault / 기관 내부 vault)
```
