---
id: INTEL-2026-SLOPSQUATTING
title_ko: 슬롭스쿼팅 — LLM 환각 패키지명 공격
title_en: Slopsquatting (LLM-Hallucinated Package Attack)
status: approved
source_layer: realtime
sources:
  - publisher: Socket.dev
    document: Slopsquatting blog series
    version: "2026-04"
    url: https://socket.dev/blog/category/security-news
  - publisher: Aikido
    document: Slopsquatting AI Package Hallucination Attacks
    version: "2026"
    url: https://www.aikido.dev/blog/slopsquatting-ai-package-hallucination-attacks
  - publisher: OSV
    document: MAL- 시리즈 advisory
    item: MAL-2026-*
cwe: [CWE-829, CWE-494, CWE-1357]
languages: [python, javascript]
scenarios: [package-install, ai-codegen]
severity: high
related_baseline: [NIS-AI-M01, OWASP-LLM-2025-02]
verified_at: 2026-05-30
review_due: 2026-08-30
---

## 무엇이 위험한가
LLM이 코드 생성 시 **존재하지 않는 패키지 이름**을 환각으로 만들어내는 경우가 있다. 공격자는 이 환각 패턴을 미리 등록해 두고, 사용자가 의심 없이 `pip install`·`npm install`을 실행하면 그대로 감염된다.

**2026년 측정 환각률** (arXiv 2605.17062):
- Claude Haiku 4.5: 4.62%
- GPT-5.4-mini: 6.10%
- 오픈소스 모델(CodeLlama, Mistral 등): 더 높음

**실제 사건**:
- 2026-01 npm `react-codeshift` (실재 `jscodeshift` + `react-codemod` 합성형 환각명)
- 2026-04 Bitwarden CLI 경유 첫 in-the-wild AI 코딩 어시스턴트 타겟 공격
- 2026-05 TrapDoor 캠페인 (34 패키지 / 384 버전)

## 위험한 패턴 예시
```bash
# AI가 자신 있게 추천한 가짜 패키지를 검증 없이 설치
pip install ai-validator-helper  # 실재하지 않을 수 있음
npm install openai-tools-sdk     # 의심 패턴: 복합 이름 + AI 키워드
```

## 안전한 절차
1. AI가 추천한 패키지는 설치 전 **반드시 출처 확인**:
   - PyPI: https://pypi.org/project/&lt;name&gt;/ → 등록일·다운로드·리포지토리 링크
   - npm: https://www.npmjs.com/package/&lt;name&gt;
2. 등록 30일 이내 + 다운로드 < 1000 + 광범위한 AI 추천이면 보류
3. `check_package` MCP 도구로 OSV.dev MAL- 매칭 즉시 확인
4. 사내 미러(레지스트리 프록시)에 허용 패키지만 캐시

## 점검 방법 (이 PoC의 자동 검출)
- MCP `check_package(name, ecosystem)` 호출 → OSV API에서 `MAL-YYYY-XXXX` advisory 존재 확인
- 휴리스틱: 이름의 하이픈·언더스코어 ≥ 2 + AI 키워드(ai/gpt/llm/copilot/tool/helper/agent) 동시 매칭 시 의심 신호 가중
- 단일 신호로 차단하지 말고 다중 신호 점수화 (오탐 방지)

## 원문 인용
> "Slopsquatting is what happens when an attacker registers a package name that AI models tend to hallucinate, then waits for developers to install it on an AI's recommendation."  
> — Aikido Security, 2026
