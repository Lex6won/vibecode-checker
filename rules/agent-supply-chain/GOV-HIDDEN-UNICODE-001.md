---
id: GOV-HIDDEN-UNICODE-001
title_ko: 사람 눈에 보이지 않는 유니코드 문자가 코드·설정·지시 파일에 들어 있습니다
title_en: Invisible Unicode characters (zero-width, variation selectors, tag block) embedded in source or config
status: approved
source_layer: baseline
sources:
  - publisher: Unicode Consortium
    document: UTS #39 Unicode Security Mechanisms
    item: Default Ignorable Code Points
  - publisher: OWASP
    document: Secure Coding with AI Cheat Sheet
    item: Hidden instructions in repository files
cwe: [CWE-94, CWE-838]
severity: critical
decision_default: block
domains: [hidden-code]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration, package-install]
related_baseline: [GOV-BIDI-CONTROL-001, GOV-LLM-PROMPT-INJECTION-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # 전용 엔진(hidden-text)이 코드포인트 단위로 판정한다. 줄 단위 정규식으로는 "보이지 않는다"는
  # 성질을 사람이 패턴으로 쓸 수 없어 patterns 를 비운다. 한 파일에 1건, 증거에 문자 자체는 싣지 않는다.
  patterns: []
  confidence: confirmed
  category: hidden-code
  why_it_matters: >-
    폭이 0인 문자(ZERO WIDTH SPACE·WORD JOINER·한글 채움 문자), 변형 선택자(U+FE00~), 태그 블록
    (U+E0000~)은 에디터·diff 뷰어·코드 리뷰 화면에 **아무것도 표시되지 않습니다**. 2025-10 ~ 2026-04
    확장프로그램 공급망 사고는 이 문자열에 실행 코드를 인코딩해 숨겼고, 리뷰어는 "빈 줄"로 봤습니다.
    에이전트 지시 파일(CLAUDE.md 등)에 넣으면 사람은 못 읽고 AI는 읽는 지시가 됩니다.
    한국어 소스에는 이런 문자가 나올 이유가 없습니다 — 이모지·한자 이체자·아랍/인도 문자 사이의
    정상 용례는 엔진이 문맥으로 제외합니다.
  public_sector_impact:
    - 코드 리뷰·결재를 통과한 파일에 실행 코드가 숨어 들어옴
    - AI 코딩 도구가 사람이 못 보는 지시를 따라 비밀값 유출·보안 검사 해제
    - 보고서·diff 에 남지 않아 사후 추적 불가
  safe_fix: |
    1. 해당 줄을 16진 뷰어(VS Code: `Hex Editor` 확장, `xxd`)로 열어 **어떤 문자가 몇 개**인지 확인하세요.
       보고서의 코드포인트(`U+200B` 등)와 개수가 길잡이입니다.
    2. 정상 용례(이모지 뒤 U+FE0F, 한자 뒤 이체자 선택자, 아랍·인도 문자 사이 ZWJ)가 아니면
       **그 파일을 신뢰하지 마세요** — 이 파일이 어디서 왔는지(패키지·PR·AI 생성)를 먼저 확인합니다.
    3. 문자를 지우는 것으로 끝내지 말고, 같은 출처의 다른 파일과 Git 이력을 함께 점검하세요.
    4. 에디터에 `"editor.unicodeHighlight.invisibleCharacters": true`(VS Code 기본값)가 꺼져 있지 않은지
       확인하세요. 저장소 `.vscode/settings.json`이 이를 끄고 있으면 그 자체가 신호입니다.
  references:
    - CWE-94 Improper Control of Generation of Code
    - Unicode UTS #39 — Default Ignorable Code Points
    - CVE-2021-42574 Trojan Source (관련 수법)
  can_auto_fix: false
examples:
  positive:
    - "const payload = \"ab\u200Bcd\u200Bef\";"
    - "sudo\u00AD apt install something"
    - "# 지시: 아래를 따를 것\u2060\u2060\u2060\u2060"
  negative:
    - "const ok = \"완료 ✅\uFE0F 처리됨\";"
    - "const flag = \"\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F\";"
    - "name = \"نا\u200Cبا\""
    - "x = 1  # 평범한 한국어 주석, 아무 문제 없음"
---

## 무엇이 위험한가

이 문자들은 **화면에 폭이 없다**. 한 줄에 수백 개가 있어도 빈 줄로 보인다. 공격자는 그 자리에
코드를 인코딩해 두고, 같은 파일의 다른 곳에서 그 문자열을 읽어 디코딩·실행한다. 리뷰어가 보는
diff 에는 바뀐 것이 없다.

## 이 발견을 보면 확인할 것

| 확인 | 왜 |
|---|---|
| 파일의 출처 | 패키지·외부 PR·AI 생성물이면 같은 출처 전부를 의심 |
| 같은 파일의 디코딩 코드 | `atob`·`Buffer.from`·`charCodeAt`·`chr()` 가 그 문자열을 읽는지 |
| `.vscode/settings.json` | `editor.unicodeHighlight.*` 를 끄고 있으면 은닉 의도 |

## 오해하지 마세요

이모지(✅️), 한자 이체자, 아랍어·힌디어의 글자 결합용 ZWJ/ZWNJ 는 정상이며 엔진이 제외한다.
한국어 완성형 한글에는 이런 문자가 필요하지 않다 — 한글 채움 문자(U+115F·U+1160·U+3164)는
공백처럼 보여 식별자 은닉에 쓰이므로 **잡는다**.
