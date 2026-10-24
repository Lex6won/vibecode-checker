---
id: GOV-BIDI-CONTROL-001
title_ko: 양방향 제어 문자가 소스에 있어 화면 표시와 실제 실행 순서가 다를 수 있습니다
title_en: Bidirectional control characters (Trojan Source) in source code
status: approved
source_layer: baseline
sources:
  - publisher: University of Cambridge
    document: "Trojan Source: Invisible Vulnerabilities"
    version: CVE-2021-42574
  - publisher: Unicode Consortium
    document: UTS #39 Unicode Security Mechanisms
cwe: [CWE-94, CWE-451]
severity: high
decision_default: block
domains: [hidden-code]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration]
related_baseline: [GOV-HIDDEN-UNICODE-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  patterns: []
  confidence: confirmed
  category: hidden-code
  why_it_matters: >-
    U+202A~U+202E(LRE·RLE·PDF·LRO·RLO)와 U+2066~U+2069(LRI·RLI·FSI·PDI)는 뒤따르는 글자의
    **표시 순서**를 바꿉니다. 컴파일러·인터프리터는 파일에 적힌 순서대로 읽고, 사람은 화면에
    보이는 순서대로 읽습니다. 그래서 "주석처럼 보이는 줄"이 실제로는 실행되고, "실행 코드처럼
    보이는 줄"이 주석이 될 수 있습니다(CVE-2021-42574). 한국어·영어 소스에는 쓸 이유가 없습니다.
  public_sector_impact:
    - 코드 리뷰에서 승인한 내용과 실제 실행 내용이 다름
    - 인증 우회·검증 생략 코드가 주석으로 위장
  safe_fix: |
    1. 해당 줄의 제어 문자를 16진 뷰어로 확인하고 **모두 제거**하세요. 아랍어·히브리어 UI 문자열이
       필요한 경우에도 소스 코드가 아니라 리소스 파일(JSON·PO)에 두고, 코드에는 이스케이프(`\u202E`)로 적습니다.
    2. 저장소 전체에서 같은 문자를 찾으세요: `grep -rP "[\x{202A}-\x{202E}\x{2066}-\x{2069}]" .`
    3. 이 파일의 출처(패키지·PR·AI 생성)를 확인하고 같은 출처를 함께 점검하세요.
  references:
    - CVE-2021-42574 Trojan Source
    - CWE-451 User Interface Misrepresentation of Critical Information
  can_auto_fix: false
examples:
  positive:
    - "if access_level != \"user\u202E \u2066// Check if admin\u2069 \u2066\":"
    - "const s = \"\u202Aabc\u202C\";"
  negative:
    - "label = \"مرحبا\"  # 아랍어 문자열(제어 문자 없음)"
    - "x = 1  # 정상 주석"
---

## 무엇이 위험한가

보이는 코드와 실행되는 코드가 다르다. 리뷰 승인 자체가 무력화된다.

## 오해하지 마세요

RTL 언어 **문자 자체**(아랍어·히브리어 글자)는 잡지 않는다. 잡는 것은 **제어 문자**만이다.
