---
id: KISA-PY-INPUT-02
title_ko: Python 코드 삽입 위험 - eval/exec/compile 사용
title_en: Code injection via eval/exec/compile in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 2. 코드 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-21
cwe: [CWE-94, CWE-95]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, llm-integration, agent]
related_baseline: [MOIS-49-INPUT-02]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - '(?<![A-Za-z0-9_.])eval\s*\('
    - '(?<![A-Za-z0-9_.])exec\s*\('
    - '(?<![A-Za-z0-9_.])compile\s*\([^)]*,[^)]*,\s*["''](exec|eval|single)["'']'
  # 같은 코드를 다른 각도로 보는 룰과 한 묶음(GOV-CODE-EXEC-001). 같은 줄에 함께 걸리면
  # 가장 확실한 엔진의 발견 하나만 남고 나머지는 also_matched 로 합쳐진다(개선요청 #34 C).
  dedup_group: py-code-exec
  category: kisa-secure-coding
  why_it_matters: >-
    eval/exec/compile은 *문자열을 Python 코드로 실행*합니다. 사용자 입력이 직접
    또는 간접적으로 흘러들어가면 임의 명령 실행으로 즉시 발전합니다. LLM이
    생성한 수식·표현식을 평가하려고 eval을 쓰는 패턴은 공공기관 챗봇·민원
    시스템에서 가장 위험한 형태입니다.
  public_sector_impact:
    - 서버 원격 명령 실행
    - 행정 시스템 침해
    - LLM 출력으로 인한 RCE
  safe_fix: |
    수식/표현식은 ast.literal_eval(안전한 리터럴만) 또는 별도 파서/화이트리스트로 처리하세요.
    LLM이 만든 JSON은 json.loads()를 사용하고, 그 외 *문자열 → 코드 실행 경로는 차단*합니다.
  references:
    - KISA Python 가이드 제2절 2
    - MOIS-49-INPUT-02
    - CWE-94
    - OWASP LLM05 Improper Output Handling
  can_auto_fix: false
examples:
  language: python
  positive:
    - "eval(user_input)"
    - "exec(code)"
    - 'co = compile(src, "<s>", "exec")'
  negative:
    - "engine.eval(expression)"
    - "model.predict(x)"
    - "ast.literal_eval(text)"
---

## 무엇이 위험한가
LLM·자동화 도구는 "사용자가 입력한 수식을 계산해줘" 같은 요구에 자주 `eval()`을 제안합니다. 이게 그대로 운영 코드에 들어가면 *서버 원격 명령 실행*으로 직결됩니다. AI 코딩 도우미가 만든 코드에서 가장 흔한 critical 위험 중 하나입니다.

## 안전한 패턴 (가이드 원문 인용)
- 안전한 리터럴 평가: `ast.literal_eval(text)` (dict·list·숫자만 허용)
- 수식 평가: `simpleeval`, `sympy.sympify(..., evaluate=False)` 등 화이트리스트 파서
- LLM 출력: `json.loads()` 또는 Pydantic 검증

## False positive 주의
- `re.compile(pattern)`, `obj.eval()` 같은 메소드 호출은 lookbehind로 제외됩니다.
