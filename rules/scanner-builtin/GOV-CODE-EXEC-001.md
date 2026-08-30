---
id: GOV-CODE-EXEC-001
title_ko: 문자열을 코드로 실행하는 위험한 함수가 사용되었습니다
title_en: Dynamic code execution
status: approved
source_layer: baseline
sources:
  - publisher: NIST
    document: SP 800-218 SSDF
cwe: [CWE-94]
severity: critical
decision_default: block
domains: [gov-secure-coding]
languages: [python, data]
scenarios: [web-app, data-pipeline, llm-integration, agent]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    # 수신자가 있는 메서드 호출(`session.exec(stmt)` · `engine.eval(x)` ·
    # `pattern.exec(text)`)은 내장 eval/exec 가 아니다. `\b` 는 `.` 뒤를 막지
    # 못해 SQLModel 의 `session.exec(select(...))` 가 치명으로 올라왔다(실측
    # 2026-08-29, 13줄). KISA-PY-INPUT-02 와 같은 경계를 쓰고, `builtins.exec`
    # 로 우회하는 형태만 명시적으로 되살린다.
    - '(?<![A-Za-z0-9_.])(eval|exec)\s*\(|\bbuiltins\.(eval|exec)\s*\('
  # 같은 코드를 다른 각도로 보는 룰과 한 묶음(KISA-PY-INPUT-02). 같은 줄에 함께 걸리면
  # 가장 확실한 엔진의 발견 하나만 남고 나머지는 also_matched 로 합쳐진다(개선요청 #34 C).
  dedup_group: py-code-exec
  category: gov-secure-coding
  why_it_matters: 사용자 입력이나 LLM 출력이 eval/exec로 실행되면 공격자가 임의 코드를 실행할 수 있습니다.
  public_sector_impact:
    - 원격 코드 실행
    - 서버 침해
    - 자료 유출
  safe_fix: eval/exec 대신 허용된 명령만 처리하는 whitelist parser 또는 안전한 라이브러리를 사용하세요.
  references:
    - CWE-94
    - NIST SSDF
  can_auto_fix: false
examples:
  language: python
  positive:
    - "eval(user_input)"
    - "exec(code)"
    - "builtins.eval(s)"
  negative:
    - "pi = 3.14"
    - "name = 'hello world'"
    - "result = session.exec(stmt).all()"
    - "engine.eval(expression)"
    - "m = pattern.exec(text)"
    - "value = ast.literal_eval(raw)"
---

## 무엇이 위험한가
`eval()`/`exec()`는 임의 Python 코드를 실행합니다. 사용자 입력 또는 LLM 응답이 흘러 들어오면 *원격 코드 실행*이 됩니다. 바이브코딩에서 흔히 등장하는 안티패턴.

## 안전한 패턴
- 수식 평가: `ast.literal_eval()` 또는 안전한 expression parser
- 동적 디스패치: `dict[str, callable]` 매핑
- JSON 파싱: `json.loads()`
