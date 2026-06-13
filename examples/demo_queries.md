# 데모 — 이렇게 말하면 됩니다

도구 이름을 외울 필요 없이, 자연어로 말하면 AI가 알맞은 MCP 도구를 골라
실행하고 한국어 보고서까지 만듭니다. 아래는 의도별 예시입니다.

트리거 단어: **보안 · 점검 · 체크 · 검토 · 검사 · 스캔 · "안전한지"**

---

## 1. 보안 점검 (메인) — 점검 → 보고서

> *"이 폴더 보안 점검해줘 → ./my-project"*
> *"방금 만든 이 코드 안전한지 체크해줘"*
> *"이 파일 검토하고 위험한 부분을 한국어 보고서로 만들어줘"*

AI가 호출하는 도구 (경로면 `scan_path`, 코드 조각이면 `scan_code`):

```json
{
  "tool": "scan_code",
  "arguments": {
    "filename": "app.py",
    "language": "python",
    "code": "name = input('name')\ncursor.execute(f\"SELECT * FROM complaints WHERE name = '{name}'\")"
  }
}
```

이어서 보고서를 만들 때 (Markdown + 보기 좋은 HTML 함께):

```json
{
  "tool": "render_report",
  "arguments": { "report": "<scan 결과 JSON>", "format": "both" }
}
```

> Claude·Cursor에서는 `/보안점검` 명령 하나로 위 과정을 한 번에 실행합니다.

---

## 2. 패키지 확인 — 설치 전에 안전한지

> *"AI가 `openai-tools-helper` 설치하라는데 안전한지 확인해줘"*

```json
{
  "tool": "check_package",
  "arguments": { "name": "openai-tools-helper", "ecosystem": "pypi" }
}
```

여러 패키지(requirements.txt 등)를 한 번에:

```json
{
  "tool": "scan_dependencies",
  "arguments": { "manifest_text": "requests==2.0.0\nopenai-tools-helper==1.2.3", "ecosystem": "pypi" }
}
```

---

## 3. 재검증 — 고친 뒤 다시

> *"고쳤어, 다시 검사해줘"*

수정한 코드를 다시 `scan_code`(또는 파일이면 `scan_path`)에 넘기면 됩니다.
이전과 비교해 발견 사항이 줄었는지 확인하세요.

---

## (참고) 보안 기준 검색

> *"RAG 챗봇에 검증 안 된 문서를 넣어도 되는지 관련 공공 보안 기준을 찾아줘"*

```json
{
  "tool": "search_rules",
  "arguments": { "query": "trusted data source", "scenario": "rag", "severity_min": "high" }
}
```

---

## (참고) 개인정보 · 시크릿만 빠르게

> *"이 설정 파일에 API key나 개인정보가 들어갔는지 확인해줘"*

```json
{
  "tool": "detect_secrets_and_pii",
  "arguments": {
    "filename": "settings.py",
    "code": "OPENAI_API_KEY = \"sk-proj-abcdefghijklmnopqrstuvwxyz\"\nphone = \"010-1234-5678\""
  }
}
```

---

> 보고서는 무엇이 위험한지·왜 위험한지·어떻게 고치는지(safe_fix)·근거 출처를
> 항목마다 알려줍니다. 검사된 파일이 0개면 '안전'이 아니라 경로·확장자를 확인하라는
> 뜻이고, '판정 불가'는 안전을 의미하지 않습니다. 이 점검은 공식 보안적합성 검토를
> 대체하지 않습니다.