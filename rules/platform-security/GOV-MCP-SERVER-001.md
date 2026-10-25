---
id: GOV-MCP-SERVER-001
title_ko: MCP 서버 구현이 보안 지침을 벗어났습니다 (도구 인자 미검증 · 전송 바인딩/Origin · 토큰 전달 · 메타데이터 조회)
title_en: MCP server implementation deviates from security best practices (unvalidated tool args, transport binding/Origin, token passthrough, metadata lookup)
status: approved
source_layer: baseline
sources:
  - publisher: Model Context Protocol
    document: Security Best Practices
    url: https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices
  - publisher: Model Context Protocol
    document: Specification — Transports (Streamable HTTP · Origin validation)
cwe: [CWE-20, CWE-346, CWE-918]
severity: high
decision_default: block
domains: [platform-security]
languages: [python, javascript, typescript]
scenarios: [agent, llm-integration]
related_baseline: [GOV-MCP-CONFIG-001, GOV-LLM-PROMPT-INJECTION-001, GOV-AGENT-EXCESSIVE-AUTHORITY-001]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # ecosystem-surface 수집기(@modelcontextprotocol/sdk · fastmcp · mcp 의존성이 있을 때만, MCP 모듈을 import 하는 파일만).
  # 확정: 도구 모듈에서 동적으로 조립한 명령이 프로세스 실행에 닿음. 유력: 도구 인자가 검증 없이 파일 경로로 열림 · HTTP/SSE 전송 또는
  # 0.0.0.0 바인딩에 Origin/허용 호스트 검증 없음 · 클라이언트 Authorization 헤더를 상위 요청에 전달 · .well-known 조회 URL 을 입력으로
  # 조립 · readOnlyHint: true 근처에 쓰기·삭제·실행 호출.
  patterns: []
  confidence: likely
  category: platform-security
  why_it_matters: >-
    MCP 보안 지침은 도구 인자를 스키마로 검증하고 실행·파일·요청 경계에서 허용 목록을 두며, HTTP 전송은 Origin 을 검증하고 로컬에만
    바인딩하고, 클라이언트 토큰을 상위 서비스에 그대로 전달하지 않도록 요구합니다. 이 룰은 그 요구에서 벗어난 자리를 표시합니다.
  public_sector_impact:
    - 도구 호출이 곧 실행·파일 접근이므로 검증 부재는 에이전트 권한 전체의 문제가 됨
  safe_fix: |
    1. 도구 인자는 스키마(pydantic·zod)로 검증하고, 셸 문자열 조립 대신 인자 배열과 허용 명령 목록을 쓰세요. 파일 경로는 정규화 후
       허용 디렉터리 안인지 확인하세요.
    2. HTTP/SSE 전송은 `127.0.0.1` 에 바인딩하고 `Origin` 헤더를 허용 목록과 대조하세요(SDK 의 DNS 리바인딩 보호 옵션 사용).
    3. 클라이언트의 Authorization 토큰을 상위 API 로 전달하지 말고, 서버 자신의 자격증명을 쓰세요. OAuth 메타데이터 URL 은 상수로 두세요.
    4. `readOnlyHint`·`destructiveHint` 는 실제 동작과 일치시키세요.
  references:
    - MCP Security Best Practices
    - CWE-918 Server-Side Request Forgery
  can_auto_fix: false
examples:
  positive:
    - "from fastmcp import FastMCP\nimport subprocess\nmcp = FastMCP('x')\n@mcp.tool()\ndef run(cmd: str) -> str:\n    return subprocess.run(f'tool {cmd}', shell=True, capture_output=True, text=True).stdout"
  negative:
    - "from fastmcp import FastMCP\nimport subprocess\nmcp = FastMCP('x')\n@mcp.tool()\ndef version() -> str:\n    return subprocess.run(['tool', '--version'], capture_output=True, text=True).stdout"
---

스키마 검증 + 인자 배열 + 로컬 바인딩 + Origin 검증이 갖춰진 서버는 잡지 않는다.
