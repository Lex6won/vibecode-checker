"""Public-sector vibe-coding security knowledge base and MCP server."""

# 버전 단일 원천(SSOT) — pyproject.toml 은 hatch dynamic version 으로 이 값을 읽는다.
# 과거에는 pyproject(0.2.1)와 이 파일(0.1.0)이 따로 놀아 server_status 가 틀린
# 버전을 보고했다(감사·재현성 요건 위반). 이제 실행 중인 코드가 곧 버전의 원천이다.
__version__ = "0.3.0"
