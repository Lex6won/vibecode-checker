# vibecode-checker

AI 코딩으로 만든 프로젝트의 소스·패키지를 점검하는 정적 분석 도구입니다. LLM 을 호출하지 않고 코드를 실행하지 않습니다.

## 설치

릴리스의 wheel 을 내려받아 설치합니다. Python 3.11 이상이 필요합니다.

```
pip install vibecode_checker-<버전>-py3-none-any.whl
```

## 사용

```
gvskb scan <폴더> --format html --output report --check-deps
gvskb check-package <이름> --ecosystem pypi --version <버전>
gvskb update-intel
gvskb sbom-report <파일>.sbom.cdx.json
gvskb registry-meta collect <요청>.json --out <번들>.zip --sign-key-env <키 환경변수>   # 외부망 PC
gvskb registry-meta import <번들>.zip                                                   # 폐쇄망 서버
```

폐쇄망 서버는 공식 저장소에 묻지 않습니다. 레지스트리 정보 번들을 반입하면 로컬 점검이 패키지 실재·발행일·라이선스까지 확인합니다.

종료 코드: 0 통과 · 1 조건부 · 2 차단 · 3 판정 불가.

## MCP 연결

```json
{ "mcpServers": { "gvskb": { "command": "gvskb-server" } } }
```

## 라이선스

[LICENSE](LICENSE) · 취약점 제보는 [SECURITY.md](SECURITY.md)
