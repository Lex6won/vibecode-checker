# gov-vibe-coding 스킬

공무원·공공기관 담당자가 AI(바이브 코딩)로 무언가를 만들 때 **기획 → 설계 → 보안점검**을
단계적으로 안내하는 Claude Code 스킬. 보안 점검은 같은 레포의 `vibecode-checker`
(`gov-vibe-security-kb`) MCP 서버로 수행한다. (GitHub: `Lex6won/vibecode-checker`)

## 구성
```
.claude/skills/gov-vibe-coding/
├─ SKILL.md            # 오케스트레이터(트리거 + 3단계 흐름)
├─ references/         # 단계별 상세 가이드(필요할 때 로드)
│   ├─ 01-기획.md
│   ├─ 02-설계.md
│   ├─ 03-보안점검.md
│   ├─ 데이터분류.md
│   └─ 체크리스트.md
└─ templates/          # 산출물 양식
    ├─ 기획서.md
    ├─ 설계서.md
    └─ 보안점검결과.md
```

## 설치
1. **스킬**: 이 스킬은 vibecode-checker 레포에 포함되어 있다. 레포를 클론하면 함께 받아진다.
   - 프로젝트용: 레포 안의 `.claude/skills/gov-vibe-coding/` 그대로 사용(현재 위치).
   - 개인용으로 어디서나 쓰려면: 이 폴더를 `~/.claude/skills/gov-vibe-coding/`로 복사.
2. **보안 점검 MCP 서버** 설치:
   ```bash
   pip install git+https://github.com/Lex6won/vibecode-checker.git
   ```
3. **MCP 등록**(`.mcp.json` 또는 Claude Code MCP 설정):
   ```json
   {
     "mcpServers": {
       "vibecode-checker": {
         "command": "python",
         "args": ["-m", "gvskb.server"],
         "env": { "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8" }
       }
     }
   }
   ```
   - 망분리 환경: `env`에 `"GVSKB_MODE": "offline"` 추가.
4. Claude Code에서 "민원 챗봇 만들고 싶어" 같은 말로 스킬이 자동 트리거되는지 확인.

## 사용 예
- "엑셀 자동 정리 도구 만들어줘" → 기획 질문 시작 → 설계 → 코드 생성 → 보안점검까지.
- "이 폴더 코드 안전한지 봐줘" → 곧장 3단계(보안점검)로.

## 주의
- 이 스킬과 MCP는 **공식 보안적합성 검토를 대체하지 않는다.** 최종은 기관 보안 담당자 확인.
- critical/high 위험은 저장·커밋·배포 전 차단을 원칙으로 한다.
