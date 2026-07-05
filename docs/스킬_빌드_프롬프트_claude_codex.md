# gov-vibe-coding 스킬 — 빌드/개선용 프롬프트 모음

이 스킬을 처음부터 만들거나 이어서 개선할 때 Claude Code 또는 Codex에 그대로 붙여넣어 쓰는 프롬프트.
스킬·MCP 서버 모두 이 레포(GitHub `Lex6won/vibecode-checker`)에 있다.
(1차 골격은 `.claude/skills/gov-vibe-coding/`에 생성되어 있음.)

---

## A. Claude Code — 스킬 신규 생성 프롬프트

```
당신은 공공기관(한국) 대상 Claude Code 스킬을 만든다.
대상 사용자는 "보안을 잘 모르고 설계도 어려워하는 공무원"이다. 스킬 하나를 설치하면
기획(企劃) → 설계 → 보안점검을 한 흐름으로 도와야 한다.

요구사항:
1) 통합 스킬 1개. 경로: `.claude/skills/gov-vibe-coding/SKILL.md`.
   frontmatter의 description은 "사이트/챗봇/자동화 만들어줘", "안전하게 개발하고 싶어",
   기획·설계 도움 요청 시 트리거되도록 한국어로 작성.
2) 보안 점검은 MCP 전용으로 `vibecode-checker`(별칭 gov-vibe-security-kb) 도구만 사용한다.
   MCP 서버는 GitHub `Lex6won/vibecode-checker` 레포이며
   `pip install git+https://github.com/Lex6won/vibecode-checker.git`로 설치한다.
   도구: server_status, scan_code, scan_path, detect_secrets_and_pii, scan_dependencies,
   check_package, search_rules, get_rule, suggest_fix, render_report.
   시작 시 server_status로 연결 확인. offline 모드면 외부 URL clone 금지, 로컬 경로만 점검.
3) progressive disclosure: SKILL.md 본문은 짧게, 상세는 references/로 분리.
   references: 01-기획.md, 02-설계.md, 03-보안점검.md, 데이터분류.md, 체크리스트.md.
   templates: 기획서.md, 설계서.md, 보안점검결과.md.
4) 핵심 사상 "shift-left": 보안을 마지막 스캔이 아니라 기획·설계에 미리 심는다.
   - 기획에서 다루는 데이터 등급(고유식별/개인정보/내부/비밀값/공개)을 먼저 분류한다.
   - 설계에서 데이터 등급에 맞춰 보안 결정(환경변수, 마스킹, 파라미터 쿼리, egress 차단)을 못 박고,
     search_rules로 해당 시나리오(web-app/llm-integration/rag/agent/data-pipeline) 룰을 미리 본다.
5) 모든 산출물은 한국어, 비전문가 눈높이. CWE 코드 대신 "민원 DB가 조작될 수 있음" 같은 업무 영향으로 설명.
6) 원칙: 검사 파일 0개 = 안전 아님, requires_review = 안전 아님, critical/high는 차단,
   공식 보안적합성 검토를 대체하지 않음(마지막에 기관 보안 담당자 확인 권고).

위 구조대로 모든 파일을 생성하라. 한 번에 한 단계씩 사용자를 안내하는 톤으로 작성.
```

---

## B. Codex — 동일 스킬 생성 프롬프트 (파일 트리 명시형)

```
Create a Claude Code "skill" (a directory of markdown files) for Korean public-sector
civil servants who do "vibe coding" but don't know security. One install must guide them
through 기획(planning) → 설계(design) → 보안점검(security check).

The skill and its MCP backend both live in the GitHub repo `Lex6won/vibecode-checker`.
Install the MCP server with:
  pip install git+https://github.com/Lex6won/vibecode-checker.git

Generate these files with Korean, non-expert-friendly content:

.claude/skills/gov-vibe-coding/
  SKILL.md                  # YAML frontmatter: name=gov-vibe-coding, description(Korean trigger
                            #   phrases: "사이트/챗봇/자동화 만들어줘", "안전하게 개발하고 싶어").
                            #   Body: orchestrate the 3 phases; load each reference file lazily.
  references/01-기획.md      # 5-7 questions; classify DATA SENSITIVITY first; raise security flags early
  references/02-설계.md      # simple stack/architecture; lock in security decisions by data grade;
                            #   use MCP search_rules to pre-load relevant rules
  references/03-보안점검.md   # MCP-only workflow: server_status → scan_code/scan_path/
                            #   detect_secrets_and_pii/scan_dependencies → render_report
  references/데이터분류.md    # data grades: 고유식별정보/개인정보/내부정보/비밀값/공개
  references/체크리스트.md    # per-phase completion checklist
  templates/기획서.md, 설계서.md, 보안점검결과.md

Constraints:
- Security checks use ONLY the vibecode-checker (a.k.a. gov-vibe-security-kb) MCP server.
- shift-left: security is embedded in planning/design, not just a final scan.
- 0 scanned files != safe; requires_review != safe; block critical/high before save/commit/deploy.
- This skill does NOT replace official security review; end by recommending the agency's
  security officer sign-off.
- Keep SKILL.md short; push detail into references/ (progressive disclosure).
```

---

## C. 개선/반복용 프롬프트 (이미 생성된 스킬 위에)

```
.claude/skills/gov-vibe-coding/ 스킬을 개선한다. 다음을 반영하라:
- 실제 공무원 업무 시나리오 예시 3개 추가(민원 FAQ 챗봇, 엑셀 자동집계, 내부 통계 대시보드)와
  각 시나리오의 데이터 등급·권장 설계·예상 보안 룰을 references에 보강.
- SKILL.md description을 트리거가 더 잘 되도록 다듬되 한 단락 이내로 유지.
- 02-설계.md에 search_rules 호출 예시를 시나리오별로 추가(짧은 단일 키워드 사용).
변경 후 SKILL.md frontmatter가 유효한지, 파일 경로/링크가 맞는지 검증하라.
```

---

## D. 스킬 동작 테스트 프롬프트 (사람이 직접 검증)

Claude Code에서 새 대화로 아래를 입력해 스킬이 트리거·진행되는지 확인:
1. `민원인 자주 묻는 질문에 답하는 챗봇 만들고 싶어` → 기획 질문이 시작되는가?
2. (기획 후) → 설계에서 외부 LLM·개인정보 마스킹 결정이 나오는가?
3. `이 폴더 코드 안전한지 봐줘` + 경로 → server_status 후 scan_path가 도는가?
4. 결과가 차단/치명/경고 순서로, 업무 영향 + 수정 방향으로 설명되는가?
```
