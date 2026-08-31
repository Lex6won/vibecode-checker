<div align="center">

<!-- 로고: docs/assets/logo.png 를 추가하면 아래 줄의 주석을 해제하세요 -->
<!-- <img src="docs/assets/logo.png" alt="vibecode-checker" width="120"/> -->

# vibecode-checker

### AI가 만든 코드를 한국 공공기관 보안 기준으로 점검합니다.

AI 코딩 도구(ChatGPT·Claude·Copilot·Cursor)로 만든 코드에 숨은
**개인정보 노출 · API 키 · SQL 삽입 · 위험한 명령 실행 · 취약 패키지**를 찾아,
공무원이 이해할 수 있는 **한국어 보고서**로 알려주는 보안 점검 도구입니다.

![License](https://img.shields.io/badge/License-PolyForm%20Noncommercial%201.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.11+-green.svg)
![Tests](https://img.shields.io/badge/tests-1909_passed-success.svg)
![독립 벤치마크](https://img.shields.io/badge/독립_벤치마크-42%2F42_탐지_·_오탐_0-success.svg)
![룰](https://img.shields.io/badge/보안_룰-탐지_101_·_참조_227-orange.svg)
![오프라인](https://img.shields.io/badge/망분리-offline_지원-informational.svg)

</div>

---

## 이 도구가 하는 일

1. **검사** — 폴더나 코드를 주면 소스 코드, 사용 중인 패키지(requirements.txt·package.json), 폴더에 직접 넣어둔 라이브러리 파일(`static/*.min.js`)까지 한 번에 검사합니다. 코드는 외부로 전송되지 않습니다.
2. **판정** — 발견을 심각도(치명·높음·보통)와 조치(차단·경고·허용)로 나누고, 코드와 패키지를 **함께** 보고 결론 하나를 냅니다: **배포 승인 가능 / 미승인(차단) / 보류(확인 필요)**.
3. **보고서** — 무엇이 위험한지 → 왜 위험한지 → 어떻게 고치는지(안전한 코드 예시)를 한국어로 정리합니다. HTML 보고서를 인쇄하면 그대로 PDF 결재 문서가 됩니다.

쓰는 방법은 두 가지이고, 설치는 하나로 둘 다 됩니다.

- **터미널**: `gvskb scan ./내프로젝트`
- **AI 코딩 도구**(VS Code·Claude Desktop·Cursor·Claude Code)에 연결한 뒤 자연어로: *"이 폴더 보안 검사 해줘"*

## 다른 도구와 다른 점

| | 내용 |
|---|---|
| **한국 공공기관 기준** | KISA 시큐어코딩·행안부 개발보안·국정원 AI 가이드를 룰에 직접 반영합니다. 발견마다 "왜 위험한지 → 어떻게 고치는지"를 출처와 함께 한국어로 제시합니다. |
| **비전문가용 보고서** | 보고서 맨 위에 배포 승인/미승인 **결론**이 먼저 나옵니다. 보안 지식 없이 결론과 조치 가이드(3단계)만 따라 하면 됩니다. 상세 근거는 보안팀용으로 접혀 있습니다. |
| **코드+패키지 통합 판정** | 코드가 문제없어도 취약한 패키지를 쓰면 승인되지 않습니다. `package.json` 없이 폴더에 넣어둔 라이브러리 파일도 버전을 식별해 알려진 취약점과 대조합니다. |
| **망분리(폐쇄망) 지원** | `GVSKB_MODE=offline` 설정으로 외부 통신을 완전히 차단하고 동작합니다. 위협 정보(취약점·악성 패키지 목록)는 매일 자동 생성되는 반입 번들로 옮기며, sha256 해시로 변조를 검증합니다. |
| **판정의 한계를 표시** | "판정하지 못함"을 "안전"으로 바꿔 말하지 않습니다. 검사한 파일이 0개면 경로를 확인하라고 말하고, 캐시가 오래되면 판정을 보류로 낮추고, 탐지 못 하는 항목은 성능 표에 공개합니다. |
| **자동화 연결** | 종료 코드로 CI에서 커밋·배포를 차단할 수 있고, SARIF·SBOM(CycloneDX) 출력과 감사로그(JSONL)를 지원합니다. |

---

## 보고서는 이렇게 생겼습니다

검사 결과를 저장하면 텍스트(`.md`)와 HTML 보고서가 함께 만들어집니다.

<p align="center">
  <!-- jsDelivr 경유 — 기관망 다수가 raw.githubusercontent.com은 차단하고 camo 프록시는
       허용한다. GitHub은 자사 raw 주소는 camo로 감싸지 않지만 외부 도메인(jsDelivr)은
       감싸므로, 열람자는 camo만 접촉하고 이미지가 기관망에서도 보인다. -->
  <img src="https://cdn.jsdelivr.net/gh/Lex6won/vibecode-checker@main/docs/assets/report-summary-2026-08-13.png" alt="vibecode-checker 보고서 — 요약층(공무원): 배포 미승인 결론 박스·해소 방안·판정 기준 표·핵심 숫자·조치 가이드 3단계" width="620"/>
  <br/><sub><b>① 요약층 (공무원용)</b> — 결론 박스(해소 방안·판정 기준 표 포함, 코드+패키지 함께 판정) → 핵심 숫자 → 조치 가이드 3단계</sub>
</p>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/Lex6won/vibecode-checker@main/docs/assets/report-detail-2026-08-13.png" alt="vibecode-checker 보고서 — 상세층(보안팀): 보안 분야 개요 표와 발견 카드(위치·마스킹된 증거·위험 이유·안전한 수정 방향·출처)" width="620"/>
  <br/><sub><b>② 상세층 (보안팀용)</b> — 보안 분야 개요 → 발견 카드: 위치 · 증거(민감값 마스킹) · 왜 위험한가 · 안전한 수정 방향 · 출처</sub>
</p>

보고서는 읽는 사람에 따라 두 층으로 나뉩니다.

- **① 요약층 — 비전문 공무원용 (항상 펼침)**: 대상·검사일시 → **결론 박스**(승인 가능 = 초록 / 미승인 = 빨강) → 핵심 숫자 → 조치 가이드 3단계 → 검토 범위·한계.
- **② 상세층 — 보안담당자용 (기본 접힘)**: 발견을 보안 분야별(개인정보·비밀값·주입·웹·암호화·설정 오류·AI 위험)로 묶어, 항목마다 *위치 · 왜 위험한지 · 대응 방법 · 근거(출처)* 를 제시합니다. 패키지 취약점, 외부 데이터 전송 목록, AI 도구에 붙여넣을 수정 프롬프트(복사 버튼)도 포함됩니다.

상세층은 기본 접혀 있고 **인쇄(→PDF) 시 자동으로 펼쳐집니다.** 그대로 공문 '붙임'으로 제출하면 보안팀이 이 문서로 보안성 검토를 진행할 수 있습니다.

<details>
<summary><b>보고서 내용 텍스트 예시 (펼쳐 보기)</b></summary>

```text
── 요약층 (공무원) ─────────────────────────────
| 대상 | C:\…\민원처리앱 |  판정 기준 | 엔진 0.3.0 · 룰셋 2026.08.9 |

## 결론
> ### 배포 미승인 (차단)              ← 빨강 박스(승인이면 초록)
> 배포 판정 · 배포 불가 — CVSS CRITICAL 취약점 · 레지스트리에 없는 이름(가짜
> 이름 의심)에 해당하는 패키지가 있습니다(pyyaml 5.3.1, reqeusts 1.0.0).
> 소스만 고치면 차단이 풀리지 않습니다 — 소스 9건과 패키지를 함께 해소하세요.
>
> 해소 방안                            ← 무엇을 하면 차단이 풀리는지 명시
> - pyyaml 5.3.1 (CVSS CRITICAL) → 5.4 이상으로 올린 뒤 다시 검사하세요
> - reqeusts 1.0.0 (레지스트리에 없는 이름) → 대체 패키지를 검토하세요
> - ⚠ 비밀값 노출 3건 — 코드에서 지우는 것만으로 끝나지 않습니다.
>   해당 키·비밀번호를 반드시 재발급(폐기)하세요.
>
> 이 판정의 기준                       ← 차단/조건부 승인/승인 기준표 동봉

## 요약
- 발견된 위험 16건 · 필수 조치 9건 · 최고 심각도: 치명
- 취약 패키지 3종 · 미존재(가짜 이름 의심) 1종
- 판정 근거: 확인됨 1건 · 유력함 2건 · 패턴 일치만 13건
                                       ← 얼마나 확신하는 판정인지 구분

## 조치 가이드 — 3단계만 따라 하세요
  1) 고치기 → AI 도구에 "방금 보안검사에서 나온 위험들을 안전하게 고쳐줘"
  2) 확인하기  3) 다시 검사

── 상세층 (보안팀, 분야별·클릭해 펼침) ──────────
## 상세 검토 결과
### 비밀값·인증정보 노출 — 3건 (치명 3) · 파일 2개
  [치명·필수 조치] API 키 또는 비밀번호로 보이는 값이 코드에 포함되어 있습니다
    위치         : app.py 12행 · db.py 4행
    증거(마스킹) : OPENAI_API_KEY = "sk-proj-[마스킹]TEST"
    왜 위험한가  : 키가 저장소나 LLM 프롬프트에 노출되면 행정시스템·클라우드·
                   외부 API가 탈취될 수 있습니다
    안전한 수정  : 키는 환경변수, 기관 secret manager로 옮기세요
    출처         : NIST SSDF, OWASP ASVS V6

## 의존성(패키지) 취약점 검사
### 컴포넌트 (고유 4종)         ← 같은 패키지가 여러 곳에 있어도 한 줄로
| 패키지   | 버전   | 라이선스 | 판정                             | 출처             |
| reqeusts | 1.0.0  | —        | ❌ 저장소에 없음(가짜 이름 의심)  | requirements.txt |
| flask    | 0.12.2 | BSD-3    | ⚠ 개별 취약점 8건                | requirements.txt |
| pyyaml   | 5.3.1  | MIT      | ⚠ 개별 취약점 2건 · 최고 CRITICAL | requirements.txt |
| requests | 2.19.1 | Apache-2 | ⚠ 개별 취약점 10건               | requirements.txt |
```

> `reqeusts` 는 AI가 지어냈을 가능성이 있는 오타 이름(슬롭스쿼팅 의심)이라
> 업그레이드가 아니라 **제거·대체** 대상입니다. 취약점마다 어떤 문제인지와
> 해결 버전, 원문 링크(osv.dev)가 보고서에 함께 실립니다.
</details>

---

## 목차

- [설치](#설치)
- [사용 방법](#사용-방법)
- [결과 읽는 법](#결과-읽는-법)
- [무엇을 탐지하나](#무엇을-탐지하나)
- [성능과 한계](#성능과-한계)
- [표시된 항목이 실제로는 문제없다면 (오탐)](#표시된-항목이-실제로는-문제없다면-오탐)
- [망분리(폐쇄망) 환경에서 쓰기](#망분리폐쇄망-환경에서-쓰기)
- [CI·자동화 — 게이트 · SBOM · 예외 관리](#ci자동화--게이트--sbom--예외-관리)
- [기여하기](#기여하기)
- [연락 · 문의](#연락--문의)
- [면책 · 라이선스](#면책--라이선스)

**바로 쓸 수 있는 문서**: [30초 시작 가이드](docs/quickstart_ko.md)(처음 쓰는 분) · [Windows 한글 설정](docs/windows_utf8.md)(콘솔 한글 깨짐 1회 설정). 기관 내 교육·보안성 검토용 자료(공무원용 안내, 전문가용 기술 설명서, 운영 계획)는 도입 기관에 직접 제공합니다 — [Discussions](https://github.com/Lex6won/vibecode-checker/discussions)로 문의해 주세요.

---

## 설치

### 전제 조건

- **Python 3.11 이상** (`python --version` 으로 확인)
- 운영체제 무관 (Windows·macOS·Linux). Windows 콘솔 한글 깨짐은 [한 번만 설정](docs/windows_utf8.md)

### 1단계 — 패키지 설치

설치 하나로 CLI 명령(`gvskb`)과 MCP 서버(`gvskb-server`)가 함께 설치됩니다.

> **PyPI에는 배포하지 않습니다**(공공기관·망분리 환경의 공급망 보안 고려). GitHub 소스에서 설치합니다.

```bash
# 한 줄 설치 (git 이 설치된 PC)
pip install git+https://github.com/Lex6won/vibecode-checker.git

# git 이 없는 PC — zip 주소를 그대로 넣으면 됩니다 (기관 표준 PC에 git 이 없는 경우)
pip install https://github.com/Lex6won/vibecode-checker/archive/refs/heads/main.zip

# 소스를 받아 설치 (수정·기여하려면 -e 권장)
git clone https://github.com/Lex6won/vibecode-checker.git
cd vibecode-checker && pip install -e .
```

> 망분리(인터넷 없는) PC라면, 외부망에서 위 소스를 받아(또는 `pip download`로 의존성까지) 옮긴 뒤 오프라인 설치하세요.

> **AI 코딩 도구에 맡겨도 됩니다.** Claude Code·Cursor처럼 터미널을 쓸 수 있는 도구에는 *"https://github.com/Lex6won/vibecode-checker 설치하고 이 폴더 보안검사해줘"* 라고 요청하면 설치·확인·검사까지 진행합니다. Claude Desktop처럼 터미널이 없는 도구는 설치 방법만 안내하므로, 위 명령을 직접 실행하세요.

### 2단계 — 설치 확인

```bash
gvskb doctor      # 룰 수·인코딩·MCP·위협 정보 캐시 상태를 점검합니다
```

### 3단계 — 첫 검사

```bash
gvskb scan ./내프로젝트
```

여기까지 하면 터미널에서 쓸 수 있습니다. AI 코딩 도구에서 자연어로 쓰려면 아래 MCP 연결을 추가하세요.

### AI 코딩 도구에 연결 (선택 — MCP)

MCP 설정 파일에 서버를 등록합니다. **Claude Desktop·Cursor·Claude Code 공통 형식**입니다(최상위 키 `mcpServers`). VS Code는 형식이 달라 아래에 따로 안내합니다.

```json
{
  "mcpServers": {
    "vibecode-checker": {
      "command": "gvskb-server",
      "args": [],
      "env": { "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```

| 도구 | 설정 파일 위치 |
|---|---|
| **Claude Desktop** | Windows `%APPDATA%\Claude\claude_desktop_config.json` · macOS `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Cursor** | 프로젝트 `.cursor/mcp.json` 또는 전역 `~/.cursor/mcp.json` (설정 → MCP) — 키 `mcpServers` |
| **VS Code** (Copilot Agent) | 워크스페이스 `.vscode/mcp.json` — 키가 `servers`(≠`mcpServers`)이고 `"type": "stdio"` 필요. 아래 스니펫 참고 |
| **Claude Code (CLI)** | 프로젝트 루트 `.mcp.json` (키 `mcpServers`, 이 저장소의 [`.mcp.json`](.mcp.json) 참고) · 또는 `claude mcp add` 명령 |

**VS Code 전용** — `.vscode/mcp.json` 은 키가 `servers` 이고 `type` 이 필요합니다:

```json
{
  "servers": {
    "vibecode-checker": {
      "type": "stdio",
      "command": "gvskb-server",
      "args": [],
      "env": { "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```

저장 후 도구를 재시작하면 연결됩니다. 확인 방법: AI에게 *"server_status 확인해줘"* — `runtime_freshness.process_stale` 이 `false` 이고 `rules_loaded_ok` 가 `true` 면 정상입니다.

> **자주 겪는 문제 3가지**
>
> 1. `gvskb-server` 를 찾지 못함 → PATH에 없는 경우입니다. 실행 파일의 전체 경로로 바꾸세요. `gvskb doctor` 가 실행되는 환경이면 `gvskb-server` 도 같은 위치에 있습니다.
> 2. Windows에서 `command` 를 `python` 으로 지정했는데 서버가 뜨지 않음 → `python` 이 Microsoft Store 스텁으로 연결된 경우입니다. `gvskb-server` 를 그대로 쓰거나, 인터프리터 전체 경로(예: `C:\Python313\python.exe`)를 지정하세요.
> 3. **룰을 갱신했는데 판정이 그대로** → gvskb는 룰을 프로세스 시작 시점에 한 번만 읽습니다. 저장소를 갱신하거나 재설치한 뒤에는 MCP 서버를 재시작하세요. `server_status` 의 `runtime_freshness.process_stale` 이 `true` 면 낡은 상태이며 조치 방법이 함께 표시됩니다.

> **신뢰하는 환경에서만 연결하세요** — MCP `scan_path` 도구는 지정한 경로의 로컬 파일을 읽습니다(검사 목적). 연결한 AI 클라이언트가 임의 경로 스캔을 요청할 수 있으므로 민감 디렉터리는 가리키지 마세요. 자세한 내용은 [SECURITY.md](SECURITY.md) 참고.

---

## 사용 방법

### A. 터미널(CLI)에서

```bash
gvskb doctor                                  # 1) 환경 점검(룰 수·인코딩·MCP·위협 정보 캐시)
gvskb scan ./my-project                        # 2) 폴더 검사 → .check-reports/ 에 자동 저장
gvskb scan ./my-project -o 보안점검.md          # 3) 지정한 이름으로 저장 → .md + .html 함께 생성
gvskb scan ./my-project --check-deps -o 보안점검.md   # 4) 패키지 취약점 검사까지 보고서에 병합

# 5) GitHub 저장소는 받은 뒤 그 폴더를 검사 (설치·빌드·실행 없이 읽기만 합니다)
git clone --depth 1 https://github.com/owner/repo /tmp/repo && gvskb scan /tmp/repo -o 보안점검.md

# 6) 설치하려는 패키지 하나만 미리 확인
gvskb check-package requests --ecosystem pypi    # 알려진 취약점 조회
gvskb check-package reqeusts --ecosystem pypi    # 오타 패키지(typosquat) 경고
```

- `-o 파일이름` : 결과를 그 이름으로 저장합니다. 마크다운/HTML 형식이면 텍스트 `.md` 와 인쇄용 `.html` 이 함께 만들어집니다.
- `--check-deps` : requirements.txt·package.json의 패키지를 취약점 DB와 대조해 코드+패키지 위험을 보고서 한 장에 담습니다. 외부로 전송되는 것은 패키지명·버전뿐입니다.

### B. AI 코딩 도구에서 — 자연어로

MCP를 연결했다면 명령어를 외울 필요 없이 요청하면 됩니다:

- *"이 폴더 **보안 검사** 해줘 → ./my-project"*
- *"이 코드가 **안전한지 확인**해줘"* (코드를 붙여넣고)
- *"**보안 점검 리포트** 써줘"* / *"**HTML 보고서로** 만들어줘"*
- *"이 깃허브 저장소 **보안 점검**해줘 → https://github.com/owner/repo"*
- *"고쳤어, **다시 검사**해줘"*

인식 단어: **보안 · 점검 · 체크 · 검토 · 검사 · 스캔 · "안전한지"**. 잘 안 불러오면 *"vibecode-checker로 점검해줘"* 라고 덧붙이세요.

> **로컬 폴더·붙여넣은 코드**는 모든 도구에서 동작합니다. **GitHub URL**은 셸을 쓸 수 있는 도구(Claude Code·Cursor)에서 동작합니다 — AI가 먼저 `git clone` 한 뒤 검사합니다. Claude Desktop처럼 셸이 없는 도구에서는 폴더를 가리키거나 코드를 붙여넣으세요.

### 보고서 저장 위치

**`-o` 를 안 붙여도 저장됩니다.** 기본 위치는 검사한 폴더 안 `.check-reports/` 입니다.

```
./my-project/.check-reports/2026-08-09_1745_보안점검.md
                                              .html   ← 인쇄하면 PDF 결재문서
```

한곳에 모으고 싶다면 폴더를 한 번 지정해 두세요. 이후 모든 검사 결과가 거기 저장됩니다.

```bash
gvskb config --report-dir "D:\보안점검"        # 한 번 지정하면 계속 적용
gvskb config                                    # 현재 저장 위치 확인
gvskb config --clear-report-dir                 # 기본값으로 되돌리기
gvskb scan ./my-project --report-dir "D:\임시"  # 이번 한 번만 다른 곳에
```

공용 폴더에 모으면 파일명에 사업 이름이 붙습니다(`2026-08-09_1745_my-project_보안점검.md`) — 여러 부서가 한 폴더를 써도 구분됩니다. 저장 위치는 보고서 머리말에도 기록되므로(`이 보고서 위치` 행) 파일만 전달받은 사람도 원본 위치를 알 수 있습니다.

> 저장 위치 우선순위: `-o` → `--report-dir` → 환경변수 `GVSKB_REPORT_DIR` → `gvskb config` 설정 → 기본값. 화면으로만 보려면 `--stdout`.

---

## 결과 읽는 법

보고서 맨 위 **결론 박스**가 판정입니다. 결론은 코드와 패키지를 함께 보고 정해집니다.

| 결론 박스 | 뜻 | 언제 나오나 | 다음 행동 |
|---|---|---|---|
| **배포 승인 가능** (초록) | 심각한 위험 미발견 | 코드·패키지 둘 다 이상 없음 | '검토 범위·한계' 확인 후 진행 |
| **배포 미승인 (차단)** (빨강) | 그대로 배포하면 위험 | 차단 발견 또는 차단 기준에 걸린 패키지 | 먼저 고치거나 보안담당자 승인 |
| **배포 보류 (확인 필요)** | 확인할 항목 있음 | 경고 발견 또는 취약·판정 불가 패키지 | 확인·수정 후 배포 |

각 발견의 심각도는 `치명 → 높음 → 보통`, 조치 등급은 `필수 조치(block) → 경고(warn) → 허용(allow)` 으로 표시됩니다. 결론 박스에는 **판정 기준표**(무엇이 차단이고 무엇이 조건부 승인인지)와 **해소 방안**(무엇을 하면 차단이 풀리는지)이 함께 실립니다. 요약에는 판정 근거의 확신 수준(확인됨 · 유력함 · 패턴 일치만)이 구분되어, 값의 출처를 직접 확인해야 하는 항목이 무엇인지 알 수 있습니다.

**"판정 불가"는 "안전"이 아닙니다.** 이 도구는 확인하지 못한 것을 통과로 바꾸지 않습니다:

- 코드에 문제가 없어도, 사용 중인 패키지에 알려진 취약점이 있거나 패키지를 확인하지 못했다면(오프라인 등) 승인 판정을 내리지 않습니다.
- **검사된 파일이 0개**면 "안전"이 아니라 경로·확장자를 확인하라는 안내가 나오고 결론은 '판정 불가'가 됩니다.
- 반입한 위협 정보 캐시가 오래되면(기본 30일 초과) '이상 없음'을 '판정 보류'로 낮춥니다.

---

## 무엇을 탐지하나

### 흔한 실수 유형

| 유형 | 예시 |
|---|---|
| 코드에 박힌 비밀값 | `DB_PASSWORD = "P@ssw0rd"`, API 키, JWT 토큰 |
| 개인정보 노출 | 주민등록번호·전화번호 평문 저장, 로그 출력 |
| SQL 삽입 | `"SELECT … WHERE name='" + name + "'"` |
| 위험한 코드 실행 | `eval()`, `exec()`, `os.system(사용자입력)` |
| 웹 취약점 | XSS, 경로 조작, 응답에 그대로 실리는 비밀번호·로그인 링크, Flask `debug=True` 배포 |
| 취약·가짜 패키지 | 알려진 CVE, 오타를 노린 typosquat(`reqeusts`) |
| 폴더에 넣어둔 외부 라이브러리 | `static/xlsx.full.min.js` 처럼 직접 받아둔 파일 — 라이브러리·버전을 식별해 알려진 취약점과 대조 (`package.json` 이 없어도 검사) |
| AI 특화 위험 | 프롬프트 인젝션(신뢰할 수 없는 입력이 LLM 프롬프트에 결합), 프롬프트에 개인정보 전송, LLM 출력 무검증 실행 |
| 외부 데이터 전송 | 외부 AI API·플러그인이 어디로(국외 포함) 무슨 데이터를 보내는지 목록으로 정리(검토용 — 사용 금지가 아님) |
| 폐쇄망 배포 영향 | CDN 스크립트·웹폰트 등 외부 리소스 로딩과 외부 API 호출 표시 — 폐쇄망에서 화면·기능이 깨질 지점을 배포 전에 확인 |

### 룰과 출처

탐지 룰은 한국 정부·국제 보안 가이드를 근거로 작성되며, 발견마다 출처를 함께 제시합니다.

| 출처 | 반영 |
|---|---|
| **KISA 시큐어코딩 가이드 (2023 개정)** | Python 45항목 · JavaScript 34항목 |
| **행안부 SW 개발보안 가이드** | 49개 보안약점 |
| **국정원 AI 보안 가이드북 (2025)** | AI 위협·대책 45룰 |
| **OWASP** | LLM Top 10 · Agentic Top 10 · AI Testing Guide |
| **실시간 취약점 피드** | OSV.dev · CISA KEV · NVD · FIRST EPSS |

룰은 총 **328개**입니다 — 탐지 룰 101개(검사에서 발견을 만드는 룰) + 참조 룰 227개(발견의 근거·출처로 인용되는 지식 룰). 모든 룰은 Markdown 파일로 정의되어 누구나 읽고 검토할 수 있습니다.

### 위협 정보(인텔)는 매일 자동 갱신됩니다

GitHub Actions가 **매일 03:00(KST)** 5개 소스(OSV 악성 패키지·OSV 취약점 DB·CISA KEV·NVD·EPSS)를 **PyPI·npm 두 생태계**에 대해 수집해 검증 가능한 번들을 [`intel-latest` 릴리스](https://github.com/Lex6won/vibecode-checker/releases/tag/intel-latest)에 게시합니다. NVD·EPSS는 매일 새 수집분을 기존 캐시에 **누적**해 시간이 지날수록 커버리지가 넓어집니다.

- **인터넷 PC**: 별도 설정 없이 자동입니다. 서버 기동·검사 시점에 캐시 신선도를 확인하고 낡았으면 하루 1회 자동으로 받아옵니다(`GVSKB_AUTO_UPDATE=off` 로 끌 수 있음). 수동 갱신은 `gvskb update-intel --all`.
- **망분리 PC**: [아래 절차](#망분리폐쇄망-환경에서-쓰기)대로 번들을 반입합니다. 관리자가 공유 폴더(`GVSKB_INTEL_DIR`)에 번들을 놓아두면 각 PC가 자동 반영합니다.
- 자동으로 받은 위협 정보는 패키지 검사(악성·취약점·실제 악용 여부 대조)에 쓰입니다. 검사 판정 기준(룰)이 자동으로 바뀌지는 않습니다 — 판정에 쓰이는 룰은 사람이 검토·승인한 것만입니다.

---

## 성능과 한계

실무형 프로젝트 5종(민원 웹앱·API 서버·정적 페이지·LLM 챗봇·데이터 처리)에 취약점 42개를 심은 벤치마크에서 **42건 전부 탐지했고, 안전한 코드를 잘못 지적한 오탐은 0건**이었습니다. 벤치마크와 결과는 저장소(`eval_corpus/`)에 포함되어 있어 누구나 재현할 수 있습니다.

**다만 어떤 자동 점검 도구도 모든 위험을 잡지 못합니다.** 이 도구의 한계는 다음과 같습니다.

| 한계 | 내용 |
|---|---|
| 일부러 숨긴 코드 | 난독화·우회 변형 11개 중 **4개만 탐지** — 악의적으로 숨긴 코드는 놓칠 수 있습니다 |
| 탐지하지 못하는 유형 | 보안 지침이 요구하는 항목 중 현재 탐지하지 못하는 **15건을 목록으로 공개**하고 있습니다 |
| 정적 분석의 한계 | 설계·권한·업무 로직상 취약점, 실행 중에만 드러나는 취약점은 잡지 못합니다 |

그래서 두 가지를 기억해 주세요:

- **발견 0건이 "안전"을 보장하지 않습니다.** 보고서의 '검토 범위 및 한계'에도 같은 내용이 명시됩니다.
- 이 도구는 명백한 실수를 1차로 걸러내는 도구이며, **보안담당자의 공식 보안성 검토를 대체하지 않습니다.**

---

## 표시된 항목이 실제로는 문제없다면 (오탐)

이 도구는 위험을 놓치는 것보다 한 번 더 알리는 쪽을 택했습니다. 따라서 맥락상 안전한 코드가 표시될 수 있습니다. 이렇게 처리하세요:

1. **먼저 확인** — 보고서의 발견 항목에는 증거 코드와 파일·줄 번호가 함께 실립니다. 특히 판정 근거가 **"패턴 일치만"** 으로 표시된 항목은 값의 출처를 사람이 확인해야 합니다.
2. **오탐이 맞다면 '승인된 예외'로 등록** — 검사 폴더에 [`.gvskb-exceptions.yaml`](#오탐수용-위험을-승인된-예외로-관리) 을 만들어 등록하면, 그 항목은 게이트(배포 판정)에서 제외되면서 승인자·사유·만료일이 보고서에 기록됩니다. 발견을 숨기는 것이 아니라 결정을 기록하는 방식입니다.
3. **반복되는 오탐은 제보** — [Issues](https://github.com/Lex6won/vibecode-checker/issues)에 알려주시면 룰을 정밀화합니다.

빌드 산출물(`dist/` 등 원본 소스가 아닌 파일)은 오탐만 만들기 때문에 자동으로 제외되며, 무엇이 왜 제외됐는지 보고서에 표기됩니다.

---

## 망분리(폐쇄망) 환경에서 쓰기

외부 통신에 대해 먼저 알아두실 것:

1. **소스 코드는 외부로 전송되지 않습니다.** 모든 정적 분석은 로컬에서 수행됩니다.
2. 외부 통신은 패키지 취약점 조회에 한정되며(OSV·CISA·NVD·EPSS 공개 API), 보내는 것은 패키지명·버전·CVE ID 같은 공개 식별자뿐입니다.
3. `GVSKB_MODE=offline` 설정 시 외부 통신을 완전히 차단하고, 반입한 캐시와 로컬 룰만으로 동작합니다.

### 위협 정보 반입 절차

**1단계 (외부망 PC) — 번들 확보.** 매일 자동 생성되는 공식 번들을 받는 방법(A, 권장)과 직접 수집하는 방법(B)이 있습니다.

```bash
# 방법 A — 공식 번들 내려받기 (매일 03:00 KST 갱신)
curl -LO https://github.com/Lex6won/vibecode-checker/releases/download/intel-latest/gvskb-intel-bundle.zip
curl -LO https://github.com/Lex6won/vibecode-checker/releases/download/intel-latest/gvskb-intel-bundle.zip.sha256
sha256sum -c gvskb-intel-bundle.zip.sha256      # OK 확인 후 반입 매체로 이동

# 방법 B — 직접 수집해 번들 만들기
gvskb update-intel --all                            # npm 패키지도 검사하려면: GVSKB_OSV_INCLUDE_NPM=1
gvskb intel-bundle export gvskb-intel-bundle.zip    # 캐시 + sha256 목록을 zip 하나로
```

**2단계 (망분리 PC) — 반입·검증·사용.**

```bash
gvskb intel-bundle import gvskb-intel-bundle.zip   # 파일별 sha256 전수 검증 — 불일치 시 전체 거부
$env:GVSKB_MODE = "offline"                        # PowerShell (bash: export GVSKB_MODE=offline)
gvskb doctor --offline                             # 캐시 존재·신선도까지 점검
gvskb scan ./my-project --check-deps
```

캐시 위치는 `%USERPROFILE%\.gvskb\cache` 입니다(환경변수 `GVSKB_CACHE_DIR` 로 변경 가능).

**반입 이후 자동화** — 관리자가 공유 폴더에 새 번들을 놓아두고 각 PC에 `GVSKB_INTEL_DIR=\\공유폴더\경로` 를 설정하면, 검사 시점에 자기 캐시보다 새 번들을 발견했을 때 자동 반입합니다(사용자 조작 불필요, 하루 1회 확인). 수동 동기화는 `gvskb intel-sync`, 상태 확인은 `gvskb intel-sync --status`.

### 오프라인 판정의 신뢰 장치

- 반입한 캐시는 읽을 때마다 **sha256 무결성을 재검증**합니다. 변조·손상된 캐시는 판정에 쓰지 않고 무시하며, 다시 받으라고 안내합니다.
- 캐시가 기본 **30일**(`GVSKB_INTEL_MAX_AGE_DAYS` 로 조정)을 넘으면 '이상 없음' 판정을 '판정 보류'로 낮춥니다 — 오래된 데이터가 최신처럼 보이지 않게 합니다.
- 보고서에 **어느 날짜 캐시 기준의 판정인지**(피드별 수집 시각)가 자동 표기됩니다. KEV 등재 취약점에는 EPSS 악용확률·CVSS 점수가 함께 실려 보안팀이 우선순위를 정할 수 있습니다.
- 반입 번들에는 **알려진 취약점 DB**(OSV 전체, 영향 버전 범위 포함)가 담겨, 망분리에서도 취약한 패키지 버전이 온라인 검사와 같은 기준으로 탐지되고 **올려야 할 버전까지 권고**됩니다(PyPI·npm).
- 오프라인에서 확인하지 못한 것(패키지 실재 여부·발행일 등)은 '판정 불가'로 명시합니다 — '안전'으로 바꿔 말하지 않습니다.

---

## CI·자동화 — 게이트 · SBOM · 예외 관리

### 종료 코드로 커밋·배포 차단

`gvskb scan` 은 결과에 따라 종료 코드(exit code)를 반환하므로 CI에서 그대로 게이트로 쓸 수 있습니다.

| 종료 코드 | 의미 |
|---|---|
| `0` | 통과 |
| `1` | 경고(warn) 발견 · 판정 불가(오프라인 캐시 없음 등 — '안전' 아님) |
| `2` | 차단(block) 발견 |
| `64` | 사용법 오류(잘못된 인자) |
| `66` | 경로를 찾을 수 없음 |

```bash
gvskb scan ./src --fail-on dependency   # 의존성 차단만 실패 — 처음 도입할 때 권장
gvskb scan ./src --fail-on block        # block만 실패(2), warn은 통과 — CI 게이트 권장
gvskb scan ./src --fail-on warn         # warn 이상 실패 (기본값)
gvskb scan ./src --fail-on never        # 항상 0 (보고서만 생성)
```

**처음 도입한다면 `--fail-on dependency` 부터 시작하세요.** 패키지 판정("이 버전에 이 취약점이 있다")은 사실 조회라 오탐이 거의 없고, 소스 코드 판정은 맥락에 따라 오탐이 있을 수 있습니다. 게이트에 대한 신뢰가 쌓인 뒤 `block` 으로 올리는 것을 권장합니다.

### SBOM — 만들기와 읽기

```bash
gvskb scan . --check-deps --sbom sbom.json   # 검사하면서 CycloneDX 1.6 SBOM 생성
gvskb sbom vendor-sbom.json                  # 건네받은 SBOM 검사 (CycloneDX·SPDX JSON)
```

컴포넌트마다 버전·라이선스·공급자 정보를 담고, 어떤 패키지가 어떤 패키지를 쓰는지(의존성 관계)도 함께 표시합니다 — 락파일(package-lock.json·poetry.lock 등)을 검사하면 전이 의존성까지, requirements.txt·package.json 같은 매니페스트만 있으면 직접 의존성까지 나옵니다. 판정하지 못한 컴포넌트도 SBOM에서 빼지 않고 사유를 남깁니다 — 빠지면 "그 패키지는 안전하다"로 읽히기 때문입니다. 엔진 버전과 룰셋 버전도 문서에 기록됩니다.

### 판정 재현 — 룰셋 고정

룰이 바뀌면 어제 통과한 코드가 오늘 차단될 수 있습니다. 코드 때문인지 룰 때문인지 구분하려면 룰셋을 고정하세요.

```bash
gvskb ruleset                            # 현재 룰셋 버전·지문 확인
export GVSKB_EXPECT_RULESET=2026.08.9    # 기대하는 룰셋 선언 — 다르면 보고서에 경고
```

보고서 머리말의 「판정 기준」 줄에 `엔진 x.y.z · 룰셋 YYYY.MM.N` 이 항상 기록됩니다 — 판정을 재현하려면 둘 다 같아야 합니다.

### 오탐·수용 위험을 '승인된 예외'로 관리

검사 대상 폴더에 `.gvskb-exceptions.yaml` 을 두면, 오탐이거나 기관이 위험을 수용하기로 결정한 발견을 **기록을 남기면서** 게이트만 통과시킵니다.

```yaml
exceptions:
  - rule_id: GOV-FLASK-DEBUG-001
    file: app.py
    line: 47                 # 선택 — 지정하면 그 줄만
    reason: 내부 개발서버 전용 — 외부 노출 없음
    approved_by: 김보안(정보보안담당관)
    expires: 2026-12-31      # 만료되면 자동으로 다시 차단
```

`reason`·`approved_by`·`expires` 가 **모두 있어야** 유효합니다. 억제된 발견은 보고서의 '승인된 예외 내역'과 감사로그에 남습니다.

### 감사로그 · SARIF

- **감사로그**: `GVSKB_AUDIT_DIR` 환경변수를 설정하면 스캔·차단·예외 승인·인텔 갱신 이력이 월별 JSONL로 기록됩니다. 원본 코드·개인정보는 저장하지 않고 해시와 마스킹된 증거만 남깁니다(기관 감사 증빙용, 기본 비활성).
- **SARIF**: `gvskb scan ./src --format sarif -o result.sarif` — GitHub code scanning 업로드나 기관 보안도구 수집에 쓸 수 있습니다(SARIF 2.1.0).

<details>
<summary><b>GitHub Actions 예시</b></summary>

```yaml
name: security scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install git+https://github.com/Lex6won/vibecode-checker.git
      - run: gvskb scan . --format markdown -o report.md --fail-on block
      - if: always()
        uses: actions/upload-artifact@v4
        with: { name: security-report, path: report.md }
```
</details>

<details>
<summary><b>pre-commit 훅 예시</b></summary>

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: gvskb-scan
        name: vibecode-checker 보안 스캔
        entry: gvskb scan .
        args: ["--format", "json", "--fail-on", "block"]
        language: system
        pass_filenames: false   # scan은 경로 1개를 받음 — 파일 목록 전달 금지
```
</details>

---

## 기여하기

룰은 코드가 아니라 **Markdown 파일 한 장**입니다. `rules/` 아래에 frontmatter로 탐지 패턴·설명·예제를 적으면 됩니다.

```bash
gvskb validate-rules     # 새 룰 형식·정규식 검증
gvskb evaluate           # 룰 예제 기반 정밀도 측정
pytest -q                # 전체 테스트
```

새 룰에는 `examples.positive`/`negative` 를 넣어주세요 — 회귀 테스트로 자동 보증됩니다. 자세한 방법은 [CONTRIBUTING.md](CONTRIBUTING.md) 참고.

- **버그·오탐 제보** → [Issues](https://github.com/Lex6won/vibecode-checker/issues)
- **새 룰·기능 제안** → [Discussions](https://github.com/Lex6won/vibecode-checker/discussions)
- **직접 고치기** → Pull Request (작은 PR 환영)

---

## 연락 · 문의

- **버그·기능 요청**: [GitHub Issues](https://github.com/Lex6won/vibecode-checker/issues)
- **사용 질문·아이디어**: [GitHub Discussions](https://github.com/Lex6won/vibecode-checker/discussions)
- **보안 취약점 비공개 제보**: [SECURITY.md](SECURITY.md)의 절차를 따라주세요

---

## 면책 · 라이선스

> 이 도구의 자동 점검은 **공식 보안적합성 검토를 대체하지 않습니다.** 비전공자가 명백한 실수를 1차로 걸러내고 학습하도록 돕는 보조 도구입니다. `치명`·`높음` 항목은 보안 담당자 검토를 권장하며, 기관별 보안 정책·개인정보 처리 기준을 함께 확인하세요.

정부·공공기관 지침(KISA·행안부·국정원), OWASP·NIST·CISA 등 외부 자료는 원문을 복제하지 않고 요약·인용·구조화하여 사용하며 각 출처의 이용 조건을 존중합니다.

### 라이선스

**PolyForm Noncommercial License 1.0.0 + 수급사업자 사용 추가 허가** — [LICENSE](LICENSE) 참고.

- **공공기관·교육기관·연구기관·공공안전 기관의 사용은 재원과 무관하게 허용됩니다.** 라이선스가 "government institution" 사용을 명시적으로 비상업 목적으로 규정합니다. 지방자치단체·중앙부처·공공기관이 자체 점검에 쓰는 것은 제약 없이 가능합니다.
- **공공사업을 수행하는 용역사·수급사업자도 그 계약 이행 목적에 한해 사용할 수 있습니다.** PolyForm 본문만으로는 용역사의 사용이 덮이지 않아, 추가 허가를 부기했습니다. 수정본을 발주기관에 납품하는 것도 포함됩니다.
- 개인의 연구·학습·취미 목적 사용도 허용됩니다.
- **상업적 목적의 사용은 허용되지 않습니다.** 예: 유료 보안 점검 서비스에 포함해 판매하거나, 자기 명의의 솔루션 제품에 번들해 공급하는 경우. 용역사의 계약 종료 후 사용도 허용되지 않습니다. 별도 상용 라이선스가 필요하면 문의해 주세요.

> 전달 시 [LICENSE](LICENSE) **파일 전체**를 함께 전달해야 합니다. PolyForm 원문 URL만 전달하면 수급사업자 추가 허가가 따라가지 않습니다.

> 2026-08-01 이전에 **MIT** 로 배포된 버전에는 이 변경이 소급되지 않습니다. 해당 버전을 MIT 조건으로 받은 이용자의 권리는 그대로 유지됩니다.

---

<div align="center">
<sub>공공기관 바이브 코딩의 첫 번째 보안 게이트 · Made for public-sector developers in Korea</sub>
</div>
