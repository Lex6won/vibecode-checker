# 🛡️ 30초 시작 가이드 — AI가 짜준 코드, 보안 점검하기

보안 용어를 몰라도 됩니다. **폴더를 가리키고 "보안 점검해줘"** 한 마디면 됩니다.

---

## 방법 1. 명령어로 바로 (가장 간단)

```bash
# 설치 — git 이 있는 PC
pip install git+https://github.com/Lex6won/vibecode-checker.git
# 설치 — git 이 없는 PC (zip 주소를 그대로)
pip install https://github.com/Lex6won/vibecode-checker/archive/refs/heads/main.zip

# 내 프로젝트 폴더를 점검 → 화면에 한국어 보고서
gvskb scan ./my-project

# 보고서를 파일로 저장 (.md 와 보기 좋은 .html 이 함께 생성됩니다)
gvskb scan ./my-project -o 보안점검.md
```

> 💬 **설치도 AI에게 맡길 수 있습니다.** Claude Code·Cursor처럼 터미널을 쓰는 도구에는
> *"https://github.com/Lex6won/vibecode-checker 설치하고 이 폴더 보안검사해줘"* 라고
> 요청하면 설치·확인·검사까지 진행합니다.

`보안점검.md`(텍스트)와 `보안점검.html`(색깔 카드, 인쇄하면 PDF 결재 문서)이
**함께** 만들어집니다. HTML은 인터넷 없이 열리고 이메일로 보낼 수 있습니다.

---

## 방법 1-B. GitHub 레포를 통째로 검사

이 도구는 **로컬에 있는 코드**를 검사합니다. GitHub 저장소는 먼저 내려받은 뒤
그 폴더를 검사하면 됩니다(코드를 외부로 보내지 않고, 받은 코드를 실행하지도
않습니다 — 정적으로 읽기만 합니다).

```bash
# git 으로 받아서 검사
git clone --depth 1 https://github.com/owner/repo /tmp/repo
gvskb scan /tmp/repo -o 보안점검.md
```

```bash
# git 없이 압축본으로 받아서 검사
curl -L https://github.com/owner/repo/archive/refs/heads/main.tar.gz | tar xz
gvskb scan repo-main
```

> 💬 **AI 코딩 도구에 연결했다면** URL만 줘도 됩니다: *"이 깃허브 레포 보안 점검해줘 →
> https://github.com/owner/repo"* — AI가 먼저 `git clone` 한 뒤 검사하고 보고서를 만듭니다.

**CI에서 자동으로**: PR·푸시마다 자동 검사하려면 GitHub Actions 예제
[`examples/github-actions/gvskb-scan.yml`](../examples/github-actions/gvskb-scan.yml)을
쓰세요. `checkout` 으로 레포를 받고 `gvskb scan` 을 돌립니다.

> ⚠️ **망분리(인터넷 없는) 환경에서는** clone/다운로드가 안 됩니다. 외부망 PC에서
> 받은 폴더(또는 zip)를 반입해 로컬 경로로 검사하세요. (`GVSKB_MODE=offline` 에서는
> 원격 URL을 받지 않습니다.)

---

## 방법 2. AI 코딩 도구(Claude Code·Cursor)에 연결해서 대화로

### 1단계 — 한 번만 연결

`claude_desktop_config.json` 등 MCP 설정에 추가합니다:

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

> 저장 후 **AI 도구를 재시작**해야 연결됩니다. VS Code는 설정 형식이 조금 달라
> [리드미의 MCP 연결 절](../README.md#ai-코딩-도구에-연결-선택--mcp)을 참고하세요.

> ⚠️ **신뢰하는 환경에서만 연결하세요.** 점검 도구는 지정한 폴더의 파일을
> 읽습니다. 자세한 내용은 [SECURITY.md](../SECURITY.md) 참고.

### 2단계 — 이렇게 말하면 됩니다 (도구 이름 몰라도 됨)

아래 단어(**보안 · 점검 · 체크 · 검토 · 검사 · "안전한지"**)가 들어가면
점검이 실행되고 한국어 보고서까지 나옵니다.

- 🟢 *"이 폴더 **보안 점검**해줘 → ./my-project"*
- 🟢 *"방금 만든 이 코드 **안전한지 체크**해줘"*
- 🟢 *"이 파일 **검토**하고 위험한 부분을 한국어 보고서로 만들어줘"*
- 🟢 *"이 패키지 설치해도 돼? → requests"*  (패키지 안전성 확인)
- 🟢 *"고쳤어, **다시 검사**해줘"*  (수정 후 재검증)

> 💡 잘 안 불러오면 한마디만 덧붙이세요: *"vibecode-checker로 점검해줘."*

---

## 3단계 — 보고서 읽는 법

보고서 **맨 위 결론 박스**만 보면 배포해도 되는지 알 수 있습니다. 결론은 내 코드와
사용 중인 패키지를 **함께** 보고 정해집니다.

| 결론 박스 | 뜻 | 무엇을 하나요 |
|---|---|---|
| 🟢 **배포 승인 가능** | 심각한 위험 미발견 | '검토 범위·한계' 확인 후 진행 |
| 🔴 **배포 미승인 (차단)** | 그대로 배포하면 위험 | 결론 박스의 '해소 방안'대로 고치거나 보안담당자 승인 |
| 🟡 **배포 보류 (확인 필요)** | 확인할 항목 있음 | 확인·수정 후 배포 |

항목마다 **무엇이 위험한지 · 왜 위험한지 · 안전한 수정 방향 · 근거 출처**가 함께
나옵니다. 심각도는 `치명 → 높음 → 보통`, 조치 등급은 `필수 조치 → 경고 → 허용`입니다.

주의할 세 가지:

- ⚠️ **"검사된 파일 0개"** = *안전하다는 뜻이 아니라* 경로·확장자를 확인하라는 뜻입니다.
- ⚠️ **"판정 불가"** = 안전이 아니라, 오프라인 등으로 판단하지 못했다는 뜻입니다.
- ⚠️ **판정 근거가 "패턴 일치만"** 인 항목은 값의 출처를 사람이 직접 확인해야 합니다.

---

## 망분리(인터넷 없는) 환경

코드 검사(정적 분석)는 인터넷 없이 그대로 동작합니다. 패키지 취약점까지 보려면
외부망에서 위협 정보 번들을 받아 반입합니다.

```bash
# (외부망 PC) 매일 갱신되는 공식 번들 + 해시를 내려받아 확인
curl -LO https://github.com/Lex6won/vibecode-checker/releases/download/intel-latest/gvskb-intel-bundle.zip
curl -LO https://github.com/Lex6won/vibecode-checker/releases/download/intel-latest/gvskb-intel-bundle.zip.sha256
sha256sum -c gvskb-intel-bundle.zip.sha256

# (망분리 PC) 반입 후 검증하며 등록 — 해시가 다르면 전체 거부됩니다
gvskb intel-bundle import gvskb-intel-bundle.zip
gvskb scan ./my-project --check-deps     # 외부 통신 없이 로컬 룰·캐시로만 점검
```

`GVSKB_MODE=offline` 을 설정하면 외부 통신을 완전히 차단합니다. 자세한 절차는
[리드미의 망분리 절](../README.md#망분리폐쇄망-환경에서-쓰기)을 참고하세요.

---

> 이 도구는 **공식 보안적합성 검토를 대체하지 않는 1차 점검 도구**입니다.
> `치명`·`높음` 항목은 보안담당자 검토를 권장합니다.