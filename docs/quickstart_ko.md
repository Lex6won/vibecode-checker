# 🛡️ 30초 시작 가이드 — AI가 짜준 코드, 보안 점검하기

보안 용어를 몰라도 됩니다. **폴더를 가리키고 "보안 점검해줘"** 한 마디면 됩니다.

---

## 방법 1. 명령어로 바로 (가장 간단)

```bash
pip install vibecode-checker

# 내 프로젝트 폴더를 점검 → 화면에 한국어 보고서
gvskb scan ./my-project

# 보고서를 파일로 저장 (.md 와 보기 좋은 .html 이 함께 생성됩니다)
gvskb scan ./my-project -o 보안점검.md
```

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
      "command": "python",
      "args": ["-m", "gvskb.server"],
      "env": { "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```

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
> Claude·Cursor에서는 `/보안점검` 명령으로도 한 번에 실행할 수 있습니다.

---

## 3단계 — 보고서 읽는 법

보고서는 **무엇이 위험한지 · 왜 위험한지 · 어떻게 고치는지(safe_fix) · 근거 출처**를
항목마다 알려줍니다. 색깔만 알면 우선순위를 잡을 수 있습니다:

| 표시 | 뜻 | 무엇을 하나요 |
|---|---|---|
| 🔴 `block` | 그대로 배포하면 위험 | 먼저 고치거나 보안 담당자 검토 |
| 🟡 `warn` | 확인이 필요 | 코드 맥락 보고 판단 |
| 🟢 `allow` | 현재 기준 허용 | 참고만 |

주의할 두 가지:

- ⚠️ **"검사된 파일 0개"** = *안전하다는 뜻이 아니라* 경로·확장자를 확인하라는 뜻입니다.
- ⚠️ **"판정 불가(requires_review)"** = 안전이 아니라, 오프라인 등으로 판단하지 못했다는 뜻입니다.

---

## 망분리(인터넷 없는) 환경

```bash
gvskb update-intel --all      # (외부망 PC) 보안 피드 캐시를 미리 받기
# 캐시 폴더를 망분리 PC로 옮긴 뒤:
gvskb scan ./my-project       # 외부 통신 없이 로컬 룰·캐시로만 점검
```

정적 분석 룰은 외부 통신 없이 동작합니다. `GVSKB_MODE=offline`로 외부 통신을
완전히 차단할 수 있습니다.

---

> 이 도구는 **공식 보안적합성 검토를 대체하지 않는 1차 보안 린터**입니다.
> `critical`·`high` 항목은 보안 담당자 검토를 권장합니다.