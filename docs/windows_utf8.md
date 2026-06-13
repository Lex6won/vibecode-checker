# Windows에서 한글이 깨질 때 — UTF-8 설정 가이드

Windows(특히 한국어 Windows)에서 `gvskb` 명령을 실행하면 한글 리포트·로그가 `?`, `Ω`, `占쏙옙` 같이 깨질 수 있습니다. 이는 도구의 버그가 아니라 **Windows 기본 인코딩(cp949)과 도구의 출력 인코딩(UTF-8)이 다르기 때문**입니다. 아래 순서대로 한 번만 설정하면 해결됩니다.

> 결론부터: PowerShell에서 `chcp 65001` + `$env:PYTHONUTF8='1'` + `$env:PYTHONIOENCODING='utf-8'` 세 가지를 설정하면 됩니다. 영구 적용 방법은 [4번](#4-매번-입력하기-귀찮다면--영구-설정)을 보세요.

---

## 0. 먼저 내 환경을 진단하기

무엇이 문제인지 도구가 직접 알려줍니다.

```powershell
gvskb doctor
```

출력에서 아래 세 줄을 확인하세요.

```
[ OK ]  stdout encoding        utf-8
[ OK ]  PYTHONUTF8             1
[ OK ]  PYTHONIOENCODING       utf-8
```

- 세 줄이 모두 `[ OK ]` 이면 — 설정 완료. 더 할 일 없습니다.
- 하나라도 `[WARN]` 이면 — 아래 1~4번을 진행하세요. doctor가 권장 명령도 함께 출력합니다.

---

## 1. 증상 확인

| 증상 | 원인 |
|---|---|
| 리포트의 한글이 `?`, `占쏙옙`, `Ω` 로 보임 | 터미널 코드페이지가 cp949(949) |
| `UnicodeEncodeError: 'cp949' codec can't encode` | Python 출력 인코딩이 cp949 |
| `gvskb scan` 결과 파일(.md)은 정상인데 화면 출력만 깨짐 | 파일은 UTF-8로 저장되나 *터미널* 만 cp949 |
| MCP 로그(`[gvskb] loaded ...`)의 한글이 깨짐 | MCP 설정 파일의 `env` 누락 |

> 파일로 저장한 보고서(`-o report.md`)는 항상 UTF-8입니다. **화면 출력만 깨지는 것이라면 터미널 설정만 바꾸면 됩니다.**

---

## 2. PowerShell에서 즉시 해결 (현재 창에만 적용)

PowerShell 창에서 아래 세 줄을 입력한 뒤 `gvskb`를 실행하세요.

```powershell
chcp 65001
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

gvskb doctor          # 세 줄이 [ OK ] 인지 확인
gvskb scan ./src --format markdown -o report.md
```

- `chcp 65001` — 터미널 코드페이지를 UTF-8(65001)로 변경
- `$env:PYTHONUTF8 = "1"` — Python을 UTF-8 모드로 강제
- `$env:PYTHONIOENCODING = "utf-8"` — Python 표준 입출력 인코딩을 UTF-8로 고정

> ⚠ 이 설정은 **현재 PowerShell 창에만** 적용됩니다. 창을 닫으면 사라집니다. 매번 입력하기 싫다면 [4번](#4-매번-입력하기-귀찮다면--영구-설정)으로.

---

## 3. 명령 프롬프트(cmd)를 쓴다면

cmd에서는 `$env:` 문법 대신 `set`을 씁니다.

```cmd
chcp 65001
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

gvskb doctor
```

> 가능하면 cmd보다 **PowerShell** 사용을 권장합니다. 한글 처리·스크립팅이 더 안정적입니다.

---

## 4. 매번 입력하기 귀찮다면 — 영구 설정

### 방법 A. PowerShell 프로필에 추가 (권장)

PowerShell을 열 때마다 자동으로 설정됩니다.

```powershell
# 프로필 파일이 없으면 만들고, 편집기로 엽니다
if (-not (Test-Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force }
notepad $PROFILE
```

열린 파일 맨 아래에 아래 세 줄을 추가하고 저장하세요.

```powershell
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
chcp 65001 > $null
```

PowerShell을 껐다 켜면 자동 적용됩니다.

### 방법 B. 사용자 환경변수로 등록 (모든 터미널에 적용)

PowerShell·cmd·IDE 터미널 모두에 적용하려면 환경변수로 등록합니다.

```powershell
[Environment]::SetEnvironmentVariable("PYTHONUTF8", "1", "User")
[Environment]::SetEnvironmentVariable("PYTHONIOENCODING", "utf-8", "User")
```

등록 후 **터미널(또는 IDE)을 재시작**해야 적용됩니다. 코드페이지(`chcp 65001`)는 터미널별 설정이라 환경변수로 등록되지 않으므로, 화면 출력이 여전히 깨지면 방법 A를 함께 사용하세요.

### 방법 C. Windows 11 시스템 전역 UTF-8 (선택)

Windows 자체를 UTF-8 우선으로 바꾸는 방법입니다. 다른 한국어 프로그램과 호환성 문제가 생길 수 있으니 **공용 PC에서는 신중히** 사용하세요.

1. `설정 → 시간 및 언어 → 언어 및 지역 → 관리 언어 설정 → 시스템 로캘 변경`
2. **"Beta: 세계 언어 지원을 위해 Unicode UTF-8 사용"** 체크
3. 재부팅

---

## 5. MCP로 연결할 때 (Claude Desktop · Cursor 등)

MCP 클라이언트는 별도 프로세스로 `gvskb` 서버를 실행하므로, **설정 파일의 `env`에 직접 인코딩 값을 넣어야** 합니다. PowerShell 설정만으로는 적용되지 않습니다.

`claude_desktop_config.json` 예시:

```json
{
  "mcpServers": {
    "vibecode-checker": {
      "command": "python",
      "args": ["-m", "gvskb.server"],
      "env": {
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

`env`의 `PYTHONUTF8`·`PYTHONIOENCODING` 두 줄이 핵심입니다. 누락하면 MCP 로그·결과의 한글이 깨질 수 있습니다.

---

## 6. 그래도 깨진다면 — 체크리스트

| 확인 | 방법 |
|---|---|
| 진단부터 다시 | `gvskb doctor` 의 인코딩 3줄이 `[ OK ]` 인가 |
| 터미널 재시작 했는가 | 환경변수 등록(방법 B) 후에는 재시작 필요 |
| 폰트 문제 아닌가 | 터미널 글꼴이 한글 지원 폰트(예: D2Coding, 맑은 고딕)인가 |
| 진짜 Python인가 | `python --version` 이 동작하는가 (Microsoft Store stub이면 비정상 종료) |
| 파일은 정상인가 | `-o report.md` 로 저장한 파일을 VS Code 등에서 열어 한글 정상 표시되면, 화면 출력만 문제 |
| Bash(Git Bash·WSL)인가 | Git Bash에서 Python 호출 시 `PYTHONIOENCODING=utf-8 PYTHONUTF8=1 python ...` 처럼 명령 앞에 붙여야 할 수 있음 |

---

## 부록. 왜 이런 일이 생기나 (배경)

- 한국어 Windows의 기본 텍스트 인코딩은 **cp949(EUC-KR 확장)** 입니다.
- `gvskb`를 포함한 현대 도구는 **UTF-8**로 한글을 출력합니다.
- 둘이 다르면 같은 한글 바이트를 서로 다르게 해석해 글자가 깨집니다.
- `chcp 65001`(코드페이지)은 *터미널*을, `PYTHONUTF8`·`PYTHONIOENCODING`은 *Python 프로세스*를 각각 UTF-8로 맞춥니다. 그래서 **세 가지를 함께** 설정해야 화면·파일·로그가 모두 정상이 됩니다.

> 망분리·행정망 환경에서도 인코딩 설정은 동일합니다. 인코딩은 외부 통신과 무관한 *로컬 출력* 문제이므로 `GVSKB_MODE=offline`과 함께 그대로 적용하면 됩니다.

---

관련 문서: [README.md](../README.md) · `gvskb doctor`(자동 진단)
