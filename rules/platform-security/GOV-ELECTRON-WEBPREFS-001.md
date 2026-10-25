---
id: GOV-ELECTRON-WEBPREFS-001
title_ko: Electron 렌더러에 Node 권한을 주는 webPreferences 가 켜져 있습니다
title_en: Electron BrowserWindow webPreferences grant Node/privileged access to renderer content
status: approved
source_layer: baseline
sources:
  - publisher: Electron
    document: Security — Checklist
    url: https://www.electronjs.org/docs/latest/tutorial/security/
cwe: [CWE-16, CWE-693]
severity: critical
decision_default: block
domains: [platform-security]
languages: [javascript, typescript]
scenarios: [web-app, agent]
related_baseline: [GOV-ELECTRON-IPC-BRIDGE-001, GOV-ELECTRON-HARDENING-001]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # ecosystem-surface 수집기(electron 의존성이 있을 때만). new BrowserWindow 근처의 webPreferences 를 본다.
  # 원격 URL(loadURL http(s)://) 로드가 같은 파일에 있으면 confirmed, 로컬 파일만이면 likely(경고).
  patterns: []
  confidence: likely
  category: platform-security
  why_it_matters: >-
    `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, `allowRunningInsecureContent: true`,
    `webviewTag: true` 는 렌더러(웹 콘텐츠)에 Node.js·파일 시스템·프로세스 권한을 줍니다. 그 렌더러가 **원격 콘텐츠**를
    로드하면 그 사이트의 XSS 하나가 PC 전체 권한이 됩니다. Electron 공식 체크리스트의 1~5번 항목입니다.
    Electron 12+ 는 contextIsolation, 20+ 는 sandbox 가 기본 켜짐이므로 명시적으로 끈 것만 잡습니다.
  public_sector_impact:
    - 내부 업무용 데스크톱 앱에서 웹 콘텐츠 취약점이 로컬 파일·자격증명 접근으로 확대
  safe_fix: |
    1. `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, `webSecurity: true` 로 두고(기본값),
       렌더러가 필요한 기능은 **preload + contextBridge 로 좁게** 노출하세요(GOV-ELECTRON-IPC-BRIDGE-001).
    2. 원격 콘텐츠는 별도 BrowserWindow(권한 없음)에서만 로드하세요.
    3. `webviewTag` 는 쓰지 말고 `BrowserView`/`WebContentsView` 로 대체하세요.
  references:
    - Electron Security Checklist
    - CWE-693 Protection Mechanism Failure
  can_auto_fix: false
examples:
  positive:
    - "const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\nwin.loadURL('https://portal.example/app');"
  negative:
    - "const win = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true } });\nwin.loadFile('index.html');"
---

## 무엇이 위험한가

렌더러는 웹페이지다. 웹페이지에 Node 권한을 주면 웹 취약점이 데스크톱 취약점이 된다.

## 오해하지 마세요

로컬 파일만 로드하는 창에서 켠 경우는 경고(검토)까지만이다 — 그래도 preload+contextBridge 로 바꾸는 것이 권장이다.
