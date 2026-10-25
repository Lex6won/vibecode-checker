---
id: GOV-ELECTRON-IPC-BRIDGE-001
title_ko: Electron IPC 경계가 넓습니다 (범용 contextBridge · 발신자 미검증 ipcMain 핸들러 · 미검증 openExternal)
title_en: Electron IPC boundary too wide (wholesale/generic contextBridge, unvalidated ipcMain handler, unvalidated openExternal)
status: approved
source_layer: baseline
sources:
  - publisher: Electron
    document: Security — Checklist (contextBridge · validate IPC sender · shell.openExternal)
    url: https://www.electronjs.org/docs/latest/tutorial/security/
cwe: [CWE-668, CWE-749]
severity: high
decision_default: block
domains: [platform-security]
languages: [javascript, typescript]
scenarios: [web-app, agent]
related_baseline: [GOV-ELECTRON-WEBPREFS-001]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # ecosystem-surface 수집기(electron 의존성이 있을 때만). 확정: contextBridge 가 ipcRenderer/require/process/shell/fs 를 통째로
  # 또는 채널명을 인자로 받는 범용 send/invoke 로 노출. 유력: 파일·프로세스·외부 요청 API 를 쓰는 ipcMain 핸들러에 senderFrame 검증
  # 없음 · shell.openExternal(비상수) 에 프로토콜 검사 없음 · openDevTools mode 비상수.
  patterns: []
  confidence: likely
  category: platform-security
  why_it_matters: >-
    Electron 보안 체크리스트는 preload 에서 기능을 **채널별 고정 함수**로만 노출하고, ipcMain 핸들러는 `event.senderFrame` 으로
    발신자를 검증하고, `shell.openExternal` 은 허용 프로토콜(https:)만 받도록 요구합니다. 이 룰은 그 세 조건이 빠진 자리를 표시합니다.
  public_sector_impact:
    - 렌더러 콘텐츠의 결함이 메인 프로세스 권한(파일·프로세스)으로 확대될 수 있는 경계
  safe_fix: |
    1. preload: `contextBridge.exposeInMainWorld('api', { getVersion: () => ipcRenderer.invoke('app:version') })` 처럼
       **채널별 고정 함수**만 노출하세요. `ipcRenderer`·`require`·`process` 객체나 `(channel, …) => ipcRenderer.send(channel, …)` 는 금지.
    2. ipcMain 핸들러 첫 줄에서 `new URL(event.senderFrame.url).origin` 을 허용 목록과 대조하고, 인자는 스키마로 검증하세요.
    3. `shell.openExternal(url)` 전에 `new URL(url).protocol === 'https:'` 를 확인하세요.
    4. `openDevTools` 의 `mode` 는 상수만 쓰세요.
  references:
    - Electron Security Checklist
    - CWE-749 Exposed Dangerous Method or Function
  can_auto_fix: false
examples:
  positive:
    - "contextBridge.exposeInMainWorld('electron', { ipcRenderer });"
  negative:
    - "contextBridge.exposeInMainWorld('api', { getVersion: () => ipcRenderer.invoke('app:version') });"
---

채널별 고정 함수 노출 + 발신자 검증 + 프로토콜 허용 목록이 갖춰진 코드는 잡지 않는다.
