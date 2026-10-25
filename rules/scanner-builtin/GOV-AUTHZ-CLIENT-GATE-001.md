---
id: GOV-AUTHZ-CLIENT-GATE-001
title_ko: 공개 번들 환경변수의 비밀·PIN 또는 브라우저 저장소만으로 세운 관리자 관문
title_en: Secret/PIN in a public bundle environment variable, or an admin gate based only on browser storage
status: approved
source_layer: baseline
sources:
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드 (2021.12.29) 제4장 제2절-1 (적절한 인증 없는 중요기능 허용)
  - publisher: Next.js
    document: Environment Variables — Bundling Environment Variables for the Browser (NEXT_PUBLIC_)
cwe: [CWE-306, CWE-602]
severity: high
decision_default: warn
domains: [gov-secure-coding]
languages: [javascript, typescript]
scenarios: [web-app]
related_baseline: [GOV-AUTHZ-ADMIN-POSTURE-001, GOV-SECRET-APIKEY-001]
verified_at: 2026-10-25
review_due: 2027-04-25
detection:
  # authz-posture 수집기. 유력: process.env/import.meta.env 의 NEXT_PUBLIC_·VITE_·REACT_APP_ 등 공개 접두사 변수 이름에
  # PIN·PASSWORD·SECRET·TOKEN·API_KEY. 패턴: 관리자 화면에서 sessionStorage/localStorage 값 비교만으로 관문을 세움.
  patterns: []
  confidence: likely
  category: access-control
  why_it_matters: >-
    공개 접두사 환경변수는 빌드 시 브라우저 번들에 그대로 들어가 누구나 읽을 수 있고, 브라우저 저장소 값은 사용자가
    직접 넣을 수 있습니다. 둘 다 클라이언트 측 조건이라 서버 검사를 대신하지 못합니다.
  public_sector_impact:
    - 관리자 PIN 이 정적 파일에 노출되어 관리자 화면·API 접근 통제가 무력화
  safe_fix: |
    1. PIN·비밀은 서버 환경변수로 옮기고, 검증은 서버 API 에서 하세요(세션·토큰 발급).
    2. 관리자 화면 진입은 서버가 발급한 세션으로 판단하고, 관리자 API 마다 서버측 검사를 두세요.
  references:
    - CWE-602 Client-Side Enforcement of Server-Side Security
  can_auto_fix: false
examples:
  positive:
    - "const ADMIN_PIN = process.env.NEXT_PUBLIC_ADMIN_PIN || '';\nif (pin === ADMIN_PIN) sessionStorage.setItem('admin_authenticated', 'true');"
  negative:
    - "const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL;\nconst res = await fetch(`${API_BASE}/api/admin/me`, { credentials: 'include' });"
---

공개 접두사라도 주소·기능 플래그처럼 비밀이 아닌 이름은 잡지 않는다.
