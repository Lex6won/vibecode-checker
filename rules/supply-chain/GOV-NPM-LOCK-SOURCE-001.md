---
id: GOV-NPM-LOCK-SOURCE-001
title_ko: npm 패키지를 공식 레지스트리 밖(비승인 호스트·git·URL·평문 HTTP)에서 받거나 무결성 값이 없습니다
title_en: npm dependencies resolved from non-registry sources (foreign host, git/URL, plaintext HTTP) or without integrity
status: approved
source_layer: baseline
sources:
  - publisher: npm
    document: npm Docs — package-lock.json (resolved · integrity)
    url: https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json
  - publisher: OWASP
    document: Dependency confusion / substitution attacks
cwe: [CWE-494, CWE-829, CWE-319]
severity: medium
decision_default: warn
domains: [supply-chain]
languages: [javascript, typescript]
scenarios: [web-app, agent, llm-integration, package-install]
related_baseline: [GOV-NPM-INSTALL-HOOK-001, GOV-MCP-CONFIG-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  # npm-surface 판정기: package.json 의 git/URL/file 의존성, 락파일 resolved 호스트·git 출처·integrity 결손, .npmrc registry.
  # 평문 http:// 레지스트리만 confirmed, 나머지는 likely(기관 미러는 허용 목록 registry_hosts 에 등록).
  patterns: []
  confidence: likely
  category: supply-chain
  why_it_matters: >-
    락파일의 `resolved` 는 **실제로 어디서 받는가**입니다. 공식 레지스트리·기관 미러가 아닌 호스트, `git+https://`
    저장소, 직접 URL tarball 은 버전 고정·취약점 조회·악성 패키지 인텔이 모두 비껴갑니다. `integrity` 가 없으면 받은
    파일이 승인한 그 파일인지 확인할 수 없습니다. 평문 `http://` 레지스트리는 중간자가 패키지를 바꿀 수 있습니다.
    내부 패키지 이름이 스코프 없이 쓰이면 공개 레지스트리의 같은 이름 패키지로 바뀌어 설치될 수 있습니다(의존성 혼동).
  public_sector_impact:
    - 취약점·악성 인텔이 닿지 않는 경로로 코드 반입
    - 망분리 반입 심사 우회
  safe_fix: |
    1. 기관 미러를 쓰면 그 호스트를 허용 목록(`GVSKB_INSTALL_SCRIPTS_ALLOW` 의 `registry_hosts`)에 등록하세요.
    2. git/URL 의존성은 레지스트리에 게시된 버전으로 바꾸거나, 꼭 필요하면 **commit SHA** 로 고정하고 사유를 기록하세요.
    3. `.npmrc` 의 `registry=` 는 반드시 `https://`. 내부 패키지는 `@기관스코프/` 를 붙이고 스코프별 레지스트리를 지정하세요.
    4. `integrity` 가 빠진 락파일은 `npm install --package-lock-only` 로 다시 생성하세요.
  references:
    - npm Docs — package-lock.json
    - CWE-494 Download of Code Without Integrity Check
  can_auto_fix: false
examples:
  positive:
    - '{"dependencies": {"utils": "git+https://github.com/someone/utils.git#main"}}'
  negative:
    - '{"dependencies": {"express": "^4.19.2"}}'
---

## 무엇이 위험한가

락파일의 `resolved` 가 곧 공급망이다. 공식 레지스트리·기관 미러 밖은 취약점·악성 인텔이 닿지 않는 길이다.

## 오해하지 마세요

허용 목록(`registry_hosts`)에 등록된 기관 미러, `workspace:`·`link:` 프로토콜(모노레포 내부 참조)은 잡지 않는다.
