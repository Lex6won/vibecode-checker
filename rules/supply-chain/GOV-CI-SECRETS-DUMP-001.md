---
id: GOV-CI-SECRETS-DUMP-001
title_ko: CI 워크플로가 저장소 비밀값 전체를 한 번에 꺼냅니다 (toJSON(secrets))
title_en: Workflow dumps the whole secrets context (toJSON(secrets))
status: approved
source_layer: baseline
sources:
  - publisher: GitHub
    document: Security hardening for GitHub Actions
    url: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
  - publisher: JFrog Security Research
    document: Shai-Hulud npm worm (2026-08) — injected codeql_analysis.yml wrote toJSON(secrets) to an artifact
cwe: [CWE-532, CWE-200]
severity: critical
decision_default: block
domains: [supply-chain]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration, package-install]
related_baseline: [GOV-CI-PWN-REQUEST-001]
verified_at: 2026-10-24
review_due: 2027-04-24
detection:
  patterns: []
  confidence: confirmed
  category: supply-chain
  why_it_matters: >-
    `${{ toJSON(secrets) }}` 는 저장소·조직의 **모든 비밀값**을 JSON 으로 꺼냅니다. 정상 워크플로에 이 표현이
    있을 이유가 없습니다 — 비밀값은 이름을 지정해 하나씩 씁니다. 2026-08 npm 웜은 피해 저장소에
    `codeql_analysis.yml` 이라는 이름의 워크플로를 밀어 넣고 이 한 줄로 비밀값을 파일에 써서 artifact 로 받아갔습니다.
    보안 도구 이름(codeql·security·dependabot)을 단 워크플로가 **이번 변경에서 새로 추가**됐다면 더 의심하세요.
  public_sector_impact:
    - 저장소에 등록된 배포·클라우드·레지스트리 토큰 일괄 유출
  safe_fix: |
    1. 해당 줄을 지우고, 필요한 비밀값만 `${{ secrets.NAME }}` 으로 **환경변수에** 주입하세요.
    2. 이 워크플로가 누가 언제 추가했는지 Git 이력을 확인하세요. 봇·낯선 계정이면 저장소 비밀값을 **전부 재발급**합니다.
  references:
    - GitHub Docs — Security hardening for GitHub Actions
    - CWE-532 Insertion of Sensitive Information into Log File
  can_auto_fix: false
examples:
  positive:
    - "      - run: echo '${{ toJSON(secrets) }}' > format-results.txt"
  negative:
    - "      - run: deploy.sh\n        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}"
---

## 오해하지 마세요

`${{ secrets.NAME }}` 처럼 **이름을 지정한** 사용은 잡지 않는다.
