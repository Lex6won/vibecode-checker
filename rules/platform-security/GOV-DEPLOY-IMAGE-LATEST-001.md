---
id: GOV-DEPLOY-IMAGE-LATEST-001
title_ko: 컨테이너 이미지를 :latest 로 받습니다 — 구성요소 버전이 고정되지 않습니다
title_en: Container image pinned to :latest
status: approved
source_layer: baseline
sources:
- publisher: 국정원
  document: 국가·공공기관 AI보안 가이드북
  version: '2025.12'
  item: M11
- publisher: 국정원
  document: 국가·공공기관 AI보안 가이드북
  version: '2025.12'
  item: M12
- publisher: (안) — 기관 채택 여부 미확인
  document: 바이브코딩 보안가이드북(안)
  item: '4.7'
- publisher: (안) — 기관 채택 여부 미확인
  document: 바이브코딩 보안가이드북(안)
  item: '4.14'
cwe:
- CWE-1357
severity: low
decision_default: warn
domains:
- gov-vibe
languages:
- data
scenarios:
- web-app
- llm-integration
related_baseline:
- NIS-AI-M11
- NIS-AI-M12
- GOV-CI-UNPINNED-ACTION-001
verified_at: '2026-11-06'
review_due: '2027-05-06'
detection:
  patterns:
  - ^\s*image:\s*[\"']?[\w./-]+:latest[\"']?\s*(?:#.*)?$
  exclude_patterns: []
  category: gov-secure-coding
  confidence: pattern-only
  why_it_matters: 배포할 때마다 다른 이미지가 들어올 수 있습니다. 검토한 구성요소와 운영 구성요소가 달라지고, 명세서에 적을 버전이 정해지지 않습니다.
  public_sector_impact:
  - 검토 후 구성요소 변경
  - 구성요소 명세·무결성 검증 불가
  safe_fix: 버전 태그와 sha256 다이제스트로 고정하세요.
  references:
  - 국정원 AI보안 가이드북 M11·M12
  - 바이브코딩 보안가이드북(안) 4.7
  can_auto_fix: false
examples:
  language: data
  positive:
  - '    image: qdrant/qdrant:latest'
  - '    image: "ollama/ollama:latest"'
  - '    image: nginx:latest  # 프록시'
  negative:
  - '    image: qdrant/qdrant:v1.12.0'
  - '    image: nginx:alpine'
  - '    image: acme/app@sha256:0123abc'
  - '    # image: qdrant/qdrant:latest'
  - 'description: image latest 금지'
---

## 무엇이 위험한가
M11 은 구성요소의 버전을 명세서로 관리하라고 요구합니다. `:latest` 는 그 전제를 무너뜨립니다.

## 안전한 패턴
`image: qdrant/qdrant:v1.12.0@sha256:…`

## 이 룰의 한계
태그 없는 이미지와 `nginx:alpine` 같은 유동 태그는 보지 않습니다(오탐보다 미탐을 택함).
