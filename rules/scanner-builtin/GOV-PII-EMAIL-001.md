---
id: GOV-PII-EMAIL-001
title_ko: 실제 이메일 주소로 보이는 값이 포함되어 있습니다
title_en: Real email address detected
status: approved
source_layer: baseline
sources:
  - publisher: 개인정보보호위원회
    document: 개인정보 보호법
    item: 제2조 제1호 (개인정보의 정의)
cwe: [CWE-359]
severity: medium
decision_default: warn
domains: [privacy-public-sector]
# 언어를 제한하지 않는다 — 설정 파일과 문서에도 들어간다.
languages: []
scenarios: [data-pipeline, llm-integration, web-app, agent]
related_baseline: [GOV-PII-PHONE-001, GOV-PII-RRN-001]
verified_at: 2026-11-06
review_due: 2027-05-06
detection:
  patterns:
    # 최상위 도메인을 목록으로 좁힌다. `pkg@1.2.3.js`, 문자열 안의 `\n@app.route` 는 이메일이 아니다.
    - '(?<![\w.+\\/-])[A-Za-z0-9][A-Za-z0-9._%+-]*@(?:[A-Za-z][A-Za-z0-9-]*\.)+(?:com|net|org|edu|gov|kr|info|biz|io|ai|dev|app|co|me|cloud|jp|cn|us|uk)(?![\w-])'
  exclude_patterns:
    # 합성 예제 · 시스템 주소 · 접속 문자열(자격증명 룰이 본다)
    - '(?i)@(?:[\w-]+\.)*(?:example|test|invalid|localhost)\b'
    - '(?i)\b(?:no-?reply|donotreply|git|postmaster|mailer-daemon)@'
    - '(?i)users\.noreply\.github\.com'
    - '://[^\s"'']*@'
    - '(?i)(?:^|[^가-힣A-Za-z])(?:예|예시|예를 들어|example|sample|e\.g\.)\s*[:：)]|마스킹|masking|placeholder'
  category: privacy-public-sector
  confidence: pattern-only
  why_it_matters: >-
    실제 이메일 주소는 개인을 식별하는 정보입니다. 코드·문서·Git 이력에 남으면 공개 저장소나 제출 자료로 그대로 나갑니다.
    서비스 운영에 필요한 주소인지 확인이 필요합니다.
  public_sector_impact:
    - 개인정보 노출
    - 표적 피싱 대상 노출
    - 감사 지적
  safe_fix: |
    실제 주소를 코드와 문서에서 지우고 환경변수나 설정으로 옮기세요.
    예시가 필요하면 name@example.com 처럼 예약된 도메인을 쓰세요.
  references:
    - 개인정보 보호법 제2조
    - CWE-359
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - 'const owner = "kim.minsu@somecompany.co.kr";'
    - 'ADMIN = "lee_ops@mail.somecorp.com"'
    - '담당: park.j@agency.or.kr'
  negative:
    - 'const email = "name@example.com";'
    - 'git clone git@github.com:org/repo.git'
    - 'Co-Authored-By: bot <noreply@anthropic.com>'
    - 'const url = "postgres://user:pw@db.somecorp.com/app";'
    - 'import vue from "vue@2.6.14.js";'
    - 'const pkg = "@types/node";'
    - 'code = "x\\n@app.route"'
---

## 무엇이 위험한가
실제 사람의 주소가 소스·문서에 남아 있는 경우입니다. 실제 사람의 주소인지는 도구가 알 수 없어 경고로 둡니다.

## 안전한 패턴
운영에 필요한 주소는 환경변수로 옮기고, 예시는 예약된 도메인을 씁니다.

## 이 룰의 한계
목록에 없는 최상위 도메인은 놓칩니다. 시험·문서 경로의 발견은 낮은 등급으로 표시됩니다.
