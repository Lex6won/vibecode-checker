---
id: KISA-JS-SEC-13
title_ko: 주석문 안에 비밀번호·계정·키가 적혀 있습니다
title_en: Credentials written inside JavaScript comments
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 12. 주석문 안에 포함된 시스템 주요정보
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-43
cwe: [CWE-615, CWE-798]
severity: high
decision_default: block
domains: [secret-scanning]
languages: [javascript, typescript]
scenarios: [web-app, web-frontend, api-server]
related_baseline: [KISA-PY-SEC-13]
verified_at: 2026-08-08
review_due: 2027-02-28
detection:
  patterns:
    # 파이썬에는 KISA-PY-SEC-13 이 있는데 **JS/TS 에는 대응 룰이 없었다**(실측
    # 2026-08-08). `/** 운영 DB: id=admin  pw=Adm1n2026Prod */` 가 통째로
    # 미탐이었다 — 주석이라 대부분의 룰은 건너뛰고, 값에 따옴표가 없어 시크릿
    # 룰도 걸리지 않는 사각지대였다.
    #
    # **JSDoc 은 파이썬 `#` 주석과 다르다 — 코드 예시를 자주 담는다.**
    # 1차 시안은 `.*` 로 주석 줄 전체를 훑다가 실측에서 세 건을 오탐으로 냈다:
    #   · `// HWP 구조: Root/BodyText/…`  → `root/` 를 'admin/비번' 으로 읽음
    #   · `* 예약어(over/root/of)`         → 같은 원인
    #   · ``* … `if (process.env.FC_RAG_BENCH_SECRET && …)` `` → 주석 속 코드 인용
    # 그래서 두 가지로 좁혔다:
    #   ① 훑는 범위가 **코드 인용 문자**(백틱·괄호·중괄호·대괄호)를 넘지 않는다.
    #      산문에는 이 문자들이 드물고 코드 인용에는 반드시 있다.
    #   ② 값이 점으로 이어진 식별자면 제외한다 — `process.env.DB_PW` 는 값이
    #      아니라 **비밀을 코드에 두지 않았다는 증거**다.
    #
    # `admin / 비번` 처럼 슬래시로 구분한 자격증명 패턴은 **넣지 않았다.**
    # 파이썬 룰에는 있지만 JS 주석에는 경로(`Root/BodyText`)와 산문(`over/root/of`)이
    # 흔해 구분이 되지 않는다. 적중보다 오경고가 많을 검사는 넣지 않는 편이 낫다.
    - "(?i)^\\s*(?://|/\\*+|\\*)[^`(){}\\[\\]]{0,60}?\\b(?:password|passwd|pw|비밀번호|암호)\\s*[:=]\\s*(?![^\\s]*(?:YOUR[_-]|[_-]HERE|X{6,}|CHANGE[_-]?ME|PLACEHOLDER|<[A-Za-z]|예시|여기))(?![A-Za-z_]\\w*(?:\\.\\w+)+(?:\\s|$))[^\\s`'\\\"(){}]{4,}"
    - "(?i)^\\s*(?://|/\\*+|\\*)[^`(){}\\[\\]]{0,60}?\\b(?:userid|username|user_id|admin_id|admin_pw)\\s*[:=]\\s*(?![A-Za-z_]\\w*(?:\\.\\w+)+(?:\\s|$))[^\\s`'\\\"(){}]{4,}"
    - "(?i)^\\s*(?://|/\\*+|\\*)[^`(){}\\[\\]]{0,60}?\\bid\\s*[:=]\\s*(?:admin|administrator|root|sa|sys)\\b"
    - "(?i)^\\s*(?://|/\\*+|\\*)[^`(){}\\[\\]]{0,60}?\\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|signing[_-]?key|jwt[_-]?secret)\\s*[:=]\\s*(?![^\\s]*(?:YOUR[_-]|[_-]HERE|X{6,}|CHANGE[_-]?ME|PLACEHOLDER|<[A-Za-z]|예시|여기))(?![A-Za-z_]\\w*(?:\\.\\w+)+(?:\\s|$))[^\\s`'\\\"(){}]{4,}"
  category: secret-scanning
  confidence: likely
  why_it_matters: >-
    주석은 배포 번들에 그대로 실려 브라우저에서 누구나 볼 수 있고, Git 이력에도
    영구히 남습니다. "나중에 지우겠다"고 적어 둔 운영 계정·비밀번호가 그대로
    공개되는 일이 실제로 반복됩니다. 코드에서 지워도 이력에 남으므로
    **해당 자격증명은 반드시 재발급**해야 합니다.
  public_sector_impact:
    - 운영 계정 탈취
    - 행정시스템 무단 접근
    - 감사 지적
  safe_fix: |
    주석에서 값을 지우고, 자격증명은 환경변수나 기관 secret manager로 옮기세요.
    이미 커밋되었다면 코드 수정만으로는 부족합니다 — **비밀번호·키를 폐기하고
    재발급**한 뒤, 필요하면 이력 정리(git filter-repo 등)를 보안담당자와 협의하세요.
  references:
    - KISA-JS-SECURE-CODING-2023
    - CWE-615
    - CWE-798
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "// 운영 DB pw = Adm1n2026Prod"
    - "/** 관리자 계정 id = admin */"
    - " * api_key = AIzaSyD1234567890abcdef"
    - "// username: operator01"
    - "/* 운영 DB: password=Adm1n2026Prod */"
  negative:
    # 실측 오탐 3건(2026-08-08) — 1차 시안이 `.*` 로 줄 전체를 훑다가 걸렸다.
    # 이 셋이 다시 걸리면 룰이 되돌아간 것이다.
    - "// HWP 구조: Root/BodyText/Section0, Root/DocInfo, Root/BinData/BIN0001 등"
    - " * 예약어(over/root/of) 를 필러로 가린 사본"
    - " * requireAiAuth 최상단에 `if (process.env.APP_SECRET && req.get('x-s'))`"
    # 값이 아니라 **어디서 읽는지**를 적은 주석 — 오히려 모범 사례다
    - "// 예: config.password = process.env.DB_PW"
    - "/** @param {string} password - 사용자 비밀번호 */"
    # 플레이스홀더는 실제 자격증명이 아니다
    - "// password = YOUR_PASSWORD_HERE"
    - "// api_key = <your-api-key>"
    - "// password = XXXXXXXX"
    # 값이 없는 안내문 — 무엇을 넣으라는 설명이지 값이 아니다
    - "// 비밀번호 정책은 8자 이상입니다"
    # 주석이 아닌 실제 코드는 다른 룰(GOV-SECRET-APIKEY-001)이 담당한다
    - "const password = getPasswordFromVault()"
---

## 무엇이 위험한가

주석은 **지워졌다고 착각하기 가장 쉬운 자리**입니다.

- 프런트엔드 번들에 그대로 실려 브라우저 개발자도구에서 누구나 읽습니다.
- 미니파이는 주석을 지우지만, **소스맵을 함께 배포하면 원본 주석이 복원**됩니다.
- 코드에서 지워도 **Git 이력에는 영구히 남습니다.**

## 안전한 패턴

```js
// 나쁨 — 주석에 값을 적어 둔다
// 운영 DB: id=admin  pw=Adm1n2026Prod

// 좋음 — 어디서 가져오는지만 적는다
// 운영 DB 자격증명은 기관 secret manager 의 `prod/db` 항목을 사용합니다.
const password = await vault.get("prod/db");
```

## 발견되면 해야 할 일

1. 주석에서 값을 지웁니다.
2. **해당 비밀번호·키를 폐기하고 재발급합니다.** 이력에 남아 있으므로 코드 수정만으로는 노출이 끝나지 않습니다.
3. 이력 정리가 필요한지 보안담당자와 협의합니다.
