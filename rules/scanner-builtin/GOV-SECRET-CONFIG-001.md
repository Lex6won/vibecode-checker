---
id: GOV-SECRET-CONFIG-001
title_ko: 설정 파일에 따옴표 없이 적힌 비밀번호·키·토큰
title_en: Unquoted secret assignment in configuration files
status: approved
source_layer: baseline
sources:
  - publisher: NIST
    document: SP 800-218 SSDF
  - publisher: OWASP
    document: ASVS 5.0
    item: V6 Authentication and Session Management
cwe: [CWE-798, CWE-260]
severity: critical
decision_default: block
domains: [secret-scanning]
# **설정·데이터 파일에서만** 돈다(.env·.properties·.ini·YAML·JSON). 이 패턴은 원래
# GOV-SECRET-APIKEY-001 안에 언어 제한 없이 있었고, 그 결과 TypeScript 타입 주석
# `token: string;` 과 Python 속성 대입 `g.auth_token = auth_token` 이 '치명·차단'으로
# 잡혔다(실측 2026-10-15 챗봇: 비밀값 오탐 7건 중 6건). 코드 파일의 따옴표 있는 리터럴은
# APIKEY-001 이 계속 본다.
languages: [config, data]
scenarios: [llm-integration, web-app, data-pipeline, agent]
related_baseline: [OWASP-LLM-2025-02]
verified_at: 2026-10-15
review_due: 2027-04-15
detection:
  patterns:
    # 따옴표 **없는** 설정 파일 대입 — `.env`·`.properties`·`.ini`·YAML.
    #
    # 실측(2026-08-08): 위 패턴을 포함해 비밀번호 룰 전부가 값에 따옴표를
    # 요구했다. 그런데 설정 파일은 **따옴표 없이 쓰는 것이 표준**이라
    # `spring.datasource.password=gg2026Secure` 나 `DB_PASSWORD=gg2026Secure`
    # 가 통째로 미탐이었다 — 공공 Java/Spring 프로젝트에서 비밀번호가 가장 흔히
    # 노출되는 자리다.
    #
    # 산문·주석까지 먹지 않도록 **한 줄 전체 모양**을 요구한다: 줄 시작 · 값에
    # 공백/따옴표 없음 · 줄 끝(또는 뒤따르는 `#`·`;` 주석)까지. 이 모양은 코드에서는
    # 문법 오류라 사실상 설정 파일에서만 나온다. `password 정책은 8자 이상입니다`
    # 같은 안내문은 값에 공백이 있어 걸리지 않는다.
    #
    # 값 **전체**가 변수 참조(`${VAR}`·`$VAR`·`%VAR%`·`{{ var }}`)면 제외한다 —
    # 비밀을 코드에 두지 않았다는 증거다. 위 따옴표 패턴이 맨몸 `$VAR` 를 제외하지
    # 않는 것과 다른데, 이유가 있다: 저쪽은 값 **안에** `$` 가 섞인 실제 비밀번호를
    # 놓치지 않으려는 것이고, 여기서는 값이 **오직** 변수 참조뿐인 경우만 뺀다.
    #
    # **코드와 설정을 가르는 것이 이 패턴의 전부다.** 1차 시안은 값의 모양만 보다가
    # `password = getpass.getpass()` 를 차단했다 — 비밀번호를 *올바르게 읽는* 코드다.
    # 모범 사례를 막는 것은 오탐 중에서도 최악이라, 값의 '비밀스러움'을 추측하지 않고
    # **키와 구분자의 모양**으로 가른다. 넷 중 하나여야 한다:
    #   ⓐ `:` 구분자      — YAML/properties. 파이썬 대입문이 아니다
    #   ⓑ 점 있는 키       — `spring.datasource.password`
    #   ⓒ 대문자 키        — `DB_PASSWORD` (.env 관행)
    #   ⓓ 공백 없는 `=`    — `api_key=값` (PEP8 문장은 `=` 양옆에 공백을 넣는다)
    # 값에 괄호가 있으면(=호출) 무조건 뺀다.
    #
    # 남는 미탐: 소문자 키 + 공백 있는 `=` 형태의 설정(`password = 값`)은 코드와
    # 구분되지 않아 잡지 않는다. 놓치는 쪽을 택한 이유는, 여기서 잡으려다 위의
    # `getpass()` 같은 **정상 코드를 막으면 도구가 통째로 꺼지기** 때문이다.
    # 실측 보정(2026-08-08): `google_api_key=GEMINI_API_KEY,` 가 걸렸다 —
    # 파이썬 **키워드 인자**이고 값은 상수 참조다. 두 가지를 더 막는다:
    #   · 값에 쉼표 금지 → 함수 인자는 `,` 로 끝나 줄 끝 앵커에서 탈락한다
    #   · 값이 대문자 상수 이름 하나뿐이면 제외 → `GEMINI_API_KEY` 는 참조다
    # 실제 비밀번호가 전부 대문자·숫자·밑줄로만 이뤄질 수 있지만, 그 미탐보다
    # **정상 코드를 차단하는 쪽이 훨씬 비싸다**(도구를 끄게 만든다).
    - '(?i)^[ \t]*(\*\*)?(?:(?:[\w.\-]*[._-])?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|token)(?(1)\*\*)[ \t]*:[ \t]*|[\w\-]+(?:\.[\w\-]+)*\.(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|token)(?(1)\*\*)[ \t]*=[ \t]*|(?-i:[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|API_?KEY|ACCESS_?KEY|TOKEN)|(?:PASSWORD|PASSWD|PWD|SECRET|API_?KEY|ACCESS_?KEY|TOKEN))(?(1)\*\*)[ \t]*=[ \t]*|(?:[\w.\-]*[._-])?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|token)(?(1)\*\*)=)(?!(?:\$\{[^}]+\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{\{[^}]+\}\})[ \t]*(?:[#;].*)?$)(?![^\s#;]*(?:YOUR[_-]|[_-]HERE|X{6,}|CHANGE[_-]?ME|PLACEHOLDER|<[A-Za-z]|\*\*\*|예시|여기))(?![^\s#;]*[(),])(?!(?-i:[A-Z][A-Z0-9_]*)[ \t]*(?:[#;].*)?$)[^\s\"'',#;]{6,}[ \t]*(?:[#;].*)?$'
  exclude_patterns:
    # 타입 이름·플레이스홀더는 값이 아니다(설정 파일에 스키마를 적는 경우).
    - '(?i)[:=][ \t]*(?:string|number|boolean|integer|int|float|bool|any|null|undefined|object)\b[ \t]*;?[ \t]*$'
  validators: [not_self_named_value]
  dedup_group: hardcoded-credential
  category: secret-scanning
  why_it_matters: >-
    .env·properties·YAML 에 적힌 비밀번호·토큰은 저장소에 그대로 커밋돼 git 이력·CI 로그로
    새어 나갑니다. 설정 파일은 따옴표 없이 쓰는 것이 표준이라 코드용 패턴으로는 놓칩니다.
  public_sector_impact:
    - DB·외부 API 자격증명 유출
    - 운영 서버 접속 토큰 노출
  safe_fix: |
    값을 파일에 두지 말고 배포 환경의 비밀 저장소(Vault·OS keyring·CI secret)에서 주입하세요.
    DB_PASSWORD=${DB_PASSWORD} 처럼 참조만 남기면 이 룰은 울리지 않습니다.
  references:
    - NIST SSDF PW.4
    - CWE-798
  can_auto_fix: false
examples:
  language: config
  positive:
    - "DB_PASSWORD=gg2026SecureP@ss"
    - "spring.datasource.password=gg2026Secure"
    - "api_key: sk-abcdefghijklmnopqrstuvwxyz123456"
  negative:
    - "DB_PASSWORD=${DB_PASSWORD}"
    - "token: string"
    - "PASSWORD="
---

# 설정 파일의 따옴표 없는 비밀값

`.env`·`.properties`·`.ini`·YAML 처럼 **따옴표 없이** `키=값`·`키: 값` 으로 쓰는 파일에서 비밀번호·토큰·
API 키 값을 찾는다. 코드 파일(Python·TypeScript 등)에는 적용하지 않는다 — 그쪽의 `token: string;`
(타입 주석)·`g.auth_token = auth_token`(변수 대입)은 값이 아니다. 코드의 따옴표 있는 리터럴은
`GOV-SECRET-APIKEY-001` 이 본다.
