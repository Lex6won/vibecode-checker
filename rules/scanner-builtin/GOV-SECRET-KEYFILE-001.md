---
id: GOV-SECRET-KEYFILE-001
title_ko: 비밀 자재로 보이는 값이 파일에 그대로 저장되어 있습니다
title_en: Credential-looking material stored in a secret-named file
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: 소프트웨어 개발보안 가이드
    item: 중요정보 평문 저장
  - publisher: OWASP
    document: ASVS 5.0
    item: V6 Stored Cryptography
cwe: [CWE-312, CWE-798]
severity: high
decision_default: warn
domains: [secret-scanning]
languages: []
scenarios: [web-app, data-pipeline, agent, llm-integration]
related_baseline: [GOV-SECRET-PRIVATEKEY-001, GOV-SECRET-001]
verified_at: 2026-07-31
review_due: 2027-01-31
detection:
  # 이 룰은 **파일명과 내용을 함께 봐야** 판정할 수 있어 스캐너가 직접 발행한다.
  # 줄 단위 regex 는 파일명을 모르므로, 64자 hex 같은 값이 해시·체크섬인지
  # 비밀키인지 구분하지 못해 오탐이 불가피하다.
  patterns: []
  confidence: likely
  category: secret-scanning
  why_it_matters: >-
    ``.secret_key``·``password.txt``·``credentials`` 처럼 **이름부터 비밀임을
    말하는 파일**에 임의의 고엔트로피 값(긴 hex·base64)이 평문으로 들어 있으면,
    그 값은 세션 위조·인증 우회에 바로 쓰일 수 있습니다. 파일을 소스와 함께
    배포·전달하거나 AI 도구에 폴더째 넘기면 그대로 유출됩니다.
    다만 **키를 코드에서 분리해 파일로 두는 것 자체는 권장 관행**이므로,
    이 발견은 "즉시 위반"이 아니라 **보관·배포 방식을 확인하라는 신호**입니다.
  public_sector_impact:
    - 세션 위조·인증 우회
    - 배포본·저장소를 통한 비밀값 확산
    - 담당자 교체 시 키 회수 불가
  safe_fix: |
    확인할 것 3가지:

    1. **저장소에 올라가지 않는가** — `.gitignore` 에 해당 파일이 있는지 확인하고,
       이미 커밋됐다면 값을 **폐기·재발급**하세요(이력에서 지워도 복구 가능).
    2. **배포본에 섞이지 않는가** — 설치 zip·USB 반입 자료에 포함되면
       받는 사람 모두가 키를 갖게 됩니다.
    3. **권한이 제한돼 있는가** — 서버에서는 서비스 계정만 읽도록 제한하세요
       (Linux: chmod 600 · Windows: 해당 계정 외 읽기 거부).

    더 안전한 방식: 환경변수 또는 기관 비밀관리 체계에서 주입하고, 파일에는
    두지 않습니다. 운영 환경에서는 기동 시 자동 생성 후 안전한 경로에 보관하세요.
  references:
    - CWE-312 Cleartext Storage of Sensitive Information
    - OWASP ASVS V6
  can_auto_fix: false
examples:
  positive:
    - '77fec85613b823cd9b6e3bdb41dfd1fc492fdf2463fd01ce7bc8cf3e1606cfac'
  negative:
    - '# 이 파일은 기동 시 자동 생성됩니다'
---

## 무엇이 위험한가
이름이 비밀을 뜻하는 파일(`.secret_key`, `password.txt`, `credentials.*` 등)에 **긴 무작위 값**이 평문으로 있으면, 그 값은 대개 세션 서명키·API 키·비밀번호입니다.

예를 들어 Flask 의 `secret_key` 가 유출되면 **세션 쿠키를 위조**해 관리자로 로그인할 수 있습니다.

## 이 발견을 보면 확인할 것

| 확인 | 왜 |
|---|---|
| `.gitignore` 등록 여부 | 커밋되면 이력에 영구 보존 — 삭제해도 복구 가능 |
| 배포본 포함 여부 | 설치 zip·USB 반입 자료에 섞이면 전원이 키 보유 |
| 파일 권한 | 공용 PC·공유 폴더에서는 다른 사용자가 읽을 수 있음 |
| AI 도구 전달 여부 | 폴더째 넘기면 외부 서비스로 전송될 수 있음 |

## 오해하지 마세요
**키를 코드에서 분리해 파일로 두는 것은 권장 관행입니다.** 이 룰은 그 관행을 나무라는 게 아니라, 그 파일이 **어디까지 함께 이동하는지** 확인하라는 신호입니다. 위 4가지가 모두 통제되고 있다면 예외로 처리해도 됩니다(`.gvskb-exceptions.yaml`).
