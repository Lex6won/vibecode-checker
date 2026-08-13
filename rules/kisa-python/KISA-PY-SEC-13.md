---
id: KISA-PY-SEC-13
title_ko: Python 주석문 안에 포함된 시스템 주요정보 - 주석에 박힌 ID·패스워드·API 키
title_en: Sensitive credentials left inside Python source comments
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 13. 주석문 안에 포함된 시스템 주요정보
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-53
cwe: [CWE-615]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline, auth]
related_baseline: [MOIS-49-SEC-13]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) 주석문 안에 password / passwd / pwd / 비밀번호 / 암호 = 값
    #    (값이 명백한 플레이스홀더면 실제 자격증명이 아니므로 제외)
    - "(?i)^\\s*#.*\\b(?:password|passwd|pwd|비밀번호|암호)(?:\\*\\*)?\\s*[:=]\\s*(?![^\\s]*(?:YOUR[_-]|[_-]HERE|X{6,}|CHANGE[_-]?ME|PLACEHOLDER|<[A-Za-z]|예시|여기))\\S+"
    # 2) 주석문 안에 id/username/userid + admin-스럽거나 비밀번호스러운 값
    - "(?i)^\\s*#.*\\b(?:userid|username|user_id|admin_id|admin_pw)(?:\\*\\*)?\\s*[:=]\\s*\\S+"
    # 2b) 주석문 안 'id = admin/root/...' — KISA 가이드 원문 예시 형태
    - "(?i)^\\s*#\\s*(?:\\*\\*)?id(?:\\*\\*)?\\s*[:=]\\s*(?:admin|administrator|root|sa|sys)\\b"
    # 3) 주석문 안에 API key / secret / token / 서명키 + 값
    #    (값이 명백한 플레이스홀더면 실제 자격증명이 아니므로 제외)
    - "(?i)^\\s*#.*\\b(?:api[_-]?key|secret(?:_key)?|access[_-]?token|signing[_-]?key|jwt[_-]?secret)(?:\\*\\*)?\\s*[:=]\\s*(?![^\\s]*(?:YOUR[_-]|[_-]HERE|X{6,}|CHANGE[_-]?ME|PLACEHOLDER|<[A-Za-z]|예시|여기))\\S+"
    # 4) 주석문 안에 'admin / password' 같이 슬래시 구분 자격증명 한 줄
    - "(?i)^\\s*#.*\\b(?:admin|root|test_?user)\\s*/\\s*\\S{3,}"
    # 5) 주석문 안 DB 접속 문자열
    - "(?i)^\\s*#.*(?:postgres|mysql|mongodb|redis|jdbc:)[a-z+]*://[^\\s:]+:[^\\s@]+@"
  category: secret-scanning
  why_it_matters: >-
    KISA 가이드의 안전하지 않은 예시는 함수 본문 위에
    `# id = admin` / `# passwd = passw0rd` 같은 주석을 남겨둡니다.
    개발 편의로 적어둔 자격증명은 *코드가 운영에 배포된 뒤에도 그대로*
    남아 있고, git 이력·코드 리뷰 캡쳐·LLM 학습 데이터·서드파티 분석
    툴 어디로도 새어나갈 수 있습니다. 한 줄 주석은 검색 한 번이면 잡히는
    가장 단순한 탈취 대상입니다. 이 룰은 `kisa-secure-coding` 이 아니라
    `secret-scanning` 카테고리를 사용하므로 *주석 라인도 검사*합니다
    — 본 룰의 본래 의도가 주석 안 자격증명 탐지이기 때문입니다.
  public_sector_impact:
    - 행정 내부망 관리자 계정 정보 노출
    - 외부 공개 저장소에 정부 시스템 자격증명 유출
    - 개인정보보호법 안전성 확보 조치 위반
    - 「공공기관 정보보안 기본지침」 비밀번호 관리 의무 위반
  safe_fix: |
    1단계: 주석에서 자격증명을 *삭제*하세요. git 이력에 남기지 않으려면
    `git rebase`/`git filter-repo`로 과거 commit에서도 제거가 필요합니다
    (이미 노출된 경우 *비밀번호 즉시 변경*이 우선).
        def user_login(id, passwd):
            # 주석문에 포함된 민감한 정보는 삭제
            result = login(id, passwd)
            return result
    2단계: 운영 자격증명은 환경변수·secret manager로 분리 (KISA-PY-SEC-06 참고):
        password = os.environ["DB_PASSWORD"]
    3단계: pre-commit 훅에 `detect-secrets` / `trufflehog` / 본 KB의
    `gvskb scan` 을 등록해 *커밋 시점*에 차단하세요.
  references:
    - KISA Python 가이드 제2절 13
    - MOIS-49-SEC-13
    - CWE-615 Inclusion of Sensitive Information in Source Code Comments
    - https://github.com/Yelp/detect-secrets
  can_auto_fix: false
examples:
  language: python
  positive:
    - "# id = admin"
    - "# passwd = passw0rd"
    - "# password: P@ssw0rd123!"
    - "# api_key = sk-1234567890abcdef"
    - "# admin / passw0rd  (운영서버)"
    - "# DB: postgres://gov_user:secret123@db.internal:5432/gov_db"
  negative:
    - "# 주석문에 포함된 민감한 정보는 삭제"
    - "password = os.environ['DB_PASSWORD']"
    - "# TODO: 비밀번호 정책 검토 필요"
    - "# 사용자 인증 후 result 반환"
    - "# password validation policy: 10 chars minimum"
    - "# example: api_key = YOUR_KEY_HERE"
    - "# password = CHANGEME_PLEASE"
---

## 무엇이 위험한가
KISA 가이드의 안전하지 않은 예시는 `user_login` 함수 안에 `# id = admin`, `# passwd = passw0rd` 같은 주석을 남겨둔 채로 코드가 완성됩니다. 개발자가 편의로 적어둔 자격증명은 *지우는 것을 잊기 쉽고*, 한 번 git에 들어가면 history 재작성 없이는 *영원히* 남습니다.

공격 경로는 평범합니다:
1. 공공기관 GitHub/GitLab/내부 저장소 노출 → 코드 검색 한 번으로 자격증명 노출
2. 코드 리뷰 캡쳐 화면이 메신저·문서로 공유될 때 함께 유출
3. LLM 코드 어시스턴트에 컨텍스트로 올라간 파일에서 자격증명이 *모델 응답*으로 재유출
4. 백업·이관 작업 중 압축 아카이브가 검색 인덱스에 노출

본 룰은 보안 카테고리를 `secret-scanning`으로 설정해 *주석 라인까지 검사*합니다 (일반 `kisa-secure-coding` 카테고리 룰은 Python `#` 주석 라인이 자동 억제됩니다). 의도된 분류입니다 — 본 룰의 *유일한 목적*이 주석 안 자격증명 탐지이기 때문입니다.

공공기관 운영 권고:
- pre-commit 훅에 `gvskb scan` + `detect-secrets`/`trufflehog` 등록
- 이미 노출된 자격증명은 즉시 *비밀번호 자체를 변경* (코드만 지우는 것으로는 불충분)
- 신규 자격증명은 환경변수·기관 secret manager로만 주입 (KISA-PY-SEC-06)

## 안전한 패턴 (가이드 원문 인용)
```python
def user_login(id, passwd):
    # 주석문에 포함된 민감한 정보는 삭제
    result = login(id, passwd)
    return result
```

자격증명은 *코드 밖*으로:
```python
import os
DB_PASSWORD = os.environ["DB_PASSWORD"]
ADMIN_API_KEY = os.environ["ADMIN_API_KEY"]

# 또는 pydantic-settings + SecretStr
from pydantic import SecretStr
from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    db_password: SecretStr
    admin_api_key: SecretStr
```

pre-commit 훅 예시 (`.pre-commit-config.yaml`):
```yaml
repos:
  - repo: local
    hooks:
      - id: gvskb-scan
        name: vibecode-checker scan
        entry: gvskb scan
        language: system
        types: [python]
```

## False positive 주의
- 본 룰은 한 줄 주석(`#`)만 검사합니다. docstring(`"""..."""`) 안 자격증명은 검출 범위 밖이지만 스캐너의 docstring 처리 로직과 별개로 *코드 리뷰 단계에서 반드시 검토*하세요.
- `# password validation policy: 10 chars minimum` 같이 자격증명이 아닌 *정책 설명* 주석은 매칭되지 않습니다. 본 룰은 `=` 또는 `:` 직후 *공백 없는 값*이 따라오는 형태만 잡으며, 위 예시처럼 값이 단어구로 이루어져 있으면 매칭이 약합니다.
- 다국어 / 한국어 자연어 주석(`# 사용자 인증 후 result 반환`)은 자격증명 키워드를 포함하더라도 `=` 또는 `:` 뒤 공백 없는 값 패턴이 없으면 매칭되지 않습니다.
- 의도된 예제 코드(README의 데모용 자격증명, 통합 테스트 픽스처)에서 매칭될 수 있습니다. 파일 단위 또는 라인 단위 `# gvskb: ignore KISA-PY-SEC-13`로 억제하세요.
