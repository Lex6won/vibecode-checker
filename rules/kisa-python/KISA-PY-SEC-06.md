---
id: KISA-PY-SEC-06
title_ko: Python 하드코드된 중요정보 - 비밀번호·DB 접속·서명키 리터럴
title_en: Hardcoded credentials in Python source
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제3절 6. 하드코드된 중요정보
cwe: [CWE-798, CWE-259]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline, auth]
related_baseline: [MOIS-49-SEC-06, GOV-SECRET-APIKEY-001]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "(?i)(?:password|passwd|pwd|비밀번호|암호)\\s*=\\s*['\"][^'\"\\s$\\{]{4,}['\"]"
    - "(?i)(?:secret|secret_key|signing_key|jwt_secret)\\s*=\\s*['\"][^'\"\\s$\\{]{8,}['\"]"
    - "(?i)(?:db_pass|db_password|database_password)\\s*=\\s*['\"][^'\"\\s$\\{]{4,}['\"]"
    - "(?:postgres|mysql|mongodb)://[^:]+:[^@]+@"
  category: secret-scanning
  why_it_matters: >-
    소스에 박힌 비밀번호·DB 접속정보·서명키는 git 이력·LLM 학습 데이터·CI
    로그 어디로든 새어 나갈 수 있습니다. 한국어 변수명(`비밀번호`, `암호`)
    역시 마찬가지로 흔히 노출됩니다.
  public_sector_impact:
    - 행정 시스템 계정 탈취
    - DB 무단 접근
    - 외부 API 토큰 비용 폭발
  safe_fix: |
    환경변수, OS keyring, 기관 secret manager(Vault, AWS Secrets Manager 등)를
    사용하세요. 한국어 변수명도 동일 원칙 적용.
    password = os.environ["DB_PASSWORD"]
    또는 pydantic-settings의 SecretStr 활용.
  references:
    - KISA Python 가이드 제3절 6
    - MOIS-49-SEC-06
    - CWE-798
    - NIST SSDF PW.4
  can_auto_fix: false
examples:
  language: python
  positive:
    - "password = \"hunter2plus9\""
    - "JWT_SECRET = \"H3xK9mQ2pR7sT1uV5wY8zC4d\""
    - "DB_PASSWORD = \"p9x2mQ7r\""
  negative:
    - "password = os.environ[\"DB_PASSWORD\"]"
    - "JWT_SECRET = os.getenv(\"JWT_SECRET\")"
---

## 무엇이 위험한가
git에 한 번 들어간 비밀은 *영원히* 노출된다고 봐야 합니다 (history rewrite는 협업에서 거의 불가능). 한국어 변수명으로 위장해도 마찬가지입니다.

## 안전한 패턴
```python
import os
password = os.environ["DB_PASSWORD"]
secret_key = os.environ["JWT_SECRET"]

# 또는 pydantic-settings
from pydantic import SecretStr
from pydantic_settings import BaseSettings
class Cfg(BaseSettings):
    db_password: SecretStr
```
