---
id: KISA-PY-SEC-14
title_ko: Python 솔트 없이 일방향 해시 함수로 비밀번호 저장
title_en: Password hashed without salt or proper KDF in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 14. 솔트 없이 일방향 해시 함수 사용
cwe: [CWE-759, CWE-916]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [auth]
related_baseline: [MOIS-49-SEC-14]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "hashlib\\.(?:sha256|sha384|sha512|md5|sha1)\\s*\\(\\s*(?:password|passwd|pwd|비밀번호|암호)"
    - "hashlib\\.(?:sha256|sha384|sha512|md5|sha1)\\s*\\(\\s*(?:request|input)\\.(?:get|form)\\s*\\([^)]*(?:password|pwd)"
  # 같은 코드를 다른 각도로 보는 룰과 한 묶음(KISA-PY-SEC-04). 같은 줄에 함께 걸리면
  # 가장 확실한 엔진의 발견 하나만 남고 나머지는 also_matched 로 합쳐진다(개선요청 #34 C).
  dedup_group: password-hashing
  category: kisa-secure-coding
  why_it_matters: >-
    `hashlib.sha256(password.encode()).hexdigest()`처럼 솔트 없는 단일 해시는
    rainbow table·GPU brute-force에 수 분 안에 깨집니다. 비밀번호는 *KDF*
    (key derivation function — bcrypt·argon2·scrypt)로만 저장해야 합니다.
  public_sector_impact:
    - 비밀번호 데이터베이스 유출 시 즉시 전수 복호
    - 동일 비밀번호 사용 사용자 다수 피해
    - 개인정보보호법 안전성 확보 조치 위반
  safe_fix: |
    bcrypt 또는 argon2-cffi를 사용하세요. 둘 다 솔트·반복 횟수를 내장합니다.
    from passlib.hash import bcrypt
    hashed = bcrypt.hash(password)             # 저장
    bcrypt.verify(input_password, hashed)      # 검증
  references:
    - KISA Python 가이드 제3절 14
    - MOIS-49-SEC-14
    - CWE-759, CWE-916
    - OWASP ASVS V6.2
  can_auto_fix: false
examples:
  language: python
  positive:
    - "stored = hashlib.sha256(password.encode()).hexdigest()"
    - "stored = hashlib.md5(pwd.encode()).hexdigest()"
  negative:
    - "stored = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
    - "stored = hashlib.pbkdf2_hmac(\"sha256\", password.encode(), salt, 200000)"
---

## 무엇이 위험한가
SHA-256은 *빠른* 해시 함수입니다. 비밀번호 저장에는 *느린* KDF가 필요합니다. 솔트가 없으면 같은 비밀번호의 사용자가 같은 해시 → 일괄 공격 가능.

## 안전한 패턴
```python
from passlib.hash import bcrypt, argon2

hashed = bcrypt.hash(password)
# 또는
hashed = argon2.hash(password)

# 검증
bcrypt.verify(input_password, hashed)
```
