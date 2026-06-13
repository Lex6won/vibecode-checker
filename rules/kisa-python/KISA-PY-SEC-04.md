---
id: KISA-PY-SEC-04
title_ko: Python에서 취약한 암호화 알고리즘 사용 (MD5/SHA1/DES/RC4)
title_en: Use of weak cryptographic algorithm in Python (MD5/SHA1/DES/RC4)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제3절 4. 취약한 암호화 알고리즘 사용
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-37
cwe: [CWE-327]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [auth, data-pipeline, web-app]
related_baseline: [MOIS-49-SEC-04]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - 'hashlib\.(?:md5|sha1)\s*\('
    - "hashlib\\.new\\s*\\(\\s*[\"'](md5|sha1|md4)[\"']"
    - 'from\s+Crypto\.Cipher\s+import\s+(?:DES|ARC4|ARC2)'
    - 'Crypto\.Cipher\.(?:DES|ARC4|ARC2)\.new\s*\('
  category: kisa-secure-coding
  why_it_matters: >-
    MD5/SHA1은 충돌 공격이 실증되어 있고 DES/RC4는 키 길이·구조가 약해 더는
    안전하지 않습니다. 비밀번호, 전자서명, 토큰 무결성 등 보안 목적에 쓰면
    공공기관 정보보안 기본지침의 암호 적합성 요건을 위배합니다.
  public_sector_impact:
    - 비밀번호 충돌 공격
    - 전자서명 위조 가능성
    - 정보보안 기본지침 위배
  safe_fix: |
    해시: hashlib.sha256(...) 또는 SHA-3 계열.
    비밀번호: bcrypt, argon2-cffi, scrypt 사용 (해시 함수 단일 호출 금지).
    대칭키 암호: AES-256 GCM 또는 ChaCha20-Poly1305.
  references:
    - KISA Python 가이드 제3절 4
    - MOIS-49-SEC-04
    - CWE-327
    - 국정원 암호모듈 검증 정책
  can_auto_fix: false
examples:
  language: python
  positive:
    - "import hashlib\nhashlib.md5(b'x').hexdigest()"
    - "import hashlib\nhashlib.sha1(b'y').hexdigest()"
    - "import hashlib\nhashlib.new('md5')"
  negative:
    - "import hashlib\nhashlib.sha256(b'x').hexdigest()"
    - "import hashlib\nhashlib.sha3_256(b'y').hexdigest()"
---

## 무엇이 위험한가
MD5는 1996년부터 충돌 가능성이 알려졌고 SHA1은 2017년 SHAttered로 실제 충돌이 시연되었습니다. DES는 56비트 키 길이로 brute-force 가능, RC4도 IV 약점이 다수 알려져 있습니다.

## 안전한 패턴 (가이드 원문 인용)
```python
import hashlib
digest = hashlib.sha256(data).hexdigest()       # 무결성 해시
# 비밀번호는 단일 해시 금지 - bcrypt 등 KDF 사용
from passlib.hash import bcrypt
hashed = bcrypt.hash(password)
```

## False positive 주의
- 비암호 용도의 캐시 키 생성에 MD5를 쓰는 사례가 있으나, KISA·국정원 정책은 *암호 적합성 검증 통과 알고리즘만 허용*이므로 본 룰은 보안·비보안 용도를 구분하지 않고 warn으로 둡니다.
