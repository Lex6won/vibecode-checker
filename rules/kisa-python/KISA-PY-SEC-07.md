---
id: KISA-PY-SEC-07
title_ko: Python 충분하지 않은 키 길이 사용 (RSA<2048 / ECC<224 / AES<128)
title_en: Insufficient key length in Python crypto (RSA<2048 / ECC<224 / AES<128)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 7. 충분하지 않은 키 길이 사용
  - publisher: 한국인터넷진흥원
    document: 암호 알고리즘 및 키 길이 이용 안내서
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-40
cwe: [CWE-326]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [auth, data-pipeline, web-app]
related_baseline: [MOIS-49-SEC-07]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - 'RSA\.generate\s*\(\s*(?:512|1024|2047)\b'
    - 'DSA\.generate\s*\(\s*(?:512|1024|2047)\b'
    - 'rsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(?:512|1024|2047)\b'
    - "registry\\.get_curve\\s*\\(\\s*['\"](?:secp112r1|secp112r2|secp128r1|secp128r2|secp160[krk]1|secp192[kr]1|prime192v[123])['\"]"
    - "ec\\.SECP192R1\\s*\\(\\s*\\)"
    - 'Crypto\.Random\.get_random_bytes\s*\(\s*(?:8|16)\s*\).{0,40}AES'
  category: kisa-secure-coding
  why_it_matters: >-
    검증된 알고리즘이라도 키 길이가 짧으면 보안강도가 무너집니다. KISA
    *암호 알고리즘 및 키 길이 이용 안내서*는 2030년 이후 RSA/DSA 최소
    2048비트, ECC 224비트, 대칭키 128비트를 요구합니다. AI 코딩 도우미가
    예전 예제(`RSA.generate(1024)`, `secp192r1`)를 그대로 권하는 경우가
    많아 더 위험합니다.
  public_sector_impact:
    - 전자서명·키 교환 위·변조
    - 공공기관 암호모듈 검증 정책(국정원) 위배
    - 장기 보관 데이터(주민등록·의료) 미래 복호 위험
  safe_fix: |
    RSA/DSA: 최소 2048비트, 장기 보관은 3072비트 이상.
        RSA.generate(2048)
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ECC: 최소 secp224r1, 가능하면 secp256r1/ed25519.
        registry.get_curve('secp256r1')
    대칭키: 최소 128비트(권장 256), GCM/ChaCha20-Poly1305 등 AEAD 모드 사용.
        AESGCM.generate_key(bit_length=256)
  references:
    - KISA Python 가이드 제2절 7
    - 암호 알고리즘 및 키 길이 이용 안내서 (KISA)
    - MOIS-49-SEC-07
    - CWE-326
    - NIST SP 800-57 Part 1
  can_auto_fix: false
examples:
  language: python
  positive:
    - "from Crypto.PublicKey import RSA\nprivate_key = RSA.generate(1024)"
    - "from Crypto.PublicKey import DSA\nDSA.generate(1024)"
    - "from tinyec import registry\nec_curve = registry.get_curve('secp192r1')"
  negative:
    - "from Crypto.PublicKey import RSA\nprivate_key = RSA.generate(2048)"
    - "from tinyec import registry\nec_curve = registry.get_curve('secp256r1')"
    - "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=3072)"
---

## 무엇이 위험한가
짧은 키는 *알고리즘이 깨진 게 아니라*, 무차별 대입 비용이 현실적인 수준으로 떨어진 것입니다. 1024비트 RSA는 2010년대 중반 이미 *국가 단위 자원*으로 복원 가능했고, 2030년이면 *개인이 빌릴 수 있는 클라우드 자원*으로도 위협이 됩니다. 공공기관 데이터는 보관 기간이 길어 *오늘 안전해 보이는 키*가 10년 후 깨질 수 있습니다.

## 안전한 패턴 (가이드 원문 인용)
```python
# RSA: 최소 2048, 권장 3072 이상
from Crypto.PublicKey import RSA
private_key = RSA.generate(2048)

# 또는 cryptography 라이브러리
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

# ECC: 최소 secp224r1, 권장 secp256r1 / Ed25519
from tinyec import registry
ec_curve = registry.get_curve('secp256r1')

# 대칭키: AES-256-GCM 권장
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
```

## False positive 주의
- 마지막 패턴은 `get_random_bytes(8/16)` 직후 동일 줄에 `AES`가 등장하는 경우에만 매칭됩니다(예: nonce 길이 8/16). nonce를 별도 줄에서 생성하면 매칭되지 않습니다.
- HMAC/HKDF에서 *원래 짧아도 되는* 솔트·IV 생성에는 본 룰을 적용하지 마세요. 본 룰의 의도는 *암호화 키 자체*의 길이입니다.
- `RSA.generate(2048)` 처럼 안전 길이는 패턴이 제외하므로 매칭되지 않습니다.
