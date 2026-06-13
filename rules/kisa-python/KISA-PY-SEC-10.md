---
id: KISA-PY-SEC-10
title_ko: Python 부적절한 전자서명 확인 - 서명 검증 없이 다운로드/복호화한 코드 실행
title_en: Improper digital signature verification in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 10. 부적절한 전자서명 확인
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-50
cwe: [CWE-347]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline]
related_baseline: [MOIS-49-SEC-10]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) 복호화 결과를 서명 검증 없이 즉시 eval/exec — KISA 가이드 원문 취약 예시
    - "(?:eval|exec)\\s*\\(\\s*(?:origin_python_code|decrypted|decoded|payload|plain(?:text)?|decrypt[a-z_]*)\\b"
    - "(?:eval|exec)\\s*\\(\\s*(?:decrypt_with_symmetric_key|aes_decrypt|rsa_decrypt|cipher\\.decrypt)\\s*\\("
    # 2) 해시값 단순 비교로 서명 검증 대체 (== 비교 — timing attack + 서명체계 미사용)
    - "hashlib\\.(?:sha256|sha384|sha512|md5|sha1)\\s*\\([^)]*\\)\\.(?:hexdigest|digest)\\s*\\(\\s*\\)\\s*=="
    - "==\\s*hashlib\\.(?:sha256|sha384|sha512|md5|sha1)\\s*\\("
    # 3) 서명/검증 API의 verify 비활성화 (PyJWT 등)
    - "jwt\\.decode\\s*\\([^)]*verify\\s*=\\s*False"
    - "jwt\\.decode\\s*\\([^)]*options\\s*=\\s*\\{[^}]*['\"]verify_signature['\"]\\s*:\\s*False"
    # 4) PKCS1 / RSA 서명 객체를 만들지 않고 raw 데이터 신뢰
    - "PKCS1_v1_5\\.new\\s*\\([^)]*\\)\\.verify\\s*\\([^)]*,\\s*None\\s*\\)"
  category: kisa-secure-coding
  why_it_matters: >-
    KISA 가이드의 안전하지 않은 예시는 클라이언트가 보낸 *암호화된 파이썬 코드*를
    대칭키로 복호한 뒤 *전자서명 검증 없이* `eval(origin_python_code)` 합니다.
    공격자가 대칭키만 알아내거나 중간자 공격으로 코드를 *원하는 어떤 것으로든*
    바꾸면 서버에서 임의 코드가 실행됩니다. 해시값을 그냥 `==` 비교하는 방식도
    안전하지 않습니다 — 해시 자체를 변조할 수 있고, 타이밍 공격에 노출되며,
    *공개키 기반 서명체계*가 없으면 송신자 진위를 증명할 수 없습니다. RSA-PSS,
    Ed25519, PyCryptodome의 PKCS1_v1_5/PKCS1_PSS 같은 *서명 객체의 verify
    메서드*를 사용해야 하고, JWT는 `options={"verify_signature": False}` 같은
    옵션을 *절대* 켜면 안 됩니다.
  public_sector_impact:
    - 서버 RCE — 행정 서버에서 임의 명령 실행
    - 공급망 공격으로 행정 패치/업데이트가 위·변조된 채 배포
    - 행정전자서명 인증 체계의 무결성 신뢰 훼손
  safe_fix: |
    PyCryptodome — RSA + SHA256 PKCS1_v1_5 서명 검증:
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        from Crypto.Signature import PKCS1_v1_5 as SIGNATURE_PKCS1_v1_5
        import base64

        def verify_digit_signature(origin_data: bytes, origin_signature: bytes,
                                   client_pub_key: str) -> bool:
            hashed_data = SHA256.new(origin_data)
            signer = SIGNATURE_PKCS1_v1_5.new(RSA.importKey(client_pub_key))
            return signer.verify(hashed_data, base64.b64decode(origin_signature))

        # 검증 통과 후에만 eval/exec
        if verify_digit_signature(origin_python_code, origin_signature, client_pub_key):
            eval(origin_python_code)
        else:
            raise SecurityError("전자서명 검증 실패")
    JWT는 명시적 알고리즘과 키를 지정:
        jwt.decode(token, public_key, algorithms=["RS256"])     # OK
        # jwt.decode(token, options={"verify_signature": False}) 절대 금지
    가능하면 원격 코드 실행 자체를 피하고, 코드 서명된 파이썬 패키지(.whl)
    + pip --require-hashes 로 대체하세요 (KISA-PY-SEC-15 참고).
  references:
    - KISA Python 가이드 제2절 10
    - MOIS-49-SEC-10
    - CWE-347 Improper Verification of Cryptographic Signature
    - NIST SP 800-89 Security Considerations for Code Signing
    - https://www.pycryptodome.org/src/signature/signature
    - https://pyjwt.readthedocs.io/en/stable/usage.html
  can_auto_fix: false
examples:
  language: python
  positive:
    - "origin_python_code = decrypt_with_symmetric_key(secret_key, encrypted_code)\neval(origin_python_code)"
    - "exec(decrypt_with_symmetric_key(key, payload))"
    - "if hashlib.sha256(data).hexdigest() == client_hash: trust(data)"
    - "payload = jwt.decode(token, verify=False)"
    - "jwt.decode(token, options={'verify_signature': False})"
  negative:
    - "if verify_digit_signature(code, sig, pub_key):\n    eval(code)"
    - "payload = jwt.decode(token, public_key, algorithms=['RS256'])"
    - "signer = PKCS1_v1_5.new(RSA.importKey(pub_key))\nif signer.verify(SHA256.new(data), b64decode(sig)):\n    process(data)"
    - "import hmac\nif hmac.compare_digest(expected_sig, received_sig):\n    process(data)"
---

## 무엇이 위험한가
전자서명은 *원문 해시를 송신자의 개인키로 암호화*해 함께 전송하는 메커니즘입니다. 수신자는 송신자의 *공개키*로 그 서명을 풀어 자신이 직접 계산한 원문 해시와 비교하여 (1) 원문이 변조되지 않았음과 (2) 송신자가 진짜 그 사람임을 동시에 증명합니다. KISA 가이드의 안전하지 않은 예시는 이 두 단계 중 *둘 다 생략*합니다 — 대칭키로 복호한 코드를 그대로 `eval()` 합니다.

위험 시나리오는 분명합니다:
- 대칭키 탈취 시 공격자는 *원하는 파이썬 코드*를 정상 메시지처럼 위장해 보낼 수 있다 → 서버 RCE
- 중간자(MITM)가 패킷을 가로채 페이로드를 통째로 바꿔도 수신측은 변조를 인지하지 못한다
- 단순 해시 비교(`hash1 == hash2`)는 *해시 자체도 함께 전송*되어야 하는 문제가 있어 변조 검증에 쓸 수 없다 (해시도 같이 위조됨)

공공기관에서는 행정 시스템 간 데이터 교환·자동 업데이트·플러그인 설치 경로에서 *반드시* 공개키 서명체계(PKI, 행정전자서명, 코드 사이닝 인증서)를 사용해야 하며, 검증 실패 시 *즉시 거부*해야 합니다. `jwt.decode(token, verify=False)` 처럼 검증을 끄는 옵션은 *어떤 환경에서도* 금지입니다 (테스트도 별도 서명키로).

## 안전한 패턴 (가이드 원문 인용)
```python
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5 as SIGNATURE_PKCS1_v1_5

# 가이드 안전 예시: 공개키로 RSA+SHA256 서명 검증
def verify_digit_signature(
    origin_data: bytes,
    origin_signature: bytes,
    client_pub_key: str,
) -> bool:
    hashed_data = SHA256.new(origin_data)
    signer = SIGNATURE_PKCS1_v1_5.new(RSA.importKey(client_pub_key))
    return signer.verify(hashed_data, base64.b64decode(origin_signature))


def verify_data(request):
    encrypted_code = request.POST.get("encrypted_msg", "")
    encrypted_sig = request.POST.get("encrypted_sig", "")

    with open("/keys/secret_key.out", "rb") as f:
        secret_key = f.read()
    with open("/keys/public_key.out", "rb") as f:
        public_key = f.read()

    origin_python_code = decrypt_with_symmetric_key(secret_key, encrypted_code)
    origin_signature = decrypt_with_symmetric_key(secret_key, encrypted_sig)

    # 전자서명 검증을 통과했을 때만 실행
    if verify_digit_signature(origin_python_code, origin_signature, public_key):
        eval(origin_python_code)
        return render(request, "/verify_success.html",
                      {"result": "전자서명 검증 통과 및 파이썬 코드를 실행했습니다."})
    else:
        return render(request, "/verify_failed.html",
                      {"result": "전자서명 또는 파이썬 코드가 위/변조되었습니다."})
```

JWT는 *알고리즘과 공개키를 명시*해야 안전합니다:
```python
import jwt
payload = jwt.decode(token, public_key, algorithms=["RS256"])  # OK
# 절대 금지:
# jwt.decode(token, options={"verify_signature": False})
# jwt.decode(token, verify=False)
```

해시 비교가 *불가피한* 경우(미리 등록된 정적 해시와 비교 등)는 타이밍 공격을 막기 위해 `hmac.compare_digest`를 사용하세요:
```python
import hmac
if hmac.compare_digest(expected_sha256, received_sha256):
    ...
```

## False positive 주의
- 본 룰은 `eval(decrypt_*(...))` 또는 `eval(origin_python_code)` 같은 *복호화 결과의 직접 실행* 패턴을 잡습니다. 검증 함수를 거친 변수명을 사용하면 (`if verify_signature(...): eval(code)`) 매칭되지 않습니다.
- `hashlib.sha256(...).hexdigest() == client_hash` 패턴은 *서명 검증 대용으로* 흔히 잘못 쓰이는 코드입니다. 의도적으로 매칭 대상에 포함했으며, 정적 화이트리스트 해시 비교 (예: 패키지 무결성 검사)라도 `hmac.compare_digest` 사용을 권장하므로 그대로 두는 편이 안전합니다.
- `jwt.decode(token, key, algorithms=[...])` 정상 호출은 매칭되지 않습니다 — 본 룰은 `verify=False` 또는 `verify_signature: False` 옵션만 잡습니다.
- 테스트 코드에서 만료된 토큰을 강제로 디코딩해야 하는 경우 `options={"verify_exp": False}` 처럼 *서명은 유지*하고 다른 검증만 끄세요. 본 룰은 `verify_signature` 비활성화만 차단합니다.
