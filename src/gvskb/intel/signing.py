"""위협정보 번들 전자서명 — Ed25519(RFC 8032), 검증은 **순수 파이썬**.

## 왜 서명인가

번들 반입은 파일별 sha256 을 전수 검증한다(bundle.py). 그것은 **손상**은 잡지만 **위조**는 못
잡는다 — 공유 폴더에 쓰기 권한이 있는 사람이 취약점 항목을 지운 번들을 놓으면, 해시는
그 번들에 맞게 다시 계산돼 있고 체커는 그것을 정상으로 받아 "깨끗하다"고 판정한다. 번들
내용은 공개 취약점 정보라 유출 위험은 없지만, 이 **독 넣기**가 실제 위험이다. 폐쇄망
자동 반입(망연계 → 공유 폴더 → 각 PC)을 켜려면 이 틈을 먼저 막아야 한다.

## 왜 공식 인증서가 아닌가

인증서는 "이 공개키가 정말 누구 것이다"를 **제3자**에게 증명하는 도구다. 여기서는 검증하는
쪽이 체커 자신이고, 공개키는 체커와 한 몸으로 배포된다. 체커 설치본을 믿는다면 그 안의
공개키도 믿는 것이라 제3자 증명이 끼어들 자리가 없다. 행정전자서명(GPKI)은 검증 서버
접속·갱신 주기 문제로 폐쇄망에서 오히려 불편하다. Sigstore 류 "키 없는" 서명도 검증에
인터넷이 필요해 맞지 않는다.

## 왜 순수 파이썬인가

검증은 비밀을 다루지 않는다(공개키 + 서명 + 메시지). 부채널 저항이 필요한 쪽은 **서명**
이고, 그것은 GitHub Actions(또는 관리자 PC) 한 곳에서만 일어난다. 그래서 체커에는
RFC 8032 §6 의 참조 구현을 그대로 둬 **새 의존성 없이** 폐쇄망 설치본이 검증할 수 있게
하고, 서명 역시 같은 구현으로 한다(하루 한 번이라 속도는 문제가 아니다). 정확성은 RFC
8032 §7.1 시험 벡터로 고정한다(tests/test_round46_bundle_signing.py).

## 무엇을 서명하나

``manifest.json`` 의 **바이트 그대로**. manifest 가 파일별 sha256 을 담고 있으므로 manifest 의
서명이 번들 전체를 덮는다. 서명 문서(``manifest.sig``)는 key_id 와 서명값만 신뢰 근거로
쓰고, 문서 안의 public_key 는 **참고용**이다 — 번들이 들고 온 공개키로 번들을 검증하면
위조자가 자기 키를 넣으면 그만이다. 공개키는 체커 안의 ``TRUSTED_PUBLIC_KEYS`` 와
기관이 환경변수로 더한 키만 인정한다.

## 운영 절차(관리자, 처음 한 번)

1. ``gvskb intel-bundle keygen --out intel-signing.key`` → 비밀키(seed) 파일 + 공개키 hex 출력
2. 비밀키 hex 를 GitHub 저장소 Secrets ``GVSKB_INTEL_SIGNING_KEY`` 에 등록, 파일 원본은 오프라인 보관
3. 공개키 hex 를 아래 ``TRUSTED_PUBLIC_KEYS`` 에 key_id 와 함께 추가해 배포(PR)
4. 키가 새면 새 쌍을 만들어 추가하고, 교체 기간이 지나면 옛 키를 지운다(여러 키 동시 허용)

정책: 서명이 **있으면 반드시 맞아야** 한다(틀리면 전체 거부). 서명이 없으면 기본은 허용하되
``signed=False`` 로 기록하고, ``GVSKB_INTEL_REQUIRE_SIGNATURE=1`` 이면 거부한다 — 운영 키를
배포한 뒤 기관이 이 값을 켜면 서명 없는 번들은 더 이상 들어오지 않는다.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timezone

SIG_ALG = "ed25519"
SIG_MEMBER = "manifest.sig"
ENV_REQUIRE_SIGNATURE = "GVSKB_INTEL_REQUIRE_SIGNATURE"
ENV_TRUSTED_KEYS = "GVSKB_INTEL_TRUSTED_KEYS"
ENV_SIGNING_KEY = "GVSKB_INTEL_SIGNING_KEY"

#: 체커가 신뢰하는 번들 서명 공개키 — ``key_id -> 32바이트 hex``.
#: 운영 키는 관리자가 keygen 뒤 PR 로 추가한다. 비밀키는 **절대** 저장소에 두지 않는다.
TRUSTED_PUBLIC_KEYS: dict[str, str] = {
    # 운영 키 1호(2026-11-02 생성, 관리자 PC 오프라인 보관). 비밀키는 GitHub Secrets GVSKB_INTEL_SIGNING_KEY.
    "gvskb-intel-2026a": "a6e1fa595f1444d81f07bcca5702d3281d82f675405cb3fd2b0874811ea1f8c5",
}

_TRUTHY = {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Ed25519 — RFC 8032 §6 참조 구현(확장 좌표). 외부 의존성 없음.
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = (-121665 * _inv(121666)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


def _sha512_modq(b: bytes) -> int:
    return int.from_bytes(_sha512(b), "little") % _Q


def _point_add(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    A = ((a[1] - a[0]) * (b[1] - b[0])) % _P
    B = ((a[1] + a[0]) * (b[1] + b[0])) % _P
    C = (2 * a[3] * b[3] * _D) % _P
    Dd = (2 * a[2] * b[2]) % _P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _point_mul(s: int, pt: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    acc = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            acc = _point_add(acc, pt)
        pt = _point_add(pt, pt)
        s >>= 1
    return acc


def _point_equal(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    if (a[0] * b[2] - b[0] * a[2]) % _P != 0:
        return False
    return (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * _inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _point_compress(pt: tuple[int, int, int, int]) -> bytes:
    zinv = _inv(pt[2])
    x = pt[0] * zinv % _P
    y = pt[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes) -> tuple[int, int, int, int] | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _secret_expand(secret: bytes) -> tuple[int, bytes]:
    if len(secret) != 32:
        raise ValueError("Ed25519 비밀키(seed)는 32바이트여야 합니다")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key_from_seed(secret: bytes) -> bytes:
    """32바이트 seed → 32바이트 공개키."""
    a, _ = _secret_expand(secret)
    return _point_compress(_point_mul(a, _G))


def ed25519_sign(secret: bytes, msg: bytes) -> bytes:
    """RFC 8032 Ed25519 서명(64바이트)."""
    a, prefix = _secret_expand(secret)
    A = _point_compress(_point_mul(a, _G))
    r = _sha512_modq(prefix + msg)
    Rs = _point_compress(_point_mul(r, _G))
    h = _sha512_modq(Rs + A + msg)
    s = (r + h * a) % _Q
    return Rs + int.to_bytes(s, 32, "little")


def ed25519_verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """RFC 8032 Ed25519 검증. 형식 오류는 예외가 아니라 False — 반입 경로는 거부로 이어진다."""
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public)
    if A is None:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = _sha512_modq(Rs + public + msg)
    sB = _point_mul(s, _G)
    hA = _point_mul(h, A)
    return _point_equal(sB, _point_add(R, hA))


# ---------------------------------------------------------------------------
# 키 · 정책
# ---------------------------------------------------------------------------

def generate_seed() -> bytes:
    """새 비밀키(seed) 32바이트 — OS CSPRNG."""
    return secrets.token_bytes(32)


def key_id_for(public: bytes) -> str:
    """공개키의 짧은 식별자 — sha256 앞 8 hex. 사람이 키를 구분하는 용도일 뿐 신뢰 근거가 아니다."""
    return hashlib.sha256(public).hexdigest()[:8]


def signature_required() -> bool:
    return os.environ.get(ENV_REQUIRE_SIGNATURE, "").strip().lower() in _TRUTHY


def trusted_keys() -> dict[str, bytes]:
    """체커 내장 키 + 기관이 환경변수로 더한 키(``id=hex,id2=hex``). 형식이 틀린 항목(길이·hex 오류)은 뺀다 — doctor 가 키 수를 보여 준다."""
    out: dict[str, bytes] = {}
    for kid, hx in TRUSTED_PUBLIC_KEYS.items():
        try:
            raw = bytes.fromhex(hx)
        except ValueError:
            continue
        if len(raw) == 32:
            out[kid] = raw
    raw_env = os.environ.get(ENV_TRUSTED_KEYS, "").strip()
    if raw_env:
        for part in raw_env.split(","):
            part = part.strip()
            if not part or "=" not in part:
                continue
            kid, hx = part.split("=", 1)
            try:
                raw = bytes.fromhex(hx.strip())
            except ValueError:
                continue
            if len(raw) == 32 and kid.strip():
                out[kid.strip()] = raw
    return out


def sign_manifest(manifest_bytes: bytes, seed: bytes, key_id: str | None = None) -> dict:
    """manifest 바이트에 대한 서명 문서(``manifest.sig`` 의 내용)."""
    public = public_key_from_seed(seed)
    return {
        "alg": SIG_ALG,
        "key_id": key_id or key_id_for(public),
        "public_key": public.hex(),          # 참고용 — 검증은 신뢰 키 목록으로만 한다
        "sig": ed25519_sign(seed, manifest_bytes).hex(),
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def verify_manifest(manifest_bytes: bytes, sig_doc: dict, keys: dict[str, bytes] | None = None) -> tuple[bool, str]:
    """(검증 성공, 사유). 성공 시 사유는 신뢰 목록의 ``key_id``.

    검증에 쓰는 공개키는 **항상 신뢰 목록의 바이트**다. key_id 가 목록과 다르면(운영자가
    CI 변수 GVSKB_INTEL_KEY_ID 를 빠뜨려 지문 id 로 서명된 경우 등) 문서 속 public_key 와
    **같은 바이트를 가진 신뢰 키**를 찾아 그 키로 검증한다 — 문서의 키를 믿는 것이 아니라
    목록에서 고르는 데만 쓰므로 위조자가 자기 키를 넣어도 통하지 않는다(검증 지적 HIGH-2).
    """
    keys = trusted_keys() if keys is None else keys
    if not isinstance(sig_doc, dict):
        return False, "서명 문서 형식 오류"
    if sig_doc.get("alg") != SIG_ALG:
        return False, f"지원하지 않는 서명 알고리즘: {sig_doc.get('alg')!r}"
    kid = str(sig_doc.get("key_id") or "")
    public = keys.get(kid)
    if public is None:
        try:
            embedded = bytes.fromhex(str(sig_doc.get("public_key") or ""))
        except ValueError:
            embedded = b""
        matched = [k for k, v in keys.items() if embedded and v == embedded]
        if not matched:
            return False, f"신뢰 목록에 없는 서명 키: {kid or '(key_id 없음)'}"
        kid = matched[0]
        public = keys[kid]
    try:
        sig = bytes.fromhex(str(sig_doc.get("sig") or ""))
    except ValueError:
        return False, "서명값 형식 오류"
    if ed25519_verify(public, manifest_bytes, sig):
        return True, kid
    return False, f"서명 불일치(key_id={kid}) — 위조·변조 의심"


def load_seed_hex(text: str) -> bytes:
    """keygen 이 만든 파일/환경변수의 hex → seed. 공백·줄바꿈 허용."""
    raw = bytes.fromhex("".join(text.split()))
    if len(raw) != 32:
        raise ValueError("서명 키는 32바이트(64 hex)여야 합니다")
    return raw
