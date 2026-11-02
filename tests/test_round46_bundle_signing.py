"""46차 — 위협정보 번들 전자서명(Ed25519, 순수 파이썬 검증).

sha256 전수 검증은 손상을 잡지만 위조는 못 잡는다. 공유 폴더 자동 반입(폐쇄망)을 켜기 전에
"누가 만들었나"를 번들이 증명해야 한다. 여기서는 (1) 구현이 RFC 8032 시험 벡터와 일치하고,
(2) 서명된 번들은 그대로 반입되며, (3) 내용을 바꾸고 해시를 다시 맞춘 번들(독 넣기)은
서명 때문에 거부되고, (4) 모르는 키·필수 정책이 의도대로 동작하는지를 고정한다.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from gvskb.intel import signing
from gvskb.intel.bundle import MANIFEST_NAME, export_bundle, import_bundle, verify_bundle
from gvskb.intel.cache import IntelCache
from gvskb.intel.signing import (
    SIG_MEMBER,
    ed25519_sign,
    ed25519_verify,
    key_id_for,
    public_key_from_seed,
    sign_manifest,
    verify_manifest,
)

# RFC 8032 §7.1 — TEST 1(빈 메시지) · TEST 2(1바이트)
_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", b"",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", bytes([0x72]),
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


@pytest.mark.parametrize("sk,pk,msg,sig", _VECTORS)
def test_rfc8032_vectors(sk: str, pk: str, msg: bytes, sig: str) -> None:
    seed = bytes.fromhex(sk)
    assert public_key_from_seed(seed).hex() == pk
    assert ed25519_sign(seed, msg).hex() == sig
    assert ed25519_verify(bytes.fromhex(pk), msg, bytes.fromhex(sig))
    assert not ed25519_verify(bytes.fromhex(pk), msg + b"x", bytes.fromhex(sig))
    sig_b = bytes.fromhex(sig)
    assert not ed25519_verify(bytes.fromhex(pk), msg, sig_b[:-1] + bytes([sig_b[-1] ^ 1]))   # 마지막 비트 반전


def test_malformed_inputs_are_false_not_exceptions() -> None:
    pub = public_key_from_seed(b"\x01" * 32)
    assert ed25519_verify(pub, b"m", b"short") is False
    assert ed25519_verify(b"\xff" * 32, b"m", b"\x00" * 64) is False
    assert ed25519_verify(pub[:-1], b"m", b"\x00" * 64) is False


def test_cross_check_with_cryptography_if_available() -> None:
    """독립 구현과 교차 검증 — 라이브러리가 없으면 건너뛴다(런타임 의존성으로 넣지 않는다)."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes_raw()
    pub = k.public_key().public_bytes_raw()
    msg = b"gvskb intel bundle"
    assert public_key_from_seed(seed) == pub
    assert ed25519_sign(seed, msg) == k.sign(msg)
    k.public_key().verify(ed25519_sign(seed, msg), msg)   # 라이브러리가 우리 서명을 받아들인다


# ---------------------------------------------------------------------------
# 번들 수준
# ---------------------------------------------------------------------------

_SEED = bytes(range(32))
_PUB = public_key_from_seed(_SEED)
_KID = "test-key"


def _seed_cache(cache_dir: Path) -> None:
    cache = IntelCache(cache_dir)
    cache.save("osv-malicious", "https://example/osv", [
        {"id": "MAL-1", "affected": [{"package": "evil", "ecosystem": "PyPI"}]},
    ], ecosystems=["PyPI"])
    cache.save("cisa-kev", "https://example/kev", [{"cveID": "CVE-2026-0001"}])


@pytest.fixture
def trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(signing, "TRUSTED_PUBLIC_KEYS", {_KID: _PUB.hex()})
    monkeypatch.delenv(signing.ENV_TRUSTED_KEYS, raising=False)
    monkeypatch.delenv(signing.ENV_REQUIRE_SIGNATURE, raising=False)


def test_signed_bundle_roundtrip(tmp_path: Path, trusted: None) -> None:
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    exp = export_bundle(bundle, cache_dir=src, sign_seed=_SEED, key_id=_KID)
    assert exp["ok"] and exp["signed"] and exp["key_id"] == _KID
    with zipfile.ZipFile(bundle) as zf:
        assert SIG_MEMBER in zf.namelist()
        doc = json.loads(zf.read(SIG_MEMBER))
        assert doc["alg"] == "ed25519" and doc["key_id"] == _KID

    v = verify_bundle(bundle)
    assert v["ok"] and v["signed"] and v["key_id"] == _KID
    imp = import_bundle(bundle, cache_dir=tmp_path / "dst")
    assert imp["ok"] and imp["signed"] and imp["key_id"] == _KID
    assert IntelCache(tmp_path / "dst").load("cisa-kev") is not None


def test_poisoned_bundle_with_recomputed_hashes_is_rejected_by_signature(tmp_path: Path, trusted: None) -> None:
    """핵심 시나리오 — 공유 폴더에 쓰기 권한이 있는 사람이 항목을 지우고 해시를 다시 맞춘 번들."""
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    assert export_bundle(bundle, cache_dir=src, sign_seed=_SEED, key_id=_KID)["ok"]

    poisoned = tmp_path / "poisoned.zip"
    with zipfile.ZipFile(bundle) as zin:
        manifest = json.loads(zin.read(MANIFEST_NAME))
        members = {i.filename: zin.read(i.filename) for i in zin.infolist()}
    # 악성 항목을 '없음'으로 바꾸고(캐시 envelope 의 sha256 도 맞춰 준다), manifest 의 파일 해시도 다시 계산한다.
    env = json.loads(members["caches/osv-malicious.json"])
    env["items"] = []
    env["item_count"] = 0
    env["sha256"] = hashlib.sha256(json.dumps([], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    new_bytes = json.dumps(env, ensure_ascii=False).encode("utf-8")
    members["caches/osv-malicious.json"] = new_bytes
    for f in manifest["files"]:
        if f["source_id"] == "osv-malicious":
            f["sha256"] = hashlib.sha256(new_bytes).hexdigest()
            f["size"] = len(new_bytes)
    members[MANIFEST_NAME] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    with zipfile.ZipFile(poisoned, "w") as zout:
        for name, data in members.items():
            zout.writestr(name, data)

    # 해시만 보는 검사는 통과했을 번들이다. 서명이 막는다.
    res = import_bundle(poisoned, cache_dir=tmp_path / "dst")
    assert res["ok"] is False
    assert "서명" in res["error"] and "위조" in res["error"]
    assert not (tmp_path / "dst").exists() or not list((tmp_path / "dst").glob("*.json"))


def test_bundle_signed_by_unknown_key_is_rejected(tmp_path: Path, trusted: None) -> None:
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    other = bytes([7] * 32)
    assert export_bundle(bundle, cache_dir=src, sign_seed=other, key_id="rogue")["ok"]
    res = import_bundle(bundle, cache_dir=tmp_path / "dst")
    assert res["ok"] is False and "신뢰 목록에 없는" in res["error"]


def test_embedded_public_key_is_not_trusted_by_itself(tmp_path: Path, trusted: None) -> None:
    """번들이 들고 온 public_key 로는 검증하지 않는다 — key_id 가 신뢰 목록에 있어야 한다."""
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    other = bytes([9] * 32)
    # 신뢰 key_id 를 사칭하되 다른 키로 서명
    assert export_bundle(bundle, cache_dir=src, sign_seed=other, key_id=_KID)["ok"]
    res = import_bundle(bundle, cache_dir=tmp_path / "dst")
    assert res["ok"] is False and "서명 불일치" in res["error"]


def test_unsigned_bundle_allowed_by_default_but_recorded(tmp_path: Path, trusted: None) -> None:
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    assert export_bundle(bundle, cache_dir=src)["signed"] is False
    res = import_bundle(bundle, cache_dir=tmp_path / "dst")
    assert res["ok"] is True and res["signed"] is False and "서명 없음" in res["signature"]


def test_unsigned_bundle_rejected_when_policy_requires(tmp_path: Path, trusted: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(signing.ENV_REQUIRE_SIGNATURE, "1")
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    assert export_bundle(bundle, cache_dir=src)["ok"]
    res = import_bundle(bundle, cache_dir=tmp_path / "dst")
    assert res["ok"] is False and "서명 없는 번들" in res["error"]
    # 서명된 번들은 정책이 켜져도 들어온다.
    signed = tmp_path / "s.zip"
    assert export_bundle(signed, cache_dir=src, sign_seed=_SEED, key_id=_KID)["ok"]
    assert import_bundle(signed, cache_dir=tmp_path / "dst2")["ok"] is True


def test_org_keys_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """기관이 자체 키로 서명한 번들 — 체커를 고치지 않고 환경변수로 공개키를 더한다."""
    monkeypatch.setattr(signing, "TRUSTED_PUBLIC_KEYS", {})
    monkeypatch.setenv(signing.ENV_TRUSTED_KEYS, f"gg-2026={_PUB.hex()}, broken=zz")
    keys = signing.trusted_keys()
    assert keys == {"gg-2026": _PUB}
    src = tmp_path / "src"
    _seed_cache(src)
    bundle = tmp_path / "b.zip"
    assert export_bundle(bundle, cache_dir=src, sign_seed=_SEED, key_id="gg-2026")["ok"]
    assert import_bundle(bundle, cache_dir=tmp_path / "dst")["signed"] is True


def test_sign_and_verify_manifest_helpers() -> None:
    doc = sign_manifest(b"{}", _SEED)
    assert doc["key_id"] == key_id_for(_PUB) and doc["public_key"] == _PUB.hex()
    ok, why = verify_manifest(b"{}", doc, {doc["key_id"]: _PUB})
    assert ok and why == doc["key_id"]
    ok, why = verify_manifest(b"{} ", doc, {doc["key_id"]: _PUB})
    assert not ok and "불일치" in why
    ok, why = verify_manifest(b"{}", {"alg": "rsa"}, {})
    assert not ok and "알고리즘" in why


def test_autopull_from_shared_folder_rejects_poisoned_signed_bundle(tmp_path: Path, trusted: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """공유 폴더 자동 반입 경로도 같은 검증을 탄다 — 서명이 틀린 번들은 캐시를 바꾸지 못한다."""
    from gvskb.intel import autopull

    src = tmp_path / "src"
    _seed_cache(src)
    share = tmp_path / "share"
    share.mkdir()
    rogue = bytes([3] * 32)
    assert export_bundle(share / "bundle.zip", cache_dir=src, sign_seed=rogue, key_id=_KID)["ok"]
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("GVSKB_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("GVSKB_INTEL_DIR", str(share))
    monkeypatch.setenv("GVSKB_MODE", "offline")
    monkeypatch.delenv("GVSKB_AUTO_UPDATE", raising=False)
    res = autopull.maybe_auto_update(cache_dir=cache_dir, force=True, verbose=False)
    assert res.ok is False and "서명" in res.error
    # 상태 파일(.autopull-state.json)은 남아도 된다 — 위협정보 캐시 파일이 없어야 한다.
    assert not [q for q in cache_dir.glob("*.json") if not q.name.startswith(".")] if cache_dir.exists() else True
