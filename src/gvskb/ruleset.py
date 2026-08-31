"""룰셋 버전 고정 — 게이트의 제1 조건인 **재현성**을 만든다.

## 왜 필요한가

라운드 13에서 위치를 다시 정했다. *"소스는 보조, 의존성은 게이트"* — 그런데
게이트가 되려면 먼저 **어제 통과한 것이 오늘도 통과해야** 한다. 우리는 룰을
고치는 즉시 판정이 바뀌었고, 바뀐 사실이 어디에도 남지 않았다. 담당자 입장에서는
*"어제는 통과였는데 오늘 갑자기 차단"* 이고, 원인을 확인할 방법이 없다.

상용툴이 룰팩에 버전을 붙이고 기업이 그것을 핀하는 이유가 이것이다.

> **데이터(취약점 DB)는 매일, 로직(룰)은 드물게.**

취약점 DB 갱신으로 판정이 바뀌는 것은 *새 사실*이라 정당하다. 룰 로직이 바뀌어
판정이 달라지는 것은 *우리 쪽 사정*이라 반드시 드러나야 한다.

## 무엇을 지문에 넣는가

**판정을 바꾸는 필드만** 넣는다. `safe_fix` 문구를 다듬었다고 버전이 흔들리면
아무도 버전을 올리지 않게 되고, 그러면 이 장치 자체가 무의미해진다.

포함: id · status · severity · decision_default · languages · category ·
patterns · exclude_patterns · validators · flags · dedup_group · confidence
제외: 제목 · why_it_matters · safe_fix · references · 본문(문서)

**룰 단위로도 같은 원칙이 적용된다** — 지문은 **집행되는 룰(approved·stale)만**
덮는다. `proposed` 는 기본 미집행(초안), `deprecated` 는 절대 미집행이므로
이들을 넣으면 "판정이 하나도 안 바뀌었는데 버전이 움직이는" 반대 방향의
오류가 생긴다. 실측(2026-08-12~31): KEV 자동 초안 PR 이 지문을 움직여
`--fail-on error` 에 막히는 바람에 **지식 카드 유입이 19일간 정지**했다 —
자동 병합이 전제인 경로는 사람이 버전을 올릴 수 없다. 초안이 승격되어
`approved` 가 되는 순간 지문에 들어오고, 그때 사람이 버전을 올린다.
예외인 실험 모드(`GVSKB_ALLOW_PROPOSED=1`, 초안도 집행)는 보고서가
"이 판정은 승인 룰만으로 재현되지 않는다"를 스스로 밝힌다.

## 무엇을 보장하지 않는가

지문은 **룰**만 덮는다. 엔진 코드(`scanners/*.py`)가 바뀌어도 판정은 바뀐다.
그래서 판정을 재현하려면 **(engine_version, ruleset_version) 쌍**이 필요하고,
리포트는 둘 다 각인한다. 여기서 한쪽만 있으면 재현성이 있다고 착각하게 된다.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

LOCK_FILENAME = "RULESET.lock"

# 지문에 넣는 필드 — 여기 없는 것은 바뀌어도 버전이 움직이지 않는다.
_DIGEST_FIELDS = (
    "status", "severity", "decision_default", "languages", "category",
    "patterns", "exclude_patterns", "validators", "flags",
    "dedup_group", "confidence",
)

# 소비자가 "이 룰셋을 기대한다"고 선언하는 자리. 다르면 리포트가 크게 알린다.
EXPECT_ENV = "GVSKB_EXPECT_RULESET"


def _rule_fingerprint_payload(rule) -> dict:
    """한 룰에서 **판정에 쓰이는 것만** 뽑아 정규화한다.

    정렬·타입을 고정해야 같은 룰셋이 어느 기계에서든 같은 지문을 낸다.
    set 을 그대로 직렬화하면 순서가 흔들려 지문이 매번 달라진다(실제로 겪는
    함정이라 여기서 반드시 정렬한다).
    """
    det = rule.detection
    out: dict = {
        "id": rule.id,
        "status": str(getattr(rule.status, "value", rule.status) or ""),
        "severity": str(getattr(rule.severity, "value", rule.severity) or ""),
        "decision_default": str(
            getattr(rule.decision_default, "value", rule.decision_default) or ""
        ),
        "languages": sorted(str(x).lower() for x in (rule.languages or [])),
    }
    if det is None:
        out["detection"] = None
        return out
    out["detection"] = {
        "category": det.category or "",
        # 패턴은 **순서가 의미를 갖는다**(정규식 교체 순서). 정렬하지 않는다.
        "patterns": list(det.patterns or []),
        "exclude_patterns": list(det.exclude_patterns or []),
        "validators": sorted(det.validators or []),
        "flags": sorted(det.flags or []),
        "dedup_group": det.dedup_group or "",
        "confidence": str(getattr(det.confidence, "value", det.confidence) or ""),
    }
    return out


#: 지문에서 제외되는 상태 — 기본 모드에서 집행되지 않아 판정을 바꿀 수 없다
#: (regex_scanner 의 status 게이트와 1:1). 모르는 상태값은 보수적으로 포함한다.
_NON_ENFORCING_STATUSES = frozenset({"proposed", "deprecated"})


def _status_str(rule) -> str:
    return str(getattr(rule.status, "value", rule.status) or "")


def compute_digest(rules) -> str:
    """**집행되는** 룰(approved·stale)의 판정 지문(blake2b 16바이트 hex).

    `Rule` 객체 목록을 받는다. 순서에 흔들리지 않도록 id 로 정렬한다.
    proposed/deprecated 는 판정에 쓰이지 않으므로 지문 밖이다 — 초안 추가로
    버전이 움직이면 자동 초안 PR(intel·guide)이 영구히 드리프트에 막힌다.
    """
    payload = [
        _rule_fingerprint_payload(r) for r in rules
        if _status_str(r) not in _NON_ENFORCING_STATUSES
    ]
    payload.sort(key=lambda d: d["id"])
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.blake2b(blob.encode("utf-8"), digest_size=16).hexdigest()


# ---------------------------------------------------------------------------
# 잠금 파일 — "이 버전은 이 지문이다"를 저장소에 박제한다
# ---------------------------------------------------------------------------

def lock_path(rules_dir: Path) -> Path:
    return Path(rules_dir) / LOCK_FILENAME


def read_lock(rules_dir: Path) -> dict | None:
    """`RULESET.lock` 을 읽는다. 없거나 깨졌으면 None.

    의존성을 늘리지 않으려고 `key: value` 한 줄 형식만 쓴다 — 이 파일은
    사람이 읽고 CI 가 검사하는 세 줄짜리다.
    """
    p = lock_path(rules_dir)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return None
    out: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    if not out.get("version") or not out.get("digest"):
        return None
    return out


def write_lock(rules_dir: Path, *, version: str, digest: str, rule_count: int) -> Path:
    p = lock_path(rules_dir)
    p.write_text(
        "# 룰셋 잠금 파일 — 판정에 쓰이는 필드의 지문입니다.\n"
        "# 룰을 고치면 지문이 바뀝니다. 그때 `gvskb ruleset --bump <버전>` 으로\n"
        "# 이 파일을 갱신하세요. CI 가 지문 불일치를 ERROR 로 막습니다.\n"
        "# 문구(safe_fix·설명)만 고친 경우에는 지문이 움직이지 않습니다.\n"
        f"version: {version}\n"
        f"digest: {digest}\n"
        f"rule_count: {rule_count}\n",
        encoding="utf-8",
    )
    return p


def verify_lock(rules, rules_dir: Path) -> dict:
    """현재 룰셋이 잠금 파일과 일치하는가 → 판정·설명.

    반환: ``{"status": "ok"|"drift"|"missing", "version", "expected", "actual",
    "rule_count", "message"}``
    """
    actual = compute_digest(rules)
    lock = read_lock(rules_dir)
    if lock is None:
        return {
            "status": "missing",
            "version": None,
            "expected": None,
            "actual": actual,
            "rule_count": len(rules),
            "message": (
                f"룰셋 잠금 파일이 없습니다({lock_path(rules_dir)}). "
                "버전이 없으면 '어제 통과한 것이 오늘도 통과한다'를 보장할 수 없습니다. "
                "`gvskb ruleset --bump <버전>` 으로 만드세요."
            ),
        }
    if lock["digest"] == actual:
        return {
            "status": "ok",
            "version": lock["version"],
            "expected": lock["digest"],
            "actual": actual,
            "rule_count": len(rules),
            "message": f"룰셋 {lock['version']} (지문 {actual[:12]}…)",
        }
    return {
        "status": "drift",
        "version": lock["version"],
        "expected": lock["digest"],
        "actual": actual,
        "rule_count": len(rules),
        "message": (
            f"룰이 바뀌었는데 룰셋 버전이 그대로입니다(선언 {lock['version']}). "
            f"기대 지문 {lock['digest'][:12]}… · 실제 {actual[:12]}…. "
            "판정이 달라졌는데 그 사실이 결과 어디에도 남지 않는 상태입니다 — "
            "`gvskb ruleset --bump <새 버전>` 으로 갱신하세요."
        ),
    }


# ---------------------------------------------------------------------------
# 소비자 측 핀 — "나는 이 룰셋을 기대한다"
# ---------------------------------------------------------------------------

def expected_from_env() -> str | None:
    value = (os.environ.get(EXPECT_ENV) or "").strip()
    return value or None


def pin_mismatch(version: str | None, digest: str | None) -> str | None:
    """소비자가 핀한 룰셋과 실제가 다르면 설명을, 같거나 핀이 없으면 None.

    버전(`2026.08.1`)과 지문(hex) 어느 쪽으로도 핀할 수 있게 한다 —
    CI 설정에는 사람이 읽는 버전을, 엄격한 감사에는 지문을 쓴다.
    """
    expected = expected_from_env()
    if not expected:
        return None
    if expected in {version, digest}:
        return None
    if digest and digest.startswith(expected) and len(expected) >= 8:
        return None                      # 지문 앞자리로 핀한 경우 허용
    return (
        f"⚠ **고정한 룰셋과 다릅니다** — `{EXPECT_ENV}={expected}` 로 선언했는데 "
        f"실제로 사용된 것은 룰셋 {version or '(버전 미상)'}"
        f"(지문 {(digest or '?')[:12]}…)입니다. **이 결과는 고정한 기준으로 재현되지 "
        "않습니다.** 룰셋을 맞추거나, 기준을 새 버전으로 옮기세요."
    )
