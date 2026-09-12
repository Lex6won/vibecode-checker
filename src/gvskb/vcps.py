"""VCPS(패키지 안전 사용 지침) 정책 로더 — 지침의 기계 규칙을 집행 설정으로.

VCPS-2026-01 지침 문서의 rules 블록(사본: ``config/vcps-rules.yaml``)에서
실행환경(E0~E2)별 쿨다운 기준일과 라이선스 허용목록을 읽는다. 기관은
``GVSKB_VCPS_RULES`` 환경변수로 자체 정책 파일을 지정할 수 있다(기관 정책팩).

설계 원칙:
- 파일이 없거나 깨져도 **내장 기본값으로 동작한다** — 정책 로드 실패가 검사를
  막으면 안 된다(단, stderr 경고 1줄).
- E3(대민·개인정보)는 의도적으로 없다 — 바이브 코딩 대상이 아니므로 등급
  파라미터 자체가 받지 않는다.
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from importlib import resources
from pathlib import Path

import yaml

# 내장 기본값 — config/vcps-rules.yaml 과 동일 내용(파일 유실 대비 최후 방어선).
_DEFAULTS: dict = {
    "environments": {
        "E0": {"label": "개인PC 일회성", "cooldown_days": 3},
        "E1": {"label": "개인PC 반복도구", "cooldown_days": 7},
        "E2": {"label": "내부서버 공용", "cooldown_days": 14},
    },
    "default_env": "E1",
    "license_allowlist": [
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "PSF-2.0",
    ],
    "license_review_required": [
        "GPL-2.0", "GPL-3.0", "AGPL-3.0", "BSL-1.1", "SSPL-1.0",
    ],
}

VALID_ENV_GRADES = ("E0", "E1", "E2")


def _resolve_config_path() -> Path:
    override = os.environ.get("GVSKB_VCPS_RULES")
    if override:
        return Path(override)
    pkg_root = Path(__file__).resolve().parent
    project_root = pkg_root.parent.parent
    repo = project_root / "config" / "vcps-rules.yaml"
    if repo.exists():
        return repo
    return Path(str(resources.files("gvskb").joinpath("config", "vcps-rules.yaml")))


@lru_cache(maxsize=1)
def load_vcps_config() -> dict:
    """정책 설정을 로드한다(1회 캐시). 실패 시 내장 기본값 + stderr 경고."""
    path = _resolve_config_path()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        print(f"[gvskb] ⚠ VCPS 정책 파일을 읽지 못해 내장 기본값을 씁니다({path}): {exc}", file=sys.stderr)
        return dict(_DEFAULTS)
    merged = dict(_DEFAULTS)
    for key in ("environments", "default_env", "license_allowlist", "license_review_required"):
        if key in data and data[key]:
            merged[key] = data[key]
    return merged


def normalize_env_grade(env_grade: str | None) -> str | None:
    """등급 표기를 정규화한다(공백·대소문자).

    ``"e2"`` 는 목록에 없는 값으로 취급돼 조용히 기본 등급으로 떨어졌다. 등급은
    판정 기준을 바꾸는 값이라, 표기 차이로 기준이 달라지면 안 된다.
    """
    if env_grade is None:
        return None
    text = str(env_grade).strip().upper()
    return text or None


def env_grade_supported(env_grade: str | None) -> bool:
    """이 등급을 체커가 판정할 수 있는가.

    ``None``(미지정)은 기본 등급을 쓰겠다는 뜻이므로 지원 대상이다. 반대로
    ``E3`` 처럼 **의도적으로 지원하지 않는** 등급과, 오타 같은 미상 값은 False 다.

    왜 구분이 필요한가: 예전에는 모르는 등급이 조용히 기본값(E1)으로 바뀌었는데,
    호출자에게는 그 사실이 전달되지 않았다. 그래서 대민(E3) 작업을 개인 PC 기준
    으로 검사하면서 기록에는 요청 등급이 그대로 남는 상태가 만들어졌다 —
    검사를 느슨하게 하고 기록은 세게 남기는, 가장 나쁜 조합이다.
    """
    grade = normalize_env_grade(env_grade)
    return grade is None or grade in VALID_ENV_GRADES


def cooldown_days_for(env_grade: str | None) -> tuple[int, str]:
    """(적용 쿨다운 일수, **실제 적용된** 등급) — 미지정·미지원이면 default_env 기준.

    돌려주는 등급은 요청값이 아니라 **적용값**이다. 호출자는 이 값을 기록해야
    하며, 요청값과 다를 수 있다는 것을 ``env_grade_supported`` 로 확인해야 한다.
    """
    cfg = load_vcps_config()
    normalized = normalize_env_grade(env_grade)
    grade = normalized if normalized in VALID_ENV_GRADES else str(cfg.get("default_env", "E1"))
    envs = cfg.get("environments", {})
    entry = envs.get(grade) or {}
    days = entry.get("cooldown_days")
    if not isinstance(days, int) or days < 0:
        days = _DEFAULTS["environments"].get(grade, {}).get("cooldown_days", 7)
    return days, grade


def env_grade_summary(env_grade: str | None) -> tuple[str, str, int]:
    """(적용 등급, 라벨, 쿨다운 일수) — 보고서 표기용.

    ``cooldown_days_for`` 와 달리 라벨까지 돌려주는 이유는, 등급이 판정을 바꾸는데
    보고서에는 그 값이 전혀 표기되지 않았기 때문이다. 같은 패키지가 E1 에서는
    통과하고 E2 에서는 ``cooldown_hold`` 가 되는데, 읽는 사람이 어느 기준으로
    나온 판정인지 알 수 없으면 결과를 검증할 수 없다.
    """
    days, grade = cooldown_days_for(env_grade)
    envs = load_vcps_config().get("environments", {}) or {}
    entry = envs.get(grade) or {}
    label = str(entry.get("label") or _DEFAULTS["environments"].get(grade, {}).get("label", ""))
    return grade, label, days


def license_verdict(license_str: str | None) -> str:
    """라이선스 문자열 → 'allowed' | 'review_required' | 'unknown'.

    SPDX 식별자 정확 일치(대소문자 무시)를 우선하고, 'MIT License' 같은
    서술형은 접두 일치로 관대하게 본다. 판단 불가는 'unknown' — 차단 아님.
    """
    if not license_str or not str(license_str).strip():
        return "unknown"
    s = str(license_str).strip()
    s_low = s.lower()
    cfg = load_vcps_config()
    for lic in cfg.get("license_review_required", []):
        if s_low == str(lic).lower() or s_low.startswith(str(lic).lower()):
            return "review_required"
    for lic in cfg.get("license_allowlist", []):
        if s_low == str(lic).lower() or s_low.startswith(str(lic).lower()):
            return "allowed"
    # 서술형 관용 표기("MIT License", "BSD License" 등)
    if "mit" in s_low.split() or s_low.startswith("mit "):
        return "allowed"
    if s_low.startswith(("apache", "bsd", "isc")):
        return "allowed"
    if s_low.startswith(("gpl", "agpl", "sspl", "bsl")):
        return "review_required"
    # PolyForm 계열은 SPDX 식별자(하이픈)와 서술형("PolyForm Noncommercial
    # License 1.0.0", 공백)이 함께 쓰인다 — 목록의 접두 일치로는 서술형이
    # 걸리지 않으므로 계열 전체를 여기서 받는다. 어느 변형이든 상업·재배포
    # 조건이 붙어 있어 검토 대상인 것은 같다.
    if s_low.startswith("polyform"):
        return "review_required"
    return "unknown"
