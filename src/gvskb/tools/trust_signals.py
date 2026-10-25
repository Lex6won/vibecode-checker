"""패키지 신뢰 신호(41차, AGSRC-021) — 레지스트리 응답 **한 번**으로 판단한다.

추가 네트워크 조회가 없다. 이미 받은 패키지 문서(npm packument · PyPI JSON)에서
**이전 판과 이번 판을 비교**해 사람이 봐야 할 변화를 적는다. 모든 신호는 단독으로
**조건부**(게이트 ``trust``)이고 차단이 아니다 — 정상 프로젝트에서도 관리자가 바뀌거나
패치판에 의존성이 더해지는 일은 있다. 결합 차단은 기관 결정 뒤의 일이다.

출처 증명(provenance·attestation)은 **안전 근거로 쓰지 않는다**. 증명이 있어도 신호가
있으면 보고서에 그대로 적는다 — 증명은 "그 저장소에서 빌드됐다"일 뿐이다.
"""
from __future__ import annotations

import re

#: 신호 키 → 사람이 읽는 이름. 게이트·보고서가 같은 표를 쓴다.
TRUST_SIGNAL_LABELS: dict[str, str] = {
    "maintainer_changed": "이전 판과 관리자 구성이 다름",
    "patch_bloat": "패치판인데 크기·의존성이 크게 달라짐",
    "install_hook_added": "이전 판에 없던 설치 스크립트가 생김",
    "repo_changed": "이전 판과 소스 저장소 주소가 다름",
    "ai_lure_name": "신생 패키지인데 이름이 AI 도구 어휘를 포함",
}

#: 이름에 섞이면 AI 도구 사용자를 겨눈 이름으로 보는 어휘. 짧은 것은 토큰 일치만.
_LURE_SUBSTR = ("codex", "claude", "cursor", "copilot", "openai", "gemini", "anthropic")
_LURE_TOKEN = ("mcp", "gpt", "llm", "agent")
AI_LURE_MAX_AGE_DAYS = 90
#: 패치판 크기 변화 허용 폭(비율). 넘으면 ``patch_bloat``.
PATCH_SIZE_RATIO = 0.30

def _ver_tuple(version: str) -> tuple[int, ...] | None:
    core = re.split(r"[-+ ]", str(version).strip().lstrip("v"), maxsplit=1)[0]
    parts = core.split(".")
    if not parts or not all(p.isdigit() for p in parts if p != ""):
        return None
    nums = [int(p) for p in parts if p != ""]
    return tuple(nums) if nums else None


def _is_prerelease(version: str) -> bool:
    core = str(version).strip()
    return core != re.split(r"[-+]", core, maxsplit=1)[0] or bool(
        re.search(r"\d(?:a|b|rc|dev)\d*$", core, re.I))


def previous_version(queried: str | None, versions: list[str]) -> str | None:
    """``queried`` 바로 아래의 정식 버전. 비교 불가면 None(추측하지 않는다)."""
    if not queried:
        return None
    cur = _ver_tuple(queried)
    if cur is None:
        return None
    best: tuple[tuple[int, ...], str] | None = None
    for v in versions:
        if v == queried or _is_prerelease(v):
            continue
        k = _ver_tuple(v)
        if k is None or k >= cur:
            continue
        if best is None or k > best[0]:
            best = (k, v)
    return best[1] if best else None


def is_patch_step(prev: str, cur: str) -> bool:
    a, b = _ver_tuple(prev), _ver_tuple(cur)
    if not a or not b or len(a) < 3 or len(b) < 3:
        return False
    return a[:2] == b[:2] and a[2] != b[2]


def _person_names(items: object) -> set[str]:
    out: set[str] = set()
    if not isinstance(items, list):
        return out
    for it in items:
        if isinstance(it, dict):
            n = (it.get("name") or it.get("email") or "").strip().lower()
        else:
            n = str(it or "").strip().lower().split("<", 1)[0].strip()
        if n:
            out.add(n)
    return out


def _signal(key: str, severity: str, detail: str) -> dict:
    return {"key": key, "label": TRUST_SIGNAL_LABELS[key], "severity": severity, "detail": detail}


def _size_change(prev_size: object, cur_size: object) -> float | None:
    try:
        p, c = int(prev_size or 0), int(cur_size or 0)
    except (TypeError, ValueError):
        return None
    if p <= 0 or c <= 0:
        return None
    return (c - p) / p


_NPM_HOOKS = ("preinstall", "install", "postinstall")


def _norm_repo(url: object) -> str:
    """``git+https://github.com/a/b.git`` · ``git@github.com:a/b`` · 축약 ``a/b`` 를 같은 키로."""
    u = url.get("url") if isinstance(url, dict) else url
    s = str(u or "").strip().lower()
    for pre in ("git+", "ssh://", "git://", "https://", "http://", "git@", "github:"):
        if s.startswith(pre):
            s = s[len(pre):]
    s = s.rstrip("/").removesuffix(".git").replace(":", "/")
    for host in ("www.github.com/", "github.com/"):
        if s.startswith(host):
            s = s[len(host):]
    return s


def _npm_publisher(user: object) -> str:
    """실제로 발행한 사람. 신뢰 발행(OIDC)이면 ``_npmUser`` 는 'GitHub Actions' 같은 자리표시자라
    승인자(``approver``)를 본다 — 승인자가 없으면 비교하지 않는다(자리표시자를 사람으로 세지 않는다)."""
    if not isinstance(user, dict):
        return ""
    if user.get("trustedPublisher"):
        approver = user.get("approver")
        return (approver.get("name") or "").strip().lower() if isinstance(approver, dict) else ""
    return (user.get("name") or "").strip().lower()


def npm_trust_signals(data: dict, queried: str | None) -> dict:
    """npm packument → ``{"previous_version", "provenance", "signals": [...]}``."""
    versions_doc = data.get("versions") or {}
    cur = versions_doc.get(queried) if queried else None
    out: dict = {"previous_version": None, "provenance": None, "signals": []}
    if not isinstance(cur, dict):
        return out
    dist = cur.get("dist") or {}
    out["provenance"] = bool(dist.get("attestations")) if isinstance(dist, dict) else None
    prev_v = previous_version(queried, list(versions_doc))
    out["previous_version"] = prev_v
    prev = versions_doc.get(prev_v) if prev_v else None
    if not isinstance(prev, dict):
        return out
    sig: list[dict] = out["signals"]

    new_people = _person_names(cur.get("maintainers")) - _person_names(prev.get("maintainers"))
    publisher = _npm_publisher(cur.get("_npmUser"))
    if publisher and publisher not in _person_names(prev.get("maintainers")) | _person_names(cur.get("maintainers")):
        new_people.add(publisher)
    if new_people and _person_names(prev.get("maintainers")):
        sig.append(_signal("maintainer_changed", "medium",
                           f"{prev_v}→{queried}: 신규 {len(new_people)}명"))

    cur_hooks = [h for h in _NPM_HOOKS if h in (cur.get("scripts") or {})]
    prev_hooks = [h for h in _NPM_HOOKS if h in (prev.get("scripts") or {})]
    if cur_hooks and not prev_hooks:
        sig.append(_signal("install_hook_added", "high",
                           f"{prev_v}→{queried}: {', '.join(cur_hooks)}"))

    if is_patch_step(prev_v, queried):
        parts: list[str] = []
        ratio = _size_change((prev.get("dist") or {}).get("unpackedSize"), dist.get("unpackedSize"))
        if ratio is not None and abs(ratio) >= PATCH_SIZE_RATIO:
            parts.append(f"크기 {ratio:+.0%}")
        added = set((cur.get("dependencies") or {})) - set((prev.get("dependencies") or {}))
        if added:
            parts.append(f"신규 의존성 {len(added)}개")
        if parts:
            sig.append(_signal("patch_bloat", "medium", f"{prev_v}→{queried}: " + ", ".join(parts)))

    r_prev, r_cur = _norm_repo(prev.get("repository")), _norm_repo(cur.get("repository"))
    if r_prev and r_cur and r_prev != r_cur:
        sig.append(_signal("repo_changed", "medium", f"{prev_v}→{queried}"))
    return out


def _pypi_release_size(files: object) -> int:
    if not isinstance(files, list):
        return 0
    sizes = [int(f.get("size") or 0) for f in files if isinstance(f, dict)]
    return max(sizes) if sizes else 0


def pypi_trust_signals(data: dict, queried: str | None) -> dict:
    """PyPI JSON → 같은 모양. 관리자 이력은 이 API 에 없으므로 크기 비교만 한다."""
    releases = data.get("releases") or {}
    out: dict = {"previous_version": None, "provenance": None, "signals": []}
    if not queried or queried not in releases:
        return out
    files = releases.get(queried) or []
    if isinstance(files, list) and files:
        out["provenance"] = any(bool(f.get("provenance")) for f in files if isinstance(f, dict))
    prev_v = previous_version(queried, list(releases))
    out["previous_version"] = prev_v
    if prev_v and is_patch_step(prev_v, queried):
        ratio = _size_change(_pypi_release_size(releases.get(prev_v)), _pypi_release_size(files))
        if ratio is not None and abs(ratio) >= PATCH_SIZE_RATIO:
            out["signals"].append(_signal("patch_bloat", "medium", f"{prev_v}→{queried}: 크기 {ratio:+.0%}"))
    return out


def ai_lure_signal(name: str, package_age_days: int | None) -> dict | None:
    """신생(90일 미만) + AI 도구 어휘 이름. 둘 다 있어야 한다."""
    if package_age_days is None or package_age_days >= AI_LURE_MAX_AGE_DAYS:
        return None
    low = name.lower()
    tokens = set(re.split(r"[^a-z0-9]+", low)) - {""}
    hit = next((w for w in _LURE_SUBSTR if w in low), None) or next((w for w in _LURE_TOKEN if w in tokens), None)
    if not hit:
        return None
    return _signal("ai_lure_name", "medium", f"'{hit}' · 최초 발행 {package_age_days}일 전")


def summarize(signals: list[dict]) -> str:
    return " · ".join(TRUST_SIGNAL_LABELS.get(s.get("key"), str(s.get("key"))) for s in signals)
