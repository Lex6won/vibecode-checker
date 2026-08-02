"""반입 번들 생성 — 망분리 환경에서 관측을 레지스트리로 넘기는 유일한 경로.

리포트 파일 전체를 올리면 ``findings[].evidence``(코드 조각)와 ``scanned_files``
(파일 경로)가 레지스트리를 거친다. 이는 연동합의 §3 이 **절대 전송 금지**로 정한
것이고, 서버가 파싱 범위를 좁혀도 업로드 시점에 이미 지나간 뒤다.

그래서 판단을 소비자가 아니라 **생산자**가 한다. 이 모듈은 봉투에 담을 것을
직접 고르며, 그 방식은 '빼기'가 아니라 **'허용한 것만 넣기'** 다 — 제외 목록은
새 필드가 생길 때마다 뒤처지지만 허용목록은 새 필드를 자동으로 막는다.

명세: `docs/연동회신_gg-trusted-registry_2026-08-02_r5.md` §3-2
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ..schema import PackageCheckResult
from .registry_client import should_submit

BUNDLE_SCHEMA = "gvskb-registry-bundle/1"

# ``result`` 에 실을 수 있는 키. PackageCheckResult 의 필드만 통과시킨다 —
# 검사 과정에서 dict 에 덧붙는 임시 키(note·caller·경로 등)는 스키마에 없으므로
# 자동으로 걸러지고, 나중에 누군가 경로가 담긴 필드를 덧붙여도 여기서 막힌다.
_RESULT_ALLOWED = frozenset(PackageCheckResult.model_fields)

# 레지스트리가 `source_scope` enum 에 `installed` 를 반영했음을 확인했으므로
# (2026-08-03 회신 §2) 보류를 해제했다. 이제 모르는 값도 거부하지 않고 심사 큐
# 미투입으로 떨어뜨린다고 하므로, 값을 늘릴 때 상대 배포를 기다릴 필요도 없다.
INSTALLED_SCOPE_ON_HOLD = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _source_scope(audit: dict, check: dict | None = None) -> str:
    """이 판정이 어느 경로에서 나왔는가 (합의 §5-C).

    **항목 단위가 감사 단위보다 우선한다.** 설치본 인벤토리 안에도 직접 의존성과
    전이 의존성이 섞여 있고, 둘은 심사 큐 정책이 다르다(레지스트리 요청 §3) —
    직접 의존성은 사람이 봐야 하고 전이 의존성은 관측으로만 쌓는다. CLI 가
    매니페스트와 설치본을 대조해 항목마다 붙여 둔 값을 그대로 쓴다.

    설치본 인벤토리는 내부적으로 ``audit_manifest`` 를 재사용하므로 ``source_kind``
    만 보면 매니페스트와 구분되지 않는다 — 표식을 따로 본다.
    """
    if check is not None and check.get("source_scope"):
        return str(check["source_scope"])
    if str(audit.get("source") or "") == "installed-inventory":
        return "installed"
    return "lockfile" if audit.get("source_kind") == "lockfile" else "manifest"


def _purl(check: dict) -> str:
    eco, name = check.get("ecosystem"), check.get("name")
    return f"pkg:{eco}/{name}" + (f"@{check['version']}" if check.get("version") else "")


# 같은 패키지가 두 경로로 잡히면 어느 쪽을 남길 것인가. 사람이 봐야 하는 쪽을
# 남긴다 — 직접 의존성이 전이 의존성으로 강등되면 심사 큐에서 사라진다.
_SCOPE_RANK = {"manifest": 3, "lockfile": 2, "installed": 1}


def build_bundle(
    dependency_audit: dict | None,
    *,
    caller: str = "cli:manual",
    now_iso: str | None = None,
) -> dict:
    """의존성 검사 결과 → 반입 번들(§3-2).

    담기는 것: 제출 필터(§5-D)를 통과한 판정만, 합의 §5-B 봉투 형식으로.
    담기지 않는 것: 코드 조각 · 파일 경로 · 개인 식별자 · findings 일체 ·
    scanned_files · target · 매니페스트 파일명.

    제외한 것은 **세어서 남긴다**. 조용히 빠지면 받는 쪽은 그 패키지를 우리가
    쓰지 않는 것으로 읽는다 — 없는 것과 안 보낸 것은 다르다.
    """
    from .. import __version__
    from ..audit import safe_caller

    caller = safe_caller(caller)
    by_purl: dict[str, dict] = {}
    installed_held = 0
    filtered = 0
    deduped = 0

    for audit in (dependency_audit or {}).get("audits") or []:
        for c in audit.get("checks") or []:
            scope = _source_scope(audit, c)
            if scope == "installed" and INSTALLED_SCOPE_ON_HOLD:
                if should_submit(c):
                    installed_held += 1
                continue
            if not should_submit(c):
                filtered += 1
                continue
            item = {
                "result": {k: v for k, v in c.items() if k in _RESULT_ALLOWED},
                "caller": caller,
                "source_scope": scope,
            }
            # 같은 패키지·같은 버전이 매니페스트와 설치본 양쪽에서 잡힐 수 있다.
            # 같은 사실을 두 번 보내면 상대 심사 큐만 늘어난다.
            key = _purl(c)
            prev = by_purl.get(key)
            if prev is None:
                by_purl[key] = item
                continue
            deduped += 1
            if _SCOPE_RANK.get(scope, 0) > _SCOPE_RANK.get(prev["source_scope"], 0):
                by_purl[key] = item

    items = list(by_purl.values())
    return {
        "schema": BUNDLE_SCHEMA,
        "generated_at": now_iso or _now_iso(),
        "client": f"gvskb/{__version__}",
        # 배포본에는 git 메타데이터가 없어 대부분 null 이다. 가짜 값을 채우느니
        # null 이 낫고, 상대도 null 을 허용했다(합의 §5-B).
        "engine_commit": None,
        "items": items,
        # 규격 외 추가 필드 — 반출 심사자와 수신자 모두 "무엇이 빠졌는지"를 알아야
        # 한다. 빠진 것을 세지 않으면 번들은 '전부'처럼 보인다.
        "excluded": {
            "installed_pending_enum": installed_held,
            "submit_filtered": filtered,
            "duplicates": deduped,
        },
    }


def bundle_notice(bundle: dict) -> str:
    """담당자에게 보여 줄 한 줄 요약 — 번들이 전부가 아님을 화면에서도 알린다."""
    ex = bundle.get("excluded") or {}
    held, filtered = ex.get("installed_pending_enum", 0), ex.get("submit_filtered", 0)
    msg = f"[gvskb] 반입 번들 {len(bundle.get('items') or [])}건"
    if held:
        msg += (
            f" · 설치본 유래 {held}건 보류(레지스트리 source_scope enum 에 "
            "'installed' 반영 확인 전까지 제출하지 않기로 한 항목)"
        )
    if filtered:
        msg += f" · 제출 대상 아님 {filtered}건(버전 미확정·경계값·우리 판정의 되돌림)"
    if ex.get("duplicates"):
        msg += f" · 중복 {ex['duplicates']}건 제거"
    scopes: dict[str, int] = {}
    for i in bundle.get("items") or []:
        s = str(i.get("source_scope") or "")
        scopes[s] = scopes.get(s, 0) + 1
    if scopes:
        msg += " · " + ", ".join(f"{k} {v}" for k, v in sorted(scopes.items()))
    return msg


def write_bundle(bundle: dict, path: str | Path) -> tuple[Path, Path]:
    """번들과 ``.sha256`` 을 함께 쓴다 — (번들 경로, 해시 경로).

    해시를 동봉하는 이유는 인텔 번들과 같다: 망을 건너는 파일은 손상·변조를
    받는 쪽에서 확인할 수 있어야 한다. 확인할 수 없는 반입물은 신뢰할 수 없다.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(bundle, ensure_ascii=False, indent=2).encode("utf-8")
    p.write_bytes(blob)
    digest = hashlib.sha256(blob).hexdigest()
    sidecar = p.with_name(p.name + ".sha256")
    # 바이트로 쓴다 — write_text 는 Windows 에서 줄바꿈을 CRLF 로 바꾸고, 그러면
    # 파일명 끝에 CR 이 붙어 받는 쪽 `sha256sum -c` 가 "그런 파일 없음"으로 실패한다.
    # 검증하라고 동봉한 파일이 검증을 막으면 없느니만 못하다.
    sidecar.write_bytes(f"{digest}  {p.name}\n".encode("utf-8"))
    return p, sidecar
