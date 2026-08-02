"""기관 신뢰 패키지 레지스트리 클라이언트 (연동합의 §5·§6).

**이 모듈이 없어도 gvskb 는 온전히 동작한다.** ``GVSKB_REGISTRY_URL`` 미설정이면
전체가 비활성이고 기존 경로와 100% 동일하다(합의 원칙 1 — 의존은 단방향).

설계 원칙(합의 §2)

1. **단방향 의존** — 레지스트리가 없어도·죽어도·느려도 검사는 계속된다.
2. **관측과 판정을 섞지 않음** — 이 도구는 승인 권한이 없다. 레지스트리 판정을
   그대로 옮길 뿐이고, 우리가 만든 판정(``registry_*``)은 되돌려 보내지 않는다.
3. **fail-open, 침묵 금지** — 조회 실패가 검사를 막지 않되 ``registry_status`` 로
   반드시 드러난다. '물어보지 못했다'가 '승인받았다'처럼 보여선 안 된다.
4. **로컬 탐지가 최종 안전망** — ``apply_registry_decision`` 이 집행한다.
5. **알림 단위는 조치 단위를 따름** — 도달 실패는 보고서 배너 1개이지 패키지마다가
   아니다. 그래서 여기서는 ``requires_review`` 를 올리지 않는다.

전송하지 않는 것: 소스 코드 · 파일 경로 · 개인 식별자.
"""
from __future__ import annotations

import asyncio
import os
import time

import httpx

# 차단 판정은 조회 실패보다 오래 살아남아야 한다 — 그렇지 않으면 레지스트리
# 도달을 방해하는 것만으로 차단을 우회할 수 있다(합의 §4-5).
_TTL_SECONDS = {
    "REJECTED": 7 * 24 * 3600,   # 만료돼도 삭제하지 않고 '낡은 차단'으로 강등
    "APPROVED": 3600,            # 철회 전파 지연을 줄이려 짧게
}

# 제출하지 않는 판정(합의 §5-D). registry_* 는 **우리가 준 답이 되돌아가는 것**이라
# 관측이 아니다 — 상대도 IGNORED_REGISTRY_ECHO 로 무시하지만 애초에 보내지 않는다.
_NO_SUBMIT_VERDICTS = frozenset({
    "unknown", "error", "registry_approved", "registry_rejected",
})

_MAX_BATCH = 200        # 합의 §5-A·§5-B
_CONCURRENCY = 8        # 합의 §5-F 권고값

# 서버가 **요청 자체를 거부**한 것 — 재시도해도 같은 답이다. 네트워크 장애와
# 조치가 정반대라(기다림 vs 스키마 교정) 같은 통에 담으면 담당자가 엉뚱한 곳을
# 본다. 422 는 실제로 예상되는 경로다: source_scope 에 `installed` 를 추가하기로
# 했는데 상대 enum 에 아직 없으면 배치가 통째로 422 로 돌아온다(회신 §1).
_SCHEMA_REJECT_CODES = frozenset({400, 404, 422})


def registry_url() -> str | None:
    """설정된 레지스트리 주소. 미설정이면 None = 플러그인 전체 비활성."""
    raw = os.environ.get("GVSKB_REGISTRY_URL", "").strip()
    return raw.rstrip("/") or None


def _token() -> str:
    return os.environ.get("GVSKB_REGISTRY_TOKEN", "").strip()


def _timeout() -> float:
    try:
        return float(os.environ.get("GVSKB_REGISTRY_TIMEOUT", "3.0"))
    except ValueError:
        return 3.0


def submit_enabled() -> bool:
    return os.environ.get("GVSKB_REGISTRY_SUBMIT", "1").strip() != "0"


def is_enabled() -> tuple[bool, str]:
    """(사용 가능한가, 사유). 사유는 registry_status 값으로 그대로 쓴다.

    오프라인 모드에서는 **별도 옵트인**을 요구한다. "외부로 나가지 않는다"는 것이
    사용자와의 약속이고, 레지스트리가 내부망이라도 그 약속을 조용히 바꿀 수 없다
    (합의 §6-2).
    """
    if registry_url() is None:
        return False, "disabled"
    if os.environ.get("GVSKB_MODE", "").lower() == "offline":
        if os.environ.get("GVSKB_REGISTRY_ALLOW_OFFLINE", "").strip() not in ("1", "true", "True"):
            return False, "disabled"
    return True, "ok"


def _headers() -> dict[str, str]:
    h = {"Accept": "application/json"}
    if _token():
        h["Authorization"] = f"Bearer {_token()}"
    return h


def _purl(eco: str, name: str, version: str | None) -> str:
    return f"pkg:{eco}/{name}" + (f"@{version}" if version else "")


# ---------------------------------------------------------------------------
# 로컬 캐시 — 조회 실패가 차단을 무력화하지 않게 한다
# ---------------------------------------------------------------------------

# purl -> (판정 dict, 저장 시각(monotonic))
_CACHE: dict[str, tuple[dict, float]] = {}


def _cache_get(purl: str) -> dict | None:
    """TTL 이 지나도 REJECTED 는 **삭제하지 않고 강등**해서 돌려준다.

    차단 사실이 사라지는 것과 오래된 것은 다르다. 만료로 지워 버리면 24시간 넘긴
    장애에서 차단이 조용히 풀린다.
    """
    hit = _CACHE.get(purl)
    if hit is None:
        return None
    decision, saved_at = hit
    status = str(decision.get("status") or "").upper()
    ttl = _TTL_SECONDS.get(status)
    if ttl is None:
        return None
    age = time.monotonic() - saved_at
    if age <= ttl:
        return decision
    if status == "REJECTED":
        stale = dict(decision)
        stale["stale"] = True
        return stale
    _CACHE.pop(purl, None)
    return None


def _cache_put(purl: str, decision: dict) -> None:
    if str(decision.get("status") or "").upper() in _TTL_SECONDS:
        _CACHE[purl] = (decision, time.monotonic())


def _reset_cache_for_tests() -> None:
    _CACHE.clear()


# ---------------------------------------------------------------------------
# 조회
# ---------------------------------------------------------------------------


async def lookup_batch(packages: list[dict], env_grade: str | None = None) -> dict[str, dict]:
    """purl -> 판정 dict. 조회 실패는 예외가 아니라 **빈 결과**로 돌려준다.

    단건 200회보다 배치 1회를 쓴다(합의 §5-F). 락파일 800건이면 단건 반복은
    곧 800회 왕복이 되어 "조회가 자체 분석보다 느리면 의미 없다"는 전제를 깬다.
    """
    ok, _ = is_enabled()
    if not ok or not packages:
        return {}
    base = registry_url()
    out: dict[str, dict] = {}
    pending: list[dict] = []

    # 캐시가 이미 답을 아는 것은 묻지 않는다.
    for p in packages:
        purl = _purl(str(p["ecosystem"]), str(p["name"]), p.get("version"))
        cached = _cache_get(purl)
        if cached is not None:
            out[purl] = cached
        else:
            pending.append(p)
    if not pending:
        return out

    chunks = [pending[i:i + _MAX_BATCH] for i in range(0, len(pending), _MAX_BATCH)]
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def _one(chunk: list[dict]) -> tuple[list[dict], str, int]:
        """(결과, 실패 종류, HTTP 코드). 실패 종류가 ``""`` 이면 성공이다.

        실패를 한 종류로 뭉개면 조치를 고를 수 없다 — 재시도가 유효한 상황과
        무의미한 상황은 담당자가 할 일이 완전히 다르다.
        """
        body = {
            "env_grade": env_grade,
            "packages": [
                {"ecosystem": c["ecosystem"], "name": c["name"], "version": c.get("version")}
                for c in chunk
            ],
        }
        async with sem:
            try:
                async with httpx.AsyncClient(timeout=_timeout()) as client:
                    r = await client.post(
                        f"{base}/api/v1/packages/check-bulk", json=body, headers=_headers(),
                    )
                    if r.status_code in (401, 403):
                        raise PermissionError("unauthorized")
                    if r.status_code in _SCHEMA_REJECT_CODES:
                        return [], "rejected", r.status_code
                    r.raise_for_status()
                    data = r.json()
            except PermissionError:
                raise
            except Exception:  # noqa: BLE001 — 조회 실패가 검사를 막으면 안 된다
                # 5xx·타임아웃·연결 거부·본문 파손 — 전부 '다시 해 보면 될 수도'
                # 쪽이다. 조치가 같으므로 한 종류로 묶는다(작업원칙 6).
                return [], "unreachable", 0
        results = data.get("results") if isinstance(data, dict) else None
        return (results if isinstance(results, list) else []), "", 200

    try:
        batches = await asyncio.gather(*(_one(c) for c in chunks))
    except PermissionError:
        return {"__error__": {"status": "unauthorized"}}

    failed: dict[str, int] = {}   # 실패 종류 -> 해당 청크 수
    codes: set[int] = set()
    for items, kind, code in batches:
        if kind:
            failed[kind] = failed.get(kind, 0) + 1
            if code:
                codes.add(code)
            continue
        for item in items:
            if isinstance(item, dict) and item.get("purl"):
                out[str(item["purl"])] = item
                _cache_put(str(item["purl"]), item)

    if failed:
        # 성공한 청크의 판정은 **버리지 않는다**. 800건 중 200건이 거부됐다고
        # 나머지 600건의 기관 차단까지 잃으면, 부분 실패가 차단 우회 수단이 된다.
        # 대신 실패 사실을 봉투에 실어 호출자가 반드시 표시하게 한다.
        out["__error__"] = {
            # 조치가 더 급한 쪽을 대표값으로 — 스키마 교정은 사람이 붙어야 하고
            # 연결 실패는 기다리면 풀릴 수 있다.
            "status": "rejected" if "rejected" in failed else "unreachable",
            "failed_chunks": sum(failed.values()),
            "total_chunks": len(chunks),
            "http_codes": sorted(codes),
        }
    return out


# ---------------------------------------------------------------------------
# 제출
# ---------------------------------------------------------------------------


def should_submit(result: dict) -> bool:
    """제출 필터(합의 §5-D) — 판정이 아닌 것과 우리가 만든 판정은 보내지 않는다."""
    if str(result.get("verdict") or "") in _NO_SUBMIT_VERDICTS:
        return False
    # 버전 미지정은 '특정 버전의 사실'이 아니다 — 레지스트리 저장 키가 성립하지 않는다.
    if not result.get("version"):
        return False
    # 같은 이유로 **경계값도 사실이 아니다**. `requests>=2.28` 을 2.28 로 판정해
    # 보내면 레지스트리에는 "2.28 에 대한 관측"으로 저장되는데, 그 프로젝트가 실제로
    # 쓰는 것은 2.31.0 일 수 있다. 우리가 보지 않은 것을 사실로 넘기지 않는다.
    return bool(result.get("version_exact", True))


def _envelope(result: dict, *, caller: str, source_scope: str, now_iso: str) -> dict:
    """봉투(합의 §5-B). ``result`` 는 변환 없는 원본 — 전송 사정으로 판정 모델을
    오염시키지 않는다.

    ``caller`` 만은 예외로 검증한다. 규칙(``<출처>:<모드>[:부서코드]``)을 제안한
    것이 우리이고, 개인 식별자가 섞이면 상대 저장소와 **우리 감사 기록이 함께**
    오염되기 때문이다. 상대 서버도 검증을 추가하지만, 규칙을 지킬 주체와 강제할
    주체가 같으면 안 된다는 말은 우리에게도 적용된다.
    """
    from .. import __version__
    from ..audit import safe_caller

    return {
        "result": result,
        "caller": safe_caller(caller),
        "submitted_at": now_iso,
        "client": f"gvskb/{__version__}",
        # 배포본에는 git 메타데이터가 없어 대부분 null 이다. 가짜 값을 채우느니
        # null 이 낫다 — 상대도 null 을 허용했다(합의 §5-B).
        "engine_commit": os.environ.get("GVSKB_ENGINE_COMMIT") or None,
        "source_scope": source_scope,
    }


async def submit_batch(
    results: list[dict], *, caller: str = "", source_scope: str = "single", now_iso: str = "",
) -> dict:
    """관측 데이터 제출. **실패해도 검사 결과를 그대로 쓴다** — 제출 실패가 검사
    실패가 되면 안 된다(합의 §2 원칙 3).

    반환값은 요약이며 호출자는 무시해도 된다.
    """
    ok, _ = is_enabled()
    if not ok or not submit_enabled():
        return {"submitted": 0, "skipped": len(results), "reason": "disabled"}
    items = [r for r in results if should_submit(r)]
    if not items:
        return {"submitted": 0, "skipped": len(results), "reason": "filtered"}

    base = registry_url()
    chunks = [items[i:i + _MAX_BATCH] for i in range(0, len(items), _MAX_BATCH)]
    sem = asyncio.Semaphore(_CONCURRENCY)
    sent = 0

    async def _one(chunk: list[dict]) -> int:
        body = {"items": [
            _envelope(r, caller=caller, source_scope=source_scope, now_iso=now_iso)
            for r in chunk
        ]}
        async with sem:
            try:
                async with httpx.AsyncClient(timeout=_timeout()) as client:
                    r = await client.post(
                        f"{base}/api/v1/packages/submit-batch", json=body, headers=_headers(),
                    )
                    r.raise_for_status()
            except Exception:  # noqa: BLE001 — 제출 실패는 검사 실패가 아니다
                return 0
        return len(chunk)

    for n in await asyncio.gather(*(_one(c) for c in chunks)):
        sent += n
    return {"submitted": sent, "skipped": len(results) - sent}


def annotate_status(result: dict, status: str) -> dict:
    """조회하지 못한 경우의 표시. **requires_review 는 올리지 않는다.**

    도달 실패는 패키지 수백 건에 공통인 시스템 문제이고 조치는 '레지스트리 복구'
    한 건이다. 패키지마다 검토 깃발을 꽂으면 담당자가 그것을 무시하게 되고, 그러면
    그 사이의 진짜 위험도 함께 묻힌다 — 보고서 배너가 대신 알린다(합의 §4-4).
    """
    out = dict(result)
    out["registry_status"] = status
    return out


def registry_banner(status: str) -> str | None:
    """조회 실패를 보고서에 한 줄로 — '물어보지 못했다'가 '승인받았다'로 보이지 않게."""
    if status == "unreachable":
        return (
            "⚠️ **기관 레지스트리에 연결하지 못했습니다** — 기관 차단 목록이 이 결과에 "
            "적용되지 않았습니다. 자체 분석 결과만 반영돼 있으며, 조회되지 않은 것은 "
            "'승인받았다'는 뜻이 아닙니다. 레지스트리 복구 후 재검사하세요."
        )
    if status == "unauthorized":
        return (
            "⚠️ **기관 레지스트리 인증에 실패했습니다**(토큰 만료·권한 변경 가능) — "
            "기관 차단 목록이 적용되지 않았습니다. `GVSKB_REGISTRY_TOKEN` 을 확인하세요."
        )
    if status == "item_failed":
        return (
            "⚠️ **일부 패키지가 기관 레지스트리에서 판정을 받지 못했습니다** — 조회 자체는 "
            "성공했으나 해당 항목만 답이 없었습니다(배치가 성공해도 항목마다 실패할 수 "
            "있습니다). 그 패키지들에는 기관 차단 목록이 적용되지 않았으며, 판정이 없다는 "
            "것은 '승인받았다'는 뜻이 아닙니다. `registry_status=item_failed` 인 항목을 "
            "확인하세요."
        )
    if status == "rejected":
        # '연결하지 못했습니다'로 뭉뚱그리면 담당자는 방화벽·VPN을 뒤진다. 실제
        # 원인은 요청 형식이고, 고칠 곳은 네트워크가 아니라 스키마다.
        return (
            "⚠️ **기관 레지스트리가 조회 요청을 거부했습니다**(형식·경로 불일치) — "
            "네트워크 문제가 아니므로 **재시도해도 같습니다**. 기관 차단 목록이 이 "
            "결과에 적용되지 않았으며, 조회되지 않은 것은 '승인받았다'는 뜻이 "
            "아닙니다. 클라이언트와 서버의 스키마 버전이 어긋난 것이므로 레지스트리 "
            "담당자에게 알리세요."
        )
    return None
