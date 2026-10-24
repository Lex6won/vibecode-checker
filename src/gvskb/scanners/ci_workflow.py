"""GitHub Actions 워크플로 판정 — PR 코드가 저장소 권한으로 실행되는 자리.

왜(38차, 2026-10-24)
--------------------
2026-03 Trivy 태그 하이재킹, 2026-05 TanStack 캐시 오염, 2026 prt-scan 캠페인은 전부 같은 모양이었다:
`pull_request_target`(또는 `workflow_run`)으로 **저장소 쓰기 권한·비밀값을 가진 채** 외부 PR 의 코드를
체크아웃해 실행했다. 워크플로 YAML 은 일반 스캔이 데이터 파일로만 봤다 — 비밀값·개인정보 룰만 돌았다.

판정은 **구조**로 한다. 트리거·체크아웃 ref·이후 run 단계·권한을 묶어서 본다. 문자열 하나로 차단하지 않는다
(`pull_request_target` 자체는 라벨 붙이기 같은 정상 용례가 있다 — 그 경우 PR 코드를 체크아웃하지 않는다).

확신도
------
- confirmed: PR 코드 체크아웃 + 실행, `toJSON(secrets)` 전체 덤프, run 에 `${{ github.event.* }}` 직접 삽입,
  `curl … | sh` 류 원격 실행. 모양 자체가 판정이다.
- likely: 비고정 서드파티 액션(`@v4`·`@main`), 과한 권한, 셀프호스트 러너 + fork PR — 검토 신호(경고).
"""
from __future__ import annotations

import re
from typing import Any

import yaml

from ..schema import Finding
from .regex_scanner import build_finding, lookup_rule, redact_evidence

RULE_PWN_REQUEST = "GOV-CI-PWN-REQUEST-001"
RULE_SECRETS_DUMP = "GOV-CI-SECRETS-DUMP-001"
RULE_SCRIPT_INJECTION = "GOV-CI-SCRIPT-INJECTION-001"
RULE_REMOTE_EXEC = "GOV-CI-REMOTE-EXEC-001"
RULE_UNPINNED_ACTION = "GOV-CI-UNPINNED-ACTION-001"
RULE_PERMISSIONS = "GOV-CI-PERMISSIONS-001"
ENGINE = "ci-workflow"

RULE_IDS = (RULE_PWN_REQUEST, RULE_SECRETS_DUMP, RULE_SCRIPT_INJECTION, RULE_REMOTE_EXEC,
            RULE_UNPINNED_ACTION, RULE_PERMISSIONS)

_PRIVILEGED_TRIGGERS = ("pull_request_target", "workflow_run")
# PR 쪽 코드를 가리키는 표현 — checkout `ref`/`repository` 에 쓰이면 비신뢰 코드 유입이다.
_UNTRUSTED_REF_RE = re.compile(
    r"github\.event\.pull_request\.head|github\.head_ref|github\.event\.workflow_run\.head"
    r"|github\.event\.pull_request\.merge_commit_sha|refs/pull/",
)
_SECRETS_DUMP_RE = re.compile(r"toJSON\s*\(\s*secrets\s*\)|\$\{\{\s*secrets\s*\}\}", re.IGNORECASE)
# run 안에 **그대로** 보간되는 사용자 제어 값 — 제목·본문·브랜치명·커밋 메시지·코멘트.
_INJECTION_RE = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:pull_request\.(?:title|body|head\.(?:ref|label|repo\.(?:description|homepage)))"
    r"|issue\.(?:title|body)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)"
    r"|head_commit\.(?:message|author\.(?:name|email))|commits\[[^\]]*\]\.(?:message|author\.(?:name|email))"
    r"|pages\.[^}]*\.page_name|workflow_run\.(?:head_branch|head_commit\.message))|head_ref)\s*\}\}",
)
_INPUTS_RE = re.compile(r"\$\{\{\s*(?:github\.event\.)?inputs\.[\w-]+\s*\}\}")
_REMOTE_EXEC_RE = re.compile(
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|(?:ba)?sh\s+<\(\s*(?:curl|wget)\b"
    r"|\b(?:iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b"
    r"|\b(?:iex|Invoke-Expression)\s*\(\s*(?:iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b"
    r"|\bpython3?\s+<\(\s*(?:curl|wget)\b|(?:curl|wget)\b[^\n|]*\|\s*python3?\b",
    re.IGNORECASE,
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TRUSTED_ACTION_OWNERS = frozenset({"actions", "github"})
_WRITE_SCOPES = ("contents", "pull-requests", "id-token", "packages", "deployments", "actions", "security-events", "statuses", "checks")
# 코드를 실행하는 단계 — run, 또는 설치·빌드를 수행하는 흔한 액션.
_EXEC_ACTION_RE = re.compile(r"^(?:actions/setup-node|actions/setup-python|pnpm/action-setup|oven-sh/setup-bun|denoland/setup-deno)", re.I)
_RUN_LIKE_RE = re.compile(r"\b(?:npm|pnpm|yarn|bun|npx|pip|pip3|uv|poetry|make|cargo|go|mvn|gradle|dotnet|node|python3?|bash|sh)\b")


def _line_of(text: str, needle: str, default: int = 1) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else default


def _emit(rule_id: str, *, rel: str, line: int, evidence: str, confidence: str) -> Finding | None:
    rule = lookup_rule(rule_id)
    if rule is None:
        return None
    return build_finding(rule, filename=rel, line_no=max(1, line), evidence=redact_evidence(evidence)[:240],
                         engine=ENGINE, confidence=confidence)


def _triggers(data: dict) -> dict[str, Any]:
    """`on:` 블록 — YAML 은 `on` 을 불리언 True 키로 읽는다. 문자열·목록·매핑 전부 매핑으로 정규화."""
    raw = data.get("on", data.get(True))
    if isinstance(raw, str):
        return {raw: {}}
    if isinstance(raw, list):
        return {str(t): {} for t in raw}
    if isinstance(raw, dict):
        return {str(k): (v if isinstance(v, dict) else {}) for k, v in raw.items()}
    return {}


def _steps(job: dict) -> list[dict]:
    steps = job.get("steps")
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def _as_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return yaml.safe_dump(v, allow_unicode=True)
    except Exception:  # noqa: BLE001
        return str(v)


def _step_executes(step: dict) -> str | None:
    """이 단계가 저장소 코드를 **실행**하는가 — 그렇다면 근거 문자열."""
    run = step.get("run")
    if isinstance(run, str) and run.strip():
        first = run.strip().splitlines()[0]
        return f"run: {first[:80]}"
    uses = str(step.get("uses") or "")
    if _EXEC_ACTION_RE.match(uses):
        with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
        if with_.get("cache"):
            return f"uses: {uses} (cache: {with_.get('cache')})"
    return None


def _has_cache(job: dict) -> bool:
    for s in _steps(job):
        uses = str(s.get("uses") or "")
        if uses.startswith("actions/cache"):
            return True
        with_ = s.get("with") if isinstance(s.get("with"), dict) else {}
        if _EXEC_ACTION_RE.match(uses) and with_.get("cache"):
            return True
    return False


def _permissions_summary(block: Any) -> tuple[bool, list[str]]:
    """(write-all 인가, 쓰기 권한 목록)."""
    if block == "write-all":
        return True, list(_WRITE_SCOPES)
    if isinstance(block, dict):
        return False, [k for k, v in block.items() if str(v).lower() == "write"]
    return False, []


def judge_workflow(data: Any, text: str, rel: str) -> list[Finding]:
    """워크플로 1개 → 발견 목록. 실행은 하지 않는다."""
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out
    triggers = _triggers(data)
    jobs = data.get("jobs") if isinstance(data.get("jobs"), dict) else {}
    # 수동 실행 입력 중 자유 문자열만 삽입 위험이다 — choice·boolean·number 는 값이 정해져 있다(개밥먹기 2026-10-24:
    # 이 저장소의 `inputs.channel`(choice: test|prod) 이 경고로 올라왔다).
    constrained_inputs: set[str] = set()
    wd = triggers.get("workflow_dispatch") or {}
    for name, spec in (wd.get("inputs") or {}).items() if isinstance(wd.get("inputs"), dict) else ():
        if isinstance(spec, dict) and str(spec.get("type", "string")).lower() in ("choice", "boolean", "number", "environment"):
            constrained_inputs.add(str(name))
    top_write_all, top_writes = _permissions_summary(data.get("permissions"))
    has_top_permissions = "permissions" in data
    privileged = [t for t in _PRIVILEGED_TRIGGERS if t in triggers]

    # 1) 비밀값 전체 덤프 — 어디에 있어도 확정.
    for m in _SECRETS_DUMP_RE.finditer(text):
        f = _emit(RULE_SECRETS_DUMP, rel=rel, line=text.count("\n", 0, m.start()) + 1,
                  evidence=f"비밀값 컨텍스트 전체를 꺼냄: {m.group(0)}", confidence="confirmed")
        if f:
            out.append(f)
        break

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = _steps(job)
        job_write_all, job_writes = _permissions_summary(job.get("permissions"))
        writes = sorted(set(top_writes) | set(job_writes))
        write_all = top_write_all or job_write_all

        # 2) pwn request — 권한 있는 트리거 + PR 코드 체크아웃 + 이후 실행
        if privileged:
            checkout_idx = None
            checkout_note = ""
            for i, s in enumerate(steps):
                uses = str(s.get("uses") or "")
                with_ = s.get("with") if isinstance(s.get("with"), dict) else {}
                if uses.startswith("actions/checkout") and (
                    _UNTRUSTED_REF_RE.search(_as_text(with_.get("ref"))) or _UNTRUSTED_REF_RE.search(_as_text(with_.get("repository")))
                ):
                    checkout_idx = i
                    checkout_note = f"ref={_as_text(with_.get('ref')).strip() or _as_text(with_.get('repository')).strip()}"
                    break
                run = s.get("run")
                if isinstance(run, str) and re.search(r"gh\s+pr\s+checkout|git\s+fetch[^\n]*(?:refs/pull|pull_request\.head)", run):
                    checkout_idx = i
                    checkout_note = "run: gh pr checkout / git fetch refs/pull"
                    break
            if checkout_idx is not None:
                exec_note = next((n for s in steps[checkout_idx + 1:] if (n := _step_executes(s))), None)
                cache = _has_cache(job)
                ev = (f"on: {', '.join(privileged)} → job `{job_name}` 가 PR 코드 체크아웃({checkout_note})"
                      + (f" → 실행: {exec_note}" if exec_note else " (이후 실행 단계 없음)")
                      + (f" · 쓰기 권한 {','.join(writes)}" if writes or write_all else "")
                      + (" · 캐시 사용 — 오염된 캐시가 다른 워크플로로 번질 수 있음" if cache else ""))
                f = _emit(RULE_PWN_REQUEST, rel=rel, line=_line_of(text, privileged[0]), evidence=ev,
                          confidence="confirmed" if exec_note else "likely")
                if f:
                    out.append(f)

        # 3) 스크립트 삽입 · 원격 실행 · 비고정 액션
        for s in steps:
            run = s.get("run")
            if isinstance(run, str):
                m = _INJECTION_RE.search(run)
                if m:
                    f = _emit(RULE_SCRIPT_INJECTION, rel=rel, line=_line_of(text, m.group(0)),
                              evidence=f"job `{job_name}` run 에 사용자 제어 값 직접 삽입: {m.group(0)} — env: 로 받아 \"$VAR\" 로 쓰세요",
                              confidence="confirmed")
                    if f:
                        out.append(f)
                elif "workflow_dispatch" in triggers:
                    free = [m for m in _INPUTS_RE.finditer(run)
                            if m.group(0).split("inputs.", 1)[1].rstrip("} ").strip() not in constrained_inputs]
                    if free:
                        f = _emit(RULE_SCRIPT_INJECTION, rel=rel, line=_line_of(text, free[0].group(0)),
                                  evidence=f"job `{job_name}` run 에 수동 실행 자유 문자열 입력값 직접 삽입: {free[0].group(0)}",
                                  confidence="likely")
                        if f:
                            out.append(f)
                m = _REMOTE_EXEC_RE.search(run)
                if m:
                    f = _emit(RULE_REMOTE_EXEC, rel=rel, line=_line_of(text, m.group(0).split("\n")[0][:40]),
                              evidence=f"job `{job_name}` run 이 원격 스크립트를 받아 바로 실행: {m.group(0)[:100]}", confidence="confirmed")
                    if f:
                        out.append(f)
            uses = str(s.get("uses") or "").strip()
            if uses and "@" in uses and not uses.startswith(("./", "docker://")):
                ref = uses.rsplit("@", 1)[1]
                owner = uses.split("/", 1)[0].lower()
                if owner not in _TRUSTED_ACTION_OWNERS and not _SHA_RE.match(ref):
                    mutable = ref in ("main", "master", "latest", "dev", "develop") or not re.match(r"^v?\d", ref)
                    f = _emit(RULE_UNPINNED_ACTION, rel=rel, line=_line_of(text, uses),
                              evidence=f"job `{job_name}` uses: {uses} — commit SHA 가 아닌 {'가변 브랜치' if mutable else '태그'} 참조"
                                       + (" (태그는 다시 밀 수 있다 — 2026-03 Trivy 사례)" if not mutable else ""),
                              confidence="likely")
                    if f:
                        out.append(f)

        # 4) 권한·러너 노출
        runs_on = _as_text(job.get("runs-on"))
        self_hosted = "self-hosted" in runs_on
        fork_trigger = "pull_request" in triggers or bool(privileged)
        if write_all:
            f = _emit(RULE_PERMISSIONS, rel=rel, line=_line_of(text, "write-all"),
                      evidence=f"job `{job_name}`: permissions: write-all — 모든 범위 쓰기", confidence="likely")
            if f:
                out.append(f)
        elif privileged and (writes or not has_top_permissions and "permissions" not in job):
            f = _emit(RULE_PERMISSIONS, rel=rel, line=_line_of(text, privileged[0]),
                      evidence=f"job `{job_name}`: {', '.join(privileged)} 트리거에 "
                               + (f"쓰기 권한 {','.join(writes)}" if writes else "permissions 미지정(저장소 기본값 — 쓰기일 수 있음)"),
                      confidence="likely")
            if f:
                out.append(f)
        if self_hosted and fork_trigger:
            f = _emit(RULE_PERMISSIONS, rel=rel, line=_line_of(text, "self-hosted"),
                      evidence=f"job `{job_name}`: self-hosted 러너에서 외부 PR 트리거 실행 — 내부망 러너에 비신뢰 코드", confidence="likely")
            if f:
                out.append(f)
    return out
