"""Public scanner facade.

Runs every registered ``ScannerAdapter`` and combines their findings into a
single ``ScanReport``. When two adapters report the same ``(rule_id, file,
line)`` the more precise engine wins (currently: python-ast > regex).

External callers should continue to use ``scan_code`` / ``scan_file`` /
``scan_path`` here; the per-engine adapters live in ``gvskb.scanners``.

Rules are still loaded once at import via the regex adapter. ``RULES`` and
``reload_rules`` are re-exported for backwards compatibility.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterable

from .profiles import apply_profile, load_profile
from .scanners.ast_scanner import PythonAstScanner
from .scanners.js_taint import JsTaintScanner
from .scanners.external_surface import (
    dedupe_connections,
    extract_api_connections,
    extract_static_resources,
    inventory_packages,
)
from .scanners.regex_scanner import (
    RULES as RULES,
    RegexScanner,
    build_finding,
    dedupe_by_group,
    lookup_rule,
    redact_evidence as _redact_evidence,
    reload_rules as _reload_runtime_rules,
)
from .scanners.semgrep_scanner import SemgrepScanner
from .schema import (
    EXPOSURE_CATEGORIES,
    Decision,
    ExternalConnection,
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
    SkippedFile,
)

# Adapter run order. Earlier adapters establish baseline findings; later
# adapters (more precise) can supersede them via dedup_findings. SemgrepScanner
# self-disables when the binary or rules dir is missing, so safe to include.
_ADAPTERS = [RegexScanner(), PythonAstScanner(), JsTaintScanner(), SemgrepScanner()]

# Engine precision ranking — higher number wins on collisions.
_ENGINE_PRECISION = {"regex": 0, "python-ast": 1, "js-taint": 1, "semgrep": 2}

SEVERITY_RANK = {
    Severity.low: 0,
    Severity.medium: 1,
    Severity.high: 2,
    Severity.critical: 3,
}


# ── 테스트 코드 경로 감쇄 ──────────────────────────────────────────────────
# 테스트 픽스처의 "비밀번호"·"주민번호"는 대개 진짜가 아니다. 그런데 값만 보는
# 룰은 진짜와 구분하지 못해, 실측에서 시크릿·PII 오탐 8건이 **전부** tests/ 밑에
# 있었고 그것만으로 배포 차단 판정이 났다. 발견을 지우지는 않는다 — 테스트에
# 진짜 키를 넣는 사고도 흔하기 때문이다. 등급만 낮춰 리포트에는 남기고 게이트는
# 통과시킨다.
_TEST_PATH_SEGMENTS = {
    "test", "tests", "__tests__", "spec", "specs", "testdata", "__mocks__",
}
_TEST_FILE_RE = re.compile(
    r"(?:^|[._-])(?:test|spec)s?\.[A-Za-z0-9]+$"   # foo.test.mjs · bar.spec.ts
    r"|^test_[^/\\]*\.py$"                          # test_foo.py
    r"|_test\.py$"                                  # foo_test.py
    r"|^conftest\.py$",
    re.IGNORECASE,
)

# 값의 진위가 판정을 좌우하는 계열만 감쇄한다. 주입·XSS 같은 *코드 모양* 룰은
# 테스트 코드에서도 그대로 둔다 — 모양이 잘못된 건 어디서든 잘못된 것이다.
#
# 목록을 여기 다시 적지 않는다(schema.EXPOSURE_CATEGORIES 참조). 예전에는
# 같은 집합이 regex_scanner 에도 따로 적혀 있었고 둘 다 public-sector-internal
# 이 빠져 있어, 테스트 픽스처의 사설 IP 48건이 차단으로 올라왔다.
_VALUE_BASED_CATEGORIES = EXPOSURE_CATEGORIES

_TEST_PATH_REASON = "테스트 코드 경로 — 값이 실제 자격증명·개인정보가 아닐 가능성이 높음"


def is_test_path(filename: str) -> bool:
    """경로가 테스트 코드로 보이는지."""
    if not filename or filename == "<memory>":
        return False
    normalized = filename.replace("\\", "/")
    parts = [p for p in normalized.split("/") if p]
    if any(p.lower() in _TEST_PATH_SEGMENTS for p in parts[:-1]):
        return True
    return bool(parts and _TEST_FILE_RE.search(parts[-1]))


def attenuate_test_path_findings(findings: list[Finding], filename: str) -> list[Finding]:
    """테스트 경로의 값 기반 발견을 low·warn 으로 낮춘다(삭제하지 않음)."""
    if not is_test_path(filename):
        return findings
    adjusted: list[Finding] = []
    for finding in findings:
        if (
            finding.category not in _VALUE_BASED_CATEGORIES
            or finding.severity == Severity.low
        ):
            adjusted.append(finding)
            continue
        adjusted.append(finding.model_copy(update={
            "severity": Severity.low,
            "decision": Decision.warn if finding.decision == Decision.block else finding.decision,
            "requires_approval_to_bypass": False,
            "severity_adjusted": f"{finding.severity.value} → low · {_TEST_PATH_REASON}",
        }))
    return adjusted


#: "이렇게 하지 마세요"라고 **말하는** 줄. 보안 가이드·룰 설명·체크리스트·
#: 인수인계 문서는 자기가 금지한 토큰을 문장 안에 그대로 담는다.
#:
#: 실측(2026-08-09, 사용자 제보): 룰 파일에 새로 쓴
#: ``description: LLM 응답을 그대로 실행(execute)하지 말고 검증하세요`` 가
#: **'LLM 출력 실행 위험'으로 차단**됐다. 도구가 자기가 하라고 쓴 문장을
#: 막은 것이다. 제보자는 그 문장을 구조화 필드로 바꿔 없앴다 —
#: **도구가 문서를 고치게 만든 것이 이 결함의 진짜 피해다.**
_PROHIBITION_RE = re.compile(
    r"(?i)("
    r"하지\s*(?:말|마)|말\s*것|말고|금지|삼가|피하세요|피할\s*것|않도록|"
    r"안\s*됩니다|안\s*된다|위험합니다|주의하세요|대신\s|권장하지|"
    # 영문 토큰은 `\s` 가 아니라 `\b` 로 끊는다. `avoid\s` 로 두었더니
    # 줄 **끝**에 온 `// avoid` 가 매치되지 않아, 같은 모양이 뒤 공백
    # 유무로 다르게 판정됐다(적대적 검증에서 검출).
    r"must\s+not|should\s+not|do\s+not|don't|never\b|avoid\b|"
    r"forbidden|prohibited|deprecated|instead\s+of"
    r")"
)

_PROHIBITION_REASON = (
    "금지·주의 문구가 있는 안내문으로 보임 — 실행되는 코드가 아니라 "
    "'이렇게 하지 말라'는 설명일 가능성이 높음"
)


def attenuate_prohibition_prose_findings(
    findings: list[Finding], code: str,
) -> list[Finding]:
    """금지 문구가 같은 줄에 있는 **실행 위험** 발견을 low·warn 으로 낮춘다.

    **삭제하지 않고 낮춘다.** 안내문처럼 보인다는 것은 확률이지 확신이 아니다.
    ``os.system(cmd)  # 하지 말 것`` 처럼 진짜 코드에 반성문이 달린 경우가
    있고, 그걸 조용히 지우면 놓친 사실이 아무 데도 남지 않는다.

    **노출 위험(비밀값·개인정보·내부망)에는 적용하지 않는다.** "비밀번호를
    하드코딩하지 마세요: password = hunter2" 라고 써 두면, 하지 말라고 적혀
    있어도 비밀번호는 그대로 노출돼 있다. 의도가 위험을 지우지 못한다.

    룰 파일 8개에 같은 제외 패턴을 흩뿌리지 않고 여기 한 곳에 둔다 — 같은
    목록을 여러 곳에 적으면 언젠가 어긋난다(이 프로젝트가 세 번 겪었다).
    """
    lines = code.splitlines()
    adjusted: list[Finding] = []
    for finding in findings:
        line_no = finding.location.line
        if (
            finding.category in EXPOSURE_CATEGORIES
            or finding.severity == Severity.low
            or not line_no
            or line_no > len(lines)
            or not _PROHIBITION_RE.search(lines[line_no - 1])
        ):
            adjusted.append(finding)
            continue
        adjusted.append(finding.model_copy(update={
            "severity": Severity.low,
            "decision": Decision.warn if finding.decision == Decision.block else finding.decision,
            "requires_approval_to_bypass": False,
            "severity_adjusted": f"{finding.severity.value} → low · {_PROHIBITION_REASON}",
        }))
    return adjusted


def reload_rules() -> int:
    """Reload the regex rule cache from disk. AST adapter follows along."""
    return _reload_runtime_rules()


def _provenance() -> dict:
    """분석 출처 각인 — 모든 ScanReport 에 엔진 버전·생성 시각(UTC)을 박는다.

    레지스트리·감사로그가 "어떤 엔진이 언제 판단했나"를 재현 가능하게 만드는
    최소 단위다. import 실패가 스캔을 막지 않도록 방어적으로 감싼다.
    """
    try:
        from gvskb import __version__
        ver: str | None = __version__
    except Exception:  # pragma: no cover - defensive
        ver = None
    from datetime import datetime, timezone
    out = {
        "engine_version": ver,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    out.update(_ruleset_identity())
    return out


# 룰셋 신원은 **프로세스당 한 번**만 계산한다. 324개 룰 지문은 ~10ms 인데,
# scan_path 는 파일마다 scan_code 를 부르므로 파일 수만큼 곱해지면 눈에 띈다.
_RULESET_IDENTITY_CACHE: dict | None = None


def _ruleset_identity() -> dict:
    """(룰셋 버전, 지문, 드리프트 설명) — 실패해도 스캔을 막지 않는다."""
    global _RULESET_IDENTITY_CACHE
    if _RULESET_IDENTITY_CACHE is not None:
        return _RULESET_IDENTITY_CACHE
    identity: dict = {"ruleset_version": None, "ruleset_digest": None, "ruleset_drift": None}
    try:
        from . import ruleset as _ruleset
        from .loader import load_all_rules
        from .scanners.regex_scanner import _resolve_rules_dir
        rules_dir = _resolve_rules_dir()
        verdict = _ruleset.verify_lock(load_all_rules(rules_dir), rules_dir)
        identity["ruleset_digest"] = verdict["actual"]
        identity["ruleset_version"] = verdict["version"]
        if verdict["status"] != "ok":
            identity["ruleset_drift"] = verdict["message"]
    except Exception:  # pragma: no cover - 방어: 신원 계산 실패가 검사를 막지 않는다
        pass
    _RULESET_IDENTITY_CACHE = identity
    return identity


def reset_ruleset_identity_cache() -> None:
    """룰 디렉터리를 바꾼 뒤(테스트·`GVSKB_RULES_DIR` 변경) 다시 계산하게 한다."""
    global _RULESET_IDENTITY_CACHE
    _RULESET_IDENTITY_CACHE = None


def _current_scan_mode() -> str | None:
    """Honest mode marker for the report — set only in offline (air-gapped) mode.

    Online is the implicit default (``None``), so normal reports are unchanged.
    In offline mode dependency/intel checks run against a local cache only, so
    the report must say so — an unchecked package is 'not judged', not 'safe'.
    """
    return "offline" if os.environ.get("GVSKB_MODE", "").lower() == "offline" else None


def _intel_freshness() -> dict | None:
    """오프라인 모드에서 리포트에 실릴 인텔 캐시 기준일(source_id → 날짜).

    보안팀이 "몇 월 며칠 캐시 기준의 판정인지"를 리포트만 보고 알 수 있어야
    반입 주기를 판단할 수 있다. 온라인 모드는 실시간 조회이므로 None.
    로드 실패는 스캔을 막지 않는다 — 기준일 표기만 생략된다.
    """
    if _current_scan_mode() != "offline":
        return None
    try:
        from .intel.cache import IntelCache
        cache = IntelCache()
        fresh: dict[str, str] = {}
        for sid in cache.list_sources():
            entry = cache.load(sid)  # sha256 재검증 포함 — 변조 캐시는 표기하지 않음
            if entry is not None and entry.fetched_at:
                fresh[sid] = entry.fetched_at[:10]  # 날짜만 — 리포트 가독성
        return fresh or None
    except Exception:  # noqa: BLE001 — 표기 실패가 검사를 막으면 안 된다
        return None


def _highest(findings: Iterable[Finding]) -> Severity | None:
    highest: Severity | None = None
    for finding in findings:
        if highest is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest]:
            highest = finding.severity
    return highest


def _summary(findings: list[Finding]) -> ScanSummary:
    by_severity = {s.value: 0 for s in Severity}
    by_decision = {d.value: 0 for d in Decision}
    for finding in findings:
        by_severity[finding.severity.value] += 1
        by_decision[finding.decision.value] += 1
    return ScanSummary(
        finding_count=len(findings),
        by_severity=by_severity,
        by_decision=by_decision,
        highest_severity=_highest(findings),
        blocked=any(f.decision == Decision.block for f in findings),
    )


# AST 엔진이 파일을 성공적으로 파싱했다면, 같은 주제를 다루는 **줄 단위 regex
# 결과는 버린다**. regex 는 삽입 값의 출처(사용자 입력 vs 개발자 상수)를 알 수
# 없어 상수 기반 SQL 조립을 치명 위험으로 잘못 올렸고(실측 오탐), AST 는 그
# 구분을 한다. 파싱 실패 시에만 regex 가 예비 수단으로 남는다.
_AST_OWNED_RULE_IDS = frozenset({
    "GOV-SQL-INJECTION-001",
    "GOV-SQL-DDL-DYNAMIC-001",
    "GOV-LLM-PROMPT-INJECTION-001",
})


def _drop_regex_when_ast_owns(findings: list[Finding], ast_parsed: bool) -> list[Finding]:
    if not ast_parsed:
        return findings
    return [
        f for f in findings
        if not (f.engine == "regex" and f.rule_id in _AST_OWNED_RULE_IDS)
    ]


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep the most precise engine's finding for each (rule_id, file, line)."""
    best: dict[tuple[str, str, int], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.location.file, f.location.line)
        prev = best.get(key)
        if prev is None:
            best[key] = f
        elif _ENGINE_PRECISION.get(f.engine, 0) > _ENGINE_PRECISION.get(prev.engine, 0):
            best[key] = f
    return list(best.values())


def scan_code(
    code: str,
    *,
    filename: str = "<memory>",
    language: str | None = None,
    scenario: str | None = None,
    profile: str = "public-default-strict",
    categories: set[str] | None = None,
    collapse_duplicates: bool = True,
) -> ScanReport:
    """``collapse_duplicates=False`` 는 룰별 정확도 평가용 — dedup_group 으로
    묶인 룰이 서로를 가려 재현율이 0으로 보이는 것을 막는다."""
    raw: list[Finding] = []
    for adapter in _ADAPTERS:
        raw.extend(adapter.scan(
            code,
            filename=filename,
            language=language,
            scenario=scenario,
            profile=profile,
            categories=categories,
        ))
    from .scanners.ast_scanner import python_ast_parsed
    raw = _drop_regex_when_ast_owns(raw, python_ast_parsed(code, filename, language))
    findings = _dedupe(raw)

    # Apply scenario-bound policy: decision overrides + severity_min filter.
    profile_spec = load_profile(profile)
    findings = apply_profile(findings, profile_spec)
    # 프로파일 뒤에 감쇄한다 — 프로파일의 decision 상향이 감쇄를 되돌리지 못하게.
    findings = attenuate_test_path_findings(findings, filename)
    # HTML sink 의 문맥(정화 헬퍼 경유 · <style> CSS)도 같은 원칙으로 낮춘다 —
    # 삭제가 아니라 감쇄다. 판단이 틀렸을 때 위험이 사라지면 안 된다.
    from .scanners.html_sink_context import attenuate_html_sink_findings
    findings = attenuate_html_sink_findings(findings, code, filename)
    # "이렇게 하지 마세요"라고 말하는 줄 — 보안 가이드·룰 설명·인수인계 문서가
    # 자기가 금지한 토큰을 문장 안에 담는다. 역시 삭제가 아니라 감쇄다.
    findings = attenuate_prohibition_prose_findings(findings, code)
    if collapse_duplicates:
        findings = dedupe_by_group(findings)
    effective_profile, profile_fallback = _profile_resolution(profile, profile_spec)

    return ScanReport(
        target=filename,
        language=language,
        scenario=scenario,
        profile=effective_profile,
        profile_fallback=profile_fallback,
        summary=_summary(findings),
        findings=findings,
        # 인메모리 조각도 "이 파일을 검사함"으로 기록 — 발견 0이 "검사 안 됨"이
        # 아니라 "위험 없음"으로 올바르게 결론나게 한다.
        scanned_files=[filename],
        external_surface=dedupe_connections(
            extract_api_connections(code, filename) + extract_static_resources(code, filename)
        ),
        scan_mode=_current_scan_mode(),
        intel_freshness=_intel_freshness(),
        **_provenance(),
    )


def scan_file(path: str | Path, *, language: str | None = None, scenario: str | None = None) -> ScanReport:
    p = Path(path)
    # utf-8-sig — BOM 제거(그대로 두면 AST 파싱이 실패한다).
    return scan_code(p.read_text(encoding="utf-8-sig"), filename=str(p), language=language, scenario=scenario)


# ---------------------------------------------------------------------------
# Directory / path scanning — unchanged from the pre-adapter version
# ---------------------------------------------------------------------------

DEFAULT_INCLUDE_EXTS: frozenset[str] = frozenset({
    ".py", ".pyw",
    # .mts/.cts 는 TypeScript 의 ESM/CJS 명시 확장자다. 실측(lexdiff)에서 이 두
    # 확장자가 목록에 없어 2,271줄과 외부 연결 11건(국외 5건 포함)이 '검사조차
    # 되지 않았다' — 발견 0이 안전으로 읽히는 가장 위험한 종류의 미탐이었다.
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts",
    ".java", ".kt", ".scala",
    ".go", ".rs",
    ".rb", ".php",
    ".cs", ".vb",
    ".swift", ".m",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
    ".sql",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties",
    ".html", ".htm", ".xml",
    ".vue", ".svelte",
    ".tf", ".tfvars",
    ".dockerfile",
    # 자격증명·키 자재 — 실측에서 SSL **개인키**(*_key.pem)가 소스에 있는데
    # 확장자 목록에 없어 '검사조차 되지 않았다'. 확장자만으로도 위험 신호이며,
    # 내용(PEM 헤더)까지 보면 개인키 노출을 확정할 수 있다.
    ".pem", ".key", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".keystore",
    ".ppk", ".asc", ".gpg", ".kdbx",
})

# 파일 **이름**만으로 비밀 취급해야 하는 것들(확장자가 .txt 여도 검사한다).
# `.txt` 전면 스캔은 로그·문서까지 끌어들여 노이즈가 크므로 이름으로 선별한다.
_SECRET_FILENAME_RE = re.compile(
    r"(?:^|[._-])(?:password|passwd|pwd|secret|secrets|credential|credentials|"
    r"apikey|api[_-]?key|token|privatekey|private[_-]?key|id_rsa|id_dsa|id_ecdsa|id_ed25519)"
    r"(?:[._-]|$)",
    re.IGNORECASE,
)


def _is_secret_filename(name: str) -> bool:
    """이름만으로 비밀 자재로 봐야 하는 파일인가(password.txt, id_rsa 등)."""
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return bool(_SECRET_FILENAME_RE.search(name) or _SECRET_FILENAME_RE.search(stem))


# 비밀 파일에 담긴 "값처럼 보이는 것" — 긴 hex / base64 / 무작위 문자열.
# 32자 이상만 본다(짧은 값은 설정·식별자일 가능성이 높아 오탐이 된다).
_SECRET_VALUE_RE = re.compile(
    r"^[A-Za-z0-9+/=_\-]{32,}$"
)
_HEXLIKE_RE = re.compile(r"^[0-9a-fA-F]{32,}$")

# 경로처럼 보이는 값 — 실측(2026-08-08) `BACKOFF_FILE="/tmp/claude-token-refresh-backoff"`
# 가 '32자 이상 무작위 값'으로 잡혔다. `/` 는 base64 알파벳이기도 해서 값 문자만
# 보면 구별되지 않는다. 경로는 **머리 모양**으로 갈린다: `/`·`./`·`../`·`~/`·`C:\`.
# base64 는 보통 `+` 나 `=` 를 동반하므로, 그 둘이 있으면 경로로 보지 않는다.
_PATHLIKE_RE = re.compile(r"^(?:~|\.{1,2})?/|^[A-Za-z]:[\\/]")

# 이름이 **공개 식별자**임을 말하는 키 — 값이 무작위해 보여도 비밀이 아니다.
# 실측: OAuth `CLIENT_ID="9d1c250a-…"`(UUID). client_id 는 브라우저 URL 에
# 그대로 실려 나가는 공개값이다. `CLIENT_SECRET` 은 여기에 들지 않는다(끝의
# `(?!...SECRET)` 가 아니라, 키 전체가 이 목록과 정확히 맞아야 한다).
_PUBLIC_ID_KEY_RE = re.compile(
    r"(?:^|[._-])(?:client[._-]?id|tenant[._-]?id|app[._-]?id|application[._-]?id|"
    r"project[._-]?id|account[._-]?id|issuer|audience|"
    r"\w*(?:file|path|dir|home|url|uri|endpoint))$",
    re.IGNORECASE,
)


def _looks_like_secret_material(text: str) -> tuple[bool, int, str]:
    """비밀 파일 내용이 '자격증명 값'으로 보이는가 → (판정, 줄번호, 근거 줄).

    파일명이 비밀을 뜻하는데 **내용이 긴 무작위 값 한 덩어리**면 그 값은 대개
    세션 서명키·API 키다. 주석·안내문만 있는 파일(예: "패스워드 없는 형태의
    인증서 파일입니다")은 제외해야 하므로 실제 값 형태만 본다.

    줄번호를 함께 돌려준다 — 이전에는 호출부가 ``line_no=1`` 을 박아서, 담당자가
    보고서를 보고 1행을 열면 아무것도 없었다. 근거 줄은 보여주면서 위치는 거짓인
    상태였고, 그러면 그 발견은 확인 자체가 되지 않는다.
    """
    for line_no, raw in enumerate(text.splitlines()[:40], start=1):   # 앞부분만
        line = raw.strip().strip("\"'")
        if not line or line.startswith(("#", "//", ";", "--")):
            continue
        # key=value 형태면 값 부분만 본다. 키 이름이 공개 식별자를 뜻하면 건너뛴다.
        if "=" in line:
            key, _, rest = line.partition("=")
            value = rest.strip().strip("\"'")
            if len(value) >= 32:
                if _PUBLIC_ID_KEY_RE.search(key.strip()):
                    continue
                line = value
        if _PATHLIKE_RE.match(line) and not any(c in line for c in "+="):
            continue
        if _HEXLIKE_RE.match(line) or _SECRET_VALUE_RE.match(line):
            return True, line_no, raw
    return False, 0, ""

# 의존성 매니페스트/락파일 — regex 스캔으로는 취약 버전이 잡히지 않으므로
# SCA(check-package / scan_dependencies)로 보내야 한다. 디렉터리 스캔 중
# 만나면 스킵하되 그 사실을 안내로 남긴다. (package.json은 .json으로 이미 스캔됨)
_DEP_MANIFEST_NAMES: frozenset[str] = frozenset({
    "requirements.txt", "poetry.lock", "pipfile.lock", "uv.lock",
    "yarn.lock", "package-lock.json", "pnpm-lock.yaml",
})

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "bower_components",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".venv", "venv", "env", ".env",
    "dist", "build", "out", "target",
    ".tox", ".nox",
    ".idea", ".vscode",
    "coverage", ".coverage", "htmlcov",
    "vendor", "third_party", "thirdparty",
    # 프런트엔드 빌드 출력·툴 캐시 — 모두 *생성물*이라 원본 소스가 아니다.
    # 미니파이드 번들을 스캔하면 룰이 import/토큰 단위로 대량 오탐을 낸다.
    ".next", ".nuxt", ".cache",
    # 이 도구가 만든 점검 보고서 — 반드시 제외해야 한다. 보고서에는 발견 사항의
    # **증거 문구가 인용**돼 있어(예: PEM 헤더), 다시 스캔하면 자기가 쓴 글을
    # 새 위험으로 잡는 자기 참조가 생긴다(실측: 재검사 때마다 발견이 2건씩 증식).
    ".check-reports",
    ".puppeteer-cache", ".tmp", "tmp", ".turbo", ".parcel-cache",
    ".svelte-kit", ".astro", ".vercel", ".netlify", ".output",
    ".angular", ".docusaurus", "storybook-static",
})

# 빌드 출력 디렉터리(이름 기준). DEFAULT_EXCLUDE_DIRS 의 부분집합으로, 이쪽은
# 제외하되 리포트에 "빌드 산출물 제외"로 *한 줄 기록*한다(정직성). 반대로
# .git/node_modules/__pycache__ 등 인프라 디렉터리는 조용히 제외한다.
_BUILD_OUTPUT_DIR_NAMES: frozenset[str] = frozenset({
    "dist", "build", "out", "target",
    ".next", ".nuxt",
    ".puppeteer-cache", ".tmp", "tmp", ".turbo", ".parcel-cache",
    ".svelte-kit", ".astro", ".vercel", ".netlify", ".output",
    ".angular", ".docusaurus", "storybook-static",
})

# 다중 세그먼트 빌드 출력 경로 — os.walk 는 디렉터리 *이름* 만 보므로
# "public/assets" 처럼 경로로만 식별되는 산출물은 상대경로 suffix 로 매칭한다.
# (소스의 "src/assets" 는 제외하지 않도록 "assets" 단독 이름은 막지 않는다.)
DEFAULT_EXCLUDE_PATH_SUFFIXES: tuple[str, ...] = (
    "public/assets",
    "static/assets",
    "public/build",
    "dist/assets",
    "build/static",
    "wwwroot/dist",
)

# 압축/번들 산출물로 스킵된 파일에 붙는 사유 마커. 리포트가 이 부분 문자열로
# "빌드 산출물 N건 제외" 한 줄을 집계한다(scanner→report 결합도 최소화).
BUILD_ARTIFACT_SKIP_REASON = "빌드 산출물(압축/번들) — 원본 소스 아님"

# 벤더링된 서드파티 라이브러리(`static/xlsx.full.min.js` 같은 것). 빌드 산출물과
# **성격이 다르다** — 빌드 출력은 원본 소스가 따로 있지만, 벤더 번들은 그 자체가
# 프로젝트가 실제로 실행하는 남의 코드이고 알려진 취약점이 붙는다.
# 예전에는 둘을 같은 사유로 묶어 조용히 제외했고, 그 결과 실측 프로젝트의
# `xlsx 0.18.5`(CVE-2023-30533 등)를 아무도 보지 않았다. 소스 룰 검사는 계속
# 제외하되(오탐 방지 원래 의도), 컴포넌트 취약점 검사로 넘긴다.
VENDOR_BUNDLE_SKIP_REASON = (
    "벤더 번들(외부 라이브러리) — 소스 룰 검사 제외, 컴포넌트 취약점 검사 대상"
)

# 콘텐츠 해시가 박힌 빌드 파일명: app-3f9a2c1b.js, chunk.4F2A.css, main.min.js 등.
# Vite/webpack/rollup/esbuild 의 캐시버스팅 산출물을 파일명만으로 거른다.
_HASHED_ASSET_RE = re.compile(
    r"[.\-_][0-9a-f]{8,}\.(?:js|mjs|cjs|jsx|ts|tsx|css|map)$",
    re.IGNORECASE,
)

# single-line 초장문(미니파이드) 판정 기준.
_MINIFIED_MAX_LINE = 2000   # 한 줄이 이 길이를 넘으면 사람이 읽는 소스가 아님
_MINIFIED_AVG_LINE = 400    # 평균 줄 길이가 이만큼 큰 다줄 번들도 미니파이드로 본다
_MINIFIED_MIN_BYTES = 1000  # 너무 짧은 파일은 판정 제외(정상적인 한 줄 파일 보호)

# 소스 파일 상한 — 실측(lexdiff)에서 568개 저장소가 500에서 잘려 70개가
# 검사되지 않았다. 걸린 시간은 전수 22초로, 아낀 2초와 맞바꾼 사각지대였다.
# 500은 "빠르게 끝내기" 위한 값이었지만 이 도구의 목적은 **빠짐없이 보는 것**이다.
# 20,000은 정상 저장소가 도달할 수 없는 값이면서(공공 프로젝트 실측 최대 수천),
# 잘못 지정한 경로(예: 사용자 홈)에서 무한정 도는 것은 막는 안전판이다.
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_FILE_BYTES = 1_000_000


def _profile_resolution(requested: str, spec) -> tuple[str, dict | None]:
    """(리포트에 적을 프로파일, 대체 사실) — 못 찾았으면 그 사실을 값으로 남긴다.

    요청한 이름을 그대로 적으면 **적용되지 않은 정책으로 판정한 것처럼** 보인다.
    실측(하네스 연동): MCP `scan_path(profile="dev-quick")` 이 정책을 못 찾아 아무
    필터도 걸리지 않았는데 보고서 머리표에는 `dev-quick` 이 찍혔다. CLI 는 경고 후
    기본값으로 바꿔 정직했지만 **API·MCP 경로에는 그 처리가 없었다** — 하네스가
    쓰는 쪽이 하필 그 경로다.
    """
    from .profiles import DEFAULT_PROFILE_ID, list_profiles

    if getattr(spec, "resolved", True):
        return requested, None
    try:
        available = list_profiles()
    except OSError:
        available = []
    return DEFAULT_PROFILE_ID, {
        "requested": requested,
        "applied": DEFAULT_PROFILE_ID,
        "reason": "정책 파일을 찾지 못했습니다(GVSKB_POLICIES_DIR 경로를 확인하세요)",
        "available": available,
    }


def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def _looks_like_build_artifact_name(name: str) -> bool:
    """파일명만으로 **빌드 산출물**을 식별한다(콘텐츠 해시가 박힌 캐시버스팅 파일).

    ``*.min.*`` 은 여기서 빼야 한다 — 그것은 빌드 출력이 아니라 대개 벤더링된
    서드파티 라이브러리이고, `_looks_like_vendor_bundle_name` 이 따로 받는다.
    """
    return bool(_HASHED_ASSET_RE.search(name.lower()))


def _looks_like_vendor_bundle_name(name: str) -> bool:
    """``*.min.js`` 계열 — 벤더링된 프런트엔드 라이브러리 후보."""
    lower = name.lower()
    return ".min." in lower and lower.endswith((".js", ".mjs", ".cjs"))


# 식별을 위해 읽어들일 최대 바이트. 라이브러리 자기 버전 대입은 파일 중간에
# 나올 수 있다(실측: xlsx 0.18.5 는 639KB 중 31.7% 지점) — 앞부분만 봐선 못 찾는다.
_VENDOR_READ_MAX_BYTES = 5_000_000


def _identify_vendor_bundle_file(
    p: Path, rel_path: str, *, detected_by: str = "name", text: str | None = None
) -> dict | None:
    """벤더 번들 파일을 읽어 컴포넌트(이름·버전)를 식별한다. 읽기 실패 시 None.

    ``detected_by`` 는 **무엇을 근거로 벤더로 봤는가**다.
    ``name`` = 파일명에 ``.min.`` (작성자가 명시적으로 배포본 라이브러리를 넣은 신호),
    ``content`` = 이름은 평범한데 내용이 미니파이드(자체 번들일 수도 있음).
    이 구분이 있어야 '식별 실패'를 어디까지 위험으로 올릴지 정할 수 있다.
    """
    from .tools.vendor_bundle import identify_vendor_bundle

    if text is None:
        try:
            with p.open("rb") as fh:
                raw = fh.read(_VENDOR_READ_MAX_BYTES)
        except OSError:
            return None
        text = raw.decode("utf-8", errors="replace")
    info = identify_vendor_bundle(rel_path, text).as_dict()
    info["detected_by"] = detected_by
    return info


def _looks_minified(text: str) -> bool:
    """내용 기반 미니파이드 판정: single-line 초장문 또는 평균 줄 과대."""
    if len(text) < _MINIFIED_MIN_BYTES:
        return False
    lines = text.splitlines() or [text]
    longest = max(len(ln) for ln in lines)
    if longest >= _MINIFIED_MAX_LINE:
        return True
    avg = len(text) / max(len(lines), 1)
    return avg >= _MINIFIED_AVG_LINE


def _path_is_excluded_suffix(rel_dir: str) -> bool:
    posix = rel_dir.replace("\\", "/").strip("/").lower()
    return any(posix == s or posix.endswith("/" + s) for s in DEFAULT_EXCLUDE_PATH_SUFFIXES)


def _rel(p: Path, root: Path, is_dir: bool) -> str:
    if not is_dir:
        return p.name
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def scan_path(
    path: str | Path,
    *,
    include_exts: set[str] | frozenset[str] | None = None,
    exclude_dirs: set[str] | frozenset[str] | None = None,
    scenario: str | None = None,
    profile: str = "public-default-strict",
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    caller: str = "",
) -> ScanReport:
    """Scan a file or directory tree on disk.

    ``caller`` 는 호출 주체 자율 신고 값(예: 'harness:auto') — 감사로그의
    caller 필드로 전달돼 레지스트리 request_type(AUTO/MANUAL) 구분 근거가 된다.
    """
    root = Path(path)
    inc = frozenset(e.lower() for e in (include_exts or DEFAULT_INCLUDE_EXTS))
    exc = frozenset(exclude_dirs or DEFAULT_EXCLUDE_DIRS)
    skipped: list[SkippedFile] = []
    vendor_bundles: list[dict] = []                  # 벤더 번들 식별 결과(SCA 대상)
    external: list[ExternalConnection] = []          # 외부 연결 인벤토리 누적
    manifest_files: list[tuple[Path, str]] = []      # (경로, ecosystem) — 플러그인 목록용

    if not root.exists():
        return ScanReport(
            target=str(root),
            scenario=scenario,
            profile=profile,
            summary=_summary([]),
            findings=[],
            scanned_files=[],
            skipped_files=[SkippedFile(path=str(root), reason="path does not exist")],
            scan_mode=_current_scan_mode(),
            intel_freshness=_intel_freshness(),
            **_provenance(),
        )

    files_to_scan: list[Path] = []
    over_limit_count = 0        # 상한 초과로 검사되지 않은 '검사 대상' 파일 수
    is_dir = root.is_dir()

    if root.is_file():
        files_to_scan = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            # 1) 이름 기반 제외 + 2) 경로 suffix 기반 제외(public/assets 등).
            # 빌드 출력 디렉터리는 제외하되 한 줄 기록하고, 인프라 디렉터리
            # (.git/node_modules 등)는 조용히 버린다.
            kept_dirs = []
            for d in dirnames:
                try:
                    rel_dir = str((Path(dirpath) / d).relative_to(root))
                except ValueError:
                    rel_dir = d
                is_build = d in _BUILD_OUTPUT_DIR_NAMES or _path_is_excluded_suffix(rel_dir)
                if is_build:
                    skipped.append(SkippedFile(
                        path=rel_dir.replace("\\", "/") + "/",
                        reason=BUILD_ARTIFACT_SKIP_REASON,
                    ))
                    continue
                if d in exc:
                    continue
                kept_dirs.append(d)
            dirnames[:] = kept_dirs
            for name in filenames:
                if len(files_to_scan) >= max_files:
                    # 상한 도달 뒤에도 **세는 것은 계속한다** — 이전에는 즉시
                    # break 해서, 잘려나간 70개 파일이 리포트에 '1건'으로만
                    # 보였다(파일 목록도 순회 비용도 read 가 아니라 거의 공짜다).
                    # 몇 개를 못 봤는지 모르면 사용자는 절단을 절단으로 못 읽는다.
                    if Path(name).suffix.lower() in inc:
                        over_limit_count += 1
                    continue
                p = Path(dirpath) / name
                if name.lower() in _DEP_MANIFEST_NAMES:
                    skipped.append(SkippedFile(
                        path=_rel(p, root, is_dir),
                        reason="의존성 매니페스트 — 취약점은 `gvskb check-package` 또는 MCP `scan_dependencies`로 검사하세요",
                    ))
                    # 외부 연결 인벤토리용으로 *직접 의존성*만 읽는다(락파일 제외).
                    if name.lower() == "requirements.txt":
                        manifest_files.append((p, "pypi"))
                    continue
                if (
                    p.suffix.lower() not in inc
                    and name.lower() not in {"dockerfile", "makefile"}
                    and not _is_secret_filename(name)
                ):
                    # **조용히 버리지 않는다** — 검사 대상이 아닌 파일도 기록해야
                    # "검사했는데 깨끗함"과 "아예 안 봤음"이 구분된다. 실측에서
                    # ssl/ 디렉터리의 개인키가 스캔·제외 어디에도 없이 사라졌다.
                    skipped.append(SkippedFile(
                        path=_rel(p, root, is_dir),
                        reason=f"검사 대상 확장자 아님({p.suffix or '확장자 없음'}) — 검사되지 않았습니다",
                    ))
                    continue
                # 벤더 번들(*.min.js)은 **조용히 빼지 않는다** — 소스 룰 검사에서만
                # 빼고, 어떤 컴포넌트인지 식별해 취약점 검사로 넘긴다.
                if _looks_like_vendor_bundle_name(name):
                    rel_path = _rel(p, root, is_dir)
                    vb = _identify_vendor_bundle_file(p, rel_path)
                    if vb is not None:
                        vendor_bundles.append(vb)
                    skipped.append(SkippedFile(
                        path=rel_path,
                        reason=VENDOR_BUNDLE_SKIP_REASON,
                    ))
                    continue
                # 콘텐츠 해시가 박힌 빌드 산출물은 원본이 따로 있으므로 스킵.
                # single-line 초장문(내용 기준)은 아래에서 텍스트 확인 후 거른다.
                if _looks_like_build_artifact_name(name):
                    skipped.append(SkippedFile(
                        path=_rel(p, root, is_dir),
                        reason=BUILD_ARTIFACT_SKIP_REASON,
                    ))
                    continue
                try:
                    size = p.stat().st_size
                except OSError as exc_io:
                    skipped.append(SkippedFile(path=_rel(p, root, is_dir), reason=f"stat error: {exc_io!s}"))
                    continue
                if size > max_file_bytes:
                    skipped.append(SkippedFile(path=_rel(p, root, is_dir), reason=f"too large ({size} bytes)"))
                    continue
                if size == 0:
                    continue
                files_to_scan.append(p)
            # 여기서 break 하지 않는다 — 남은 디렉터리도 끝까지 걸어야
            # over_limit_count 가 실제 미검사 건수가 된다. os.walk 는 파일을
            # 열지 않으므로 추가 비용은 디렉터리 목록 읽기뿐이다.

    if over_limit_count:
        skipped.append(SkippedFile(
            path=str(root),
            reason=(
                f"max_files={max_files} reached — {over_limit_count}개 파일이 "
                f"검사되지 않았습니다"
            ),
        ))

    all_findings: list[Finding] = []
    scanned: list[str] = []
    content_hashes: dict[str, list[str]] = {}   # 내용 해시 → 같은 내용 파일 경로들

    for f in files_to_scan:
        rel = _rel(f, root, is_dir)
        try:
            head = f.read_bytes()[:4096]
        except OSError as exc_io:
            skipped.append(SkippedFile(path=rel, reason=f"read error: {exc_io!s}"))
            continue
        if _looks_binary(head):
            skipped.append(SkippedFile(path=rel, reason="binary content (NUL detected)"))
            continue
        try:
            # utf-8-sig: BOM 을 **제거하고** 읽는다. utf-8 로 읽으면 BOM 이
            # U+FEFF 문자로 남아 `ast.parse` 가 SyntaxError 를 내고, AST 정밀
            # 엔진이 조용히 꺼진 채 regex 로만 검사된다(실측: Windows·한글
            # 환경에서 흔한 BOM 파일 2개에서 SQL 테인트 분석이 통째로 누락).
            text = f.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = f.read_text(encoding="cp949")
            except UnicodeDecodeError:
                skipped.append(SkippedFile(path=rel, reason="encoding: not utf-8 or cp949"))
                continue
        # single-line 초장문/평균 줄 과대 = 미니파이드 번들. 룰 대량 오탐의 원인.
        # 다만 **파일명에 `.min.` 이 없어도** 미니파이드 `.js` 는 벤더 라이브러리를
        # 그대로 받아 둔 경우가 흔하다(`vendor/lib.js`). 이름 규칙으로만 걸면 그쪽이
        # 통째로 사각지대로 남으므로, 내용으로 판정된 것도 컴포넌트 식별을 시도한다.
        if _looks_minified(text):
            if f.suffix.lower() in {".js", ".mjs", ".cjs"}:
                vb = _identify_vendor_bundle_file(f, rel, detected_by="content", text=text)
                if vb is not None:
                    vendor_bundles.append(vb)
                skipped.append(SkippedFile(path=rel, reason=VENDOR_BUNDLE_SKIP_REASON))
            else:
                skipped.append(SkippedFile(path=rel, reason=BUILD_ARTIFACT_SKIP_REASON))
            continue
        # 내용 해시 — 같은 파일이 여러 경로에 복사돼 발견이 배수로 보이는 상황을
        # 리포트가 "동일 파일 N곳"으로 설명할 수 있게 한다(예: ssl/ 폴더 복제).
        content_hashes.setdefault(
            hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(), []
        ).append(rel)
        report = scan_code(text, filename=rel, scenario=scenario, profile=profile)
        all_findings.extend(report.findings)
        # 이름이 비밀을 뜻하는 파일에 값처럼 보이는 내용이 있으면 별도 발행.
        # 파일명 + 내용을 함께 봐야 하는 판정이라 regex 룰로는 만들 수 없다.
        if _is_secret_filename(f.name):
            hit, evidence_no, evidence_line = _looks_like_secret_material(text)
            if hit:
                keyfile_rule = lookup_rule("GOV-SECRET-KEYFILE-001")
                if keyfile_rule is not None:
                    all_findings.append(build_finding(
                        keyfile_rule, filename=rel, line_no=evidence_no,
                        evidence=_redact_evidence(evidence_line),
                        engine="secret-file",
                    ))
        scanned.append(rel)
        # 외부 연결 인벤토리: 코드의 외부 API 호출 + package.json 의 직접 의존성.
        external.extend(extract_api_connections(text, rel))
        external.extend(extract_static_resources(text, rel))
        if f.name.lower() == "package.json":
            external.extend(
                inventory_packages(parse_manifest_packages(text, "npm"), rel)
            )

    for mpath, eco in manifest_files:
        try:
            mtext = mpath.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue
        external.extend(
            inventory_packages(parse_manifest_packages(mtext, eco), _rel(mpath, root, is_dir))
        )

    # 승인된 예외(.gvskb-exceptions.yaml) — 발견을 숨기지 않고 표시만 하며,
    # 요약(건수·차단)과 exit code 는 비억제 발견 기준으로 계산한다.
    from .suppressions import apply_suppressions, load_exceptions
    sup = apply_suppressions(all_findings, load_exceptions(root))
    active = [f for f in all_findings if not f.suppressed]
    suppression_summary = None
    if sup.applied or sup.expired or sup.invalid:
        suppression_summary = {
            "applied": sup.applied,
            "expired": sup.expired,
            "invalid": sup.invalid,
        }

    _eff_profile, _profile_fallback = _profile_resolution(profile, load_profile(profile))
    report = ScanReport(
        target=str(root),
        scenario=scenario,
        profile=_eff_profile,
        profile_fallback=_profile_fallback,
        summary=_summary(active),
        findings=all_findings,
        scanned_files=scanned,
        skipped_files=skipped,
        external_surface=dedupe_connections(external),
        scan_mode=_current_scan_mode(),
        intel_freshness=_intel_freshness(),
        suppression_summary=suppression_summary,
        vendor_bundles=vendor_bundles,
        # 발견이 있는 파일 중 복제본만 기록한다(무관한 중복 파일은 소음).
        duplicate_files=[
            {"hash": h[:12], "paths": sorted(paths)}
            for h, paths in sorted(content_hashes.items())
            if len(paths) > 1 and any(f.location.file in paths for f in all_findings)
        ],
        **_provenance(),
    )
    # 감사로그(옵트인, GVSKB_AUDIT_DIR) — 공공 점검 이력 증빙. 실패해도 스캔은 계속.
    from .audit import record_scan
    record_scan(report, "scan_path", caller=caller)
    return report


def detect_secrets_and_pii(code: str, *, filename: str = "<memory>") -> ScanReport:
    return scan_code(
        code,
        filename=filename,
        categories={"privacy-public-sector", "secret-scanning", "public-sector-internal"},
    )


def path_level_rule_ids() -> tuple[str, ...]:
    """``scan_path`` 가 직접 발행하는 룰 — 파일명·내용을 **함께** 봐야 하는 것들.

    어댑터(regex/AST)가 아니라 경로 순회 단계에서 판정하므로 여기에 선언한다.
    선언이 없으면 patterns 도 없고 발행 주체도 없는 '침묵하는 룰'이 된다.
    """
    return ("GOV-SECRET-KEYFILE-001",)


def parse_manifest_packages(manifest_text: str, ecosystem: str) -> list[dict]:
    """Parse common dependency manifests without executing package managers.

    각 항목은 ``version_exact`` 를 함께 싣는다. ``requests>=2.28`` 은 "2.28 이상"이지
    "2.28"이 아니다 — 설치된 것은 2.31.0 일 수 있다. 예전에는 연산자를 버리고 경계값을
    구체 버전처럼 다뤄, 2.31.0 을 쓰는 프로젝트에 2.28 의 취약점을 보고할 수 있었고
    그 판정이 레지스트리에 "2.28 에 대한 사실"로 제출됐다.

    경계값 검사 자체는 남긴다 — "이 제약이 취약한 버전을 허용한다"는 것도 실제 신호다.
    다만 그것이 **관측이 아니라 가정**임을 값에 실어 뒤에서 구분할 수 있게 한다.
    """
    packages: list[dict] = []
    eco = ecosystem.lower()
    if eco == "pypi":
        for raw in manifest_text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.!*+-]+)?", line)
            if m:
                version, op = m.group(3), m.group(2)
                packages.append({
                    "name": m.group(1),
                    "version": version,
                    # ``===`` 는 정규식상 ``==`` + 남은 ``=`` 로 잡히지 않으므로 다루지 않는다.
                    # 와일드카드(``2.*``)는 고정이 아니다.
                    "version_exact": bool(version) and op == "==" and "*" not in version,
                })
    elif eco == "npm":
        try:
            data = json.loads(manifest_text)
        except json.JSONDecodeError:
            return packages
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(data.get(key, {}) or {})
        for name, spec in deps.items():
            raw_spec = str(spec) if spec else ""
            version = raw_spec.lstrip("^~") if raw_spec else None
            # npm 은 접두사가 없어야 고정이다. ``4.17.0`` 은 고정, ``^4.17.0``·``>=4``·
            # ``*``·``latest``·git URL 은 아니다.
            exact = bool(version) and raw_spec == version and re.fullmatch(
                r"\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?", version,   # 4.17.0-beta.1 도 고정이다
            ) is not None
            packages.append({"name": name, "version": version, "version_exact": exact})
    return packages


def suggest_fix(rule_id: str, unsafe_code: str | None = None) -> dict:
    matched = lookup_rule(rule_id)
    if not matched:
        return {
            "rule_id": rule_id,
            "can_suggest": False,
            "message": "알 수 없는 룰입니다. finding의 rule_id를 확인하세요.",
        }
    return {
        "rule_id": rule_id,
        "can_suggest": True,
        "plain_title": matched["plain_title"],
        "safe_fix": matched.get("fix"),
        "can_auto_fix": bool(matched.get("auto", False)),
        "unsafe_code_preview": _redact_evidence(unsafe_code or ""),
        "note": "자동 수정은 diff 미리보기 후 적용해야 하며, 업무 로직 변경은 담당자 확인이 필요합니다.",
    }
