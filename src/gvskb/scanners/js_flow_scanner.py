"""JS·TS 요청 값 추적 엔진(`js-flow`) 어댑터 — **선택 설치**(tree-sitter, `pip install vibecode-checker[ts]`).

분석은 :mod:`.js_web_flows` 가 한다. 이 어댑터는 파일을 거르고(JS·TS, 서버 프레임워크 표지), 공용 파서(:mod:`._ts_parse`)의
결과를 넘기고, 발견을 만든다. 발견은 전부 근거 '유력'·결정 **검토**다 — Python 판(`python-flow`)과 같은 사유 문구로 감쇄한다.

엔진 순위(`policy.ENGINE_PRECISION`)에 넣지 않는다(순위 0). 같은 룰·같은 줄을 정규식·`js-taint` 가 이미 보고했으면 그쪽이 남는다.
필수 엔진도 아니다 — 없으면 이 발견만 빠지고 판정 기준은 같다. 줄 단위 대체 분석은 두지 않는다.
"""
from __future__ import annotations

from ..schema import Finding
from ._ts_parse import load_languages, parse
from .base import ScannerAdapter
from .regex_scanner import InlineIgnores, build_finding, lookup_rule

ENGINE = "js-flow"
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
_JS_LANGS = {"javascript", "typescript", "js", "ts"}
_REASON = ("웹 요청 값이 변수·함수를 거쳐 이 자리에 닿고, 이 파일에서 그 값을 검사한 흔적을 찾지 못했습니다. "
           "다른 파일·프레임워크 설정에서 검사한다면 수용 예외로 기록하고, 아니라면 조치하세요")


class JsFlowScanner(ScannerAdapter):
    name = ENGINE

    def is_available(self) -> bool:
        return load_languages() is not None

    def scan(self, code: str, *, filename: str = "<memory>", language: str | None = None,
             scenario: str | None = None, profile: str = "public-default-strict",
             categories: set[str] | None = None) -> list[Finding]:
        from ..policy import attenuate
        from ..schema import Decision
        from .js_web_flows import EMITTED_RULE_IDS, MAX_BYTES, has_framework_marker, scan_js_flows

        low = filename.lower()
        if not (low.endswith(_JS_SUFFIXES) or (language or "").lower() in _JS_LANGS):
            return []
        if len(code) > MAX_BYTES or not has_framework_marker(code):
            return []                                       # 파서도 부르지 않는다(라이브러리·브라우저 코드 대부분)
        if categories:
            wanted = {r for r in EMITTED_RULE_IDS if (lookup_rule(r) or {}).get("category") in categories}
            if not wanted:
                return []
        if not self.is_available():
            return []
        parsed = parse(code, filename)
        if parsed is None:
            return []
        root, src = parsed
        hits = scan_js_flows(root, src, filename)
        if not hits:
            return []
        ignores = InlineIgnores(code, "javascript")
        out: list[Finding] = []
        for rule_id, line_no, evidence, confidence in hits:
            rule = lookup_rule(rule_id)
            if rule is None or (categories and rule["category"] not in categories):
                continue
            if ignores.suppresses(line_no, rule_id, confidence):
                continue
            finding = build_finding(rule, filename=filename, line_no=line_no, evidence=evidence,
                                    engine=ENGINE, confidence=confidence)
            if finding.decision == Decision.block:
                finding = attenuate(finding, step="web_flow", decision=Decision.warn, reason=_REASON)
            out.append(finding)
        return out
