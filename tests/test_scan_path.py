"""scan_path: 디렉토리·파일 일괄 검사 동작 확인."""
from __future__ import annotations

from pathlib import Path

from gvskb.scanner import scan_path


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_scan_path_aggregates_findings_across_files(tmp_path: Path) -> None:
    _write(
        tmp_path / "app.py",
        "name = input('name')\n"
        "cursor.execute(f\"SELECT * FROM complaints WHERE name = '{name}'\")\n",
    )
    _write(
        tmp_path / "settings.py",
        'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz"\n',
    )

    report = scan_path(tmp_path)

    rule_ids = {f.rule_id for f in report.findings}
    assert "GOV-SQL-INJECTION-001" in rule_ids
    assert any(rid.startswith("GOV-SECRET") for rid in rule_ids)
    assert report.summary.blocked is True
    assert {"app.py", "settings.py"} <= set(report.scanned_files)


def test_scan_path_skips_excluded_dirs(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "main.py", "import os\n")
    _write(
        tmp_path / "node_modules" / "evil" / "index.js",
        "eval(userInput)\n",
    )
    _write(
        tmp_path / "__pycache__" / "junk.py",
        'OPENAI_API_KEY = "sk-proj-zzzzzzzzzzzzzzzzzz"\n',
    )

    report = scan_path(tmp_path)

    for f in report.scanned_files:
        assert "node_modules" not in f
        assert "__pycache__" not in f


def test_scan_path_skips_binary_and_oversized(tmp_path: Path) -> None:
    big = tmp_path / "big.py"
    big.parent.mkdir(parents=True, exist_ok=True)
    big.write_text("x = 1\n" * 200_000, encoding="utf-8")  # > 1 MB
    (tmp_path / "blob.py").write_bytes(b"\x00\x01\x02binary")

    report = scan_path(tmp_path)

    skipped_reasons = {sf.path: sf.reason for sf in report.skipped_files}
    assert any("too large" in r for r in skipped_reasons.values())
    assert any("binary" in r for r in skipped_reasons.values())


def test_scan_path_returns_clean_report_for_safe_code(tmp_path: Path) -> None:
    _write(
        tmp_path / "safe.py",
        'def total(items):\n'
        '    return sum(item.price for item in items)\n'
        '\n'
        'cursor.execute("SELECT * FROM t WHERE name=%s", (name,))\n',
    )

    report = scan_path(tmp_path)
    assert report.summary.finding_count == 0
    assert report.summary.blocked is False
    assert "safe.py" in report.scanned_files


def test_scan_path_returns_skipped_entry_for_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    report = scan_path(missing)
    assert report.summary.finding_count == 0
    assert len(report.skipped_files) == 1
    assert report.skipped_files[0].reason == "path does not exist"


# ---------------------------------------------------------------------------
# 노이즈 제거 — 빌드 산출물(압축/번들·빌드 출력 디렉터리) 자동 제외
# ---------------------------------------------------------------------------

from gvskb.scanner import (  # noqa: E402
    BUILD_ARTIFACT_SKIP_REASON,
    VENDOR_BUNDLE_SKIP_REASON,
)

# 룰이 줄마다 걸리는 미니파이드 번들 한 줄. 검사하면 오탐이 폭주한다.
_NOISY = "function deleteNode(){};function removeItem(){};agent.send_email();\n" * 40


def test_scan_path_excludes_build_output_dirs(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "app.py", "import os\n")
    _write(tmp_path / "public" / "assets" / "bundle.js", _NOISY)
    _write(tmp_path / ".puppeteer-cache" / "chrome.js", _NOISY)
    _write(tmp_path / ".tmp" / "scratch.js", _NOISY)
    _write(tmp_path / "dist" / "out.js", _NOISY)

    report = scan_path(tmp_path)

    # 노이즈 파일은 한 건도 검사되지 않는다.
    for f in report.scanned_files:
        assert "public/assets" not in f.replace("\\", "/")
        assert ".puppeteer-cache" not in f
        assert ".tmp" not in f
        assert "dist" not in f
    # 제외 사실은 빌드 산출물로 기록된다(버리되 정직) — 이제 **몇 개를** 안
    # 봤는지 함께 적는다. 디렉터리를 1건으로 세면 규모가 사라진다.
    build = [s for s in report.skipped_files if "빌드 산출물" in (s.reason or "")]
    assert len(build) >= 3
    assert all("파일 미검사" in (s.reason or "") for s in build if s.path.endswith("/"))
    # `.tmp` 는 빌드 산출물이 **아니다** — 임시·업로드 디렉터리로 따로 기록한다.
    staging = [s for s in report.skipped_files if s.path.rstrip("/").endswith(".tmp")]
    assert len(staging) == 1
    assert "임시·업로드 디렉터리" in staging[0].reason
    assert "빌드 산출물" not in staging[0].reason


def test_scan_path_skips_minified_and_hashed_files(tmp_path: Path) -> None:
    # 해시 파일명 = 빌드 산출물(원본이 따로 있음).
    # `*.min.js` = 벤더 번들(이름 신호) · 미니파이드 `.js` = 벤더 번들(내용 신호).
    # 셋 다 소스 룰 검사에서는 빠지지만 **사유가 다르다** — 벤더 번들은 조용히
    # 버리지 않고 컴포넌트 취약점 검사로 넘긴다(라운드6).
    _write(tmp_path / "src" / "main.py", "import os\n")
    _write(tmp_path / "src" / "index-3f9a2c1b.js", _NOISY)   # 해시 파일명
    _write(tmp_path / "src" / "widget.min.js", "var a=1;\n" * 5)  # *.min.*
    _write(tmp_path / "src" / "inline.js", "x" * 3000 + ";\n")  # single-line 초장문

    report = scan_path(tmp_path)

    scanned = {f.replace("\\", "/") for f in report.scanned_files}
    assert "src/main.py" in scanned
    assert "src/index-3f9a2c1b.js" not in scanned
    assert "src/widget.min.js" not in scanned
    assert "src/inline.js" not in scanned
    build = [s.path.replace("\\", "/") for s in report.skipped_files
             if s.reason == BUILD_ARTIFACT_SKIP_REASON]
    assert build == ["src/index-3f9a2c1b.js"]
    vendor = {s.path.replace("\\", "/") for s in report.skipped_files
              if s.reason == VENDOR_BUNDLE_SKIP_REASON}
    assert vendor == {"src/widget.min.js", "src/inline.js"}
    # 제외로 끝나지 않고 컴포넌트 후보로 남아야 한다(이름 신호 vs 내용 신호 구분).
    assert {(b["name"], b["detected_by"]) for b in report.vendor_bundles} == {
        ("widget", "name"), ("inline", "content"),
    }


def test_scan_path_keeps_real_source_when_noise_present(tmp_path: Path) -> None:
    # 노이즈를 걷어내도 진짜 위험은 그대로 잡혀야 한다(과잉 제외 방지).
    _write(
        tmp_path / "src" / "app.py",
        "name = input('name')\n"
        "cursor.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n",
    )
    _write(tmp_path / "public" / "assets" / "bundle-9e8d7c6b.js", _NOISY)

    report = scan_path(tmp_path)
    rule_ids = {f.rule_id for f in report.findings}
    assert "GOV-SQL-INJECTION-001" in rule_ids
    assert "src/app.py" in {f.replace("\\", "/") for f in report.scanned_files}


# ---------------------------------------------------------------------------
# .mts / .cts — TypeScript 의 ESM/CJS 명시 확장자
#
# 실측(lexdiff)에서 이 두 확장자가 포함 목록에 없어 2,271줄과 외부 연결 11건이
# '검사조차 되지 않았다'. 발견 0이 안전으로 읽히는 미탐이므로, 확장자별로
# ① 파일이 실제로 열렸는지(scanned_files) ② 룰이 발화하는지(findings)
# ③ 언어 추론이 typescript 로 되는지(languages 필터가 붙은 룰이 걸리는지)를
# 각각 고정한다. 셋 중 하나만 확인하면 나머지가 조용히 깨질 수 있다.
# ---------------------------------------------------------------------------

_TS_MODULE_SNIPPET = 'const el = document.getElementById("x");\nel.innerHTML = userInput;\n'


def test_mts_and_cts_are_scanned_not_skipped(tmp_path: Path) -> None:
    for name in ("mod.mts", "mod.cts"):
        _write(tmp_path / name, _TS_MODULE_SNIPPET)

    report = scan_path(tmp_path)

    scanned = {Path(p).name for p in report.scanned_files}
    assert "mod.mts" in scanned, "「.mts」가 검사 대상에서 빠졌습니다"
    assert "mod.cts" in scanned, "「.cts」가 검사 대상에서 빠졌습니다"


def test_mts_and_cts_findings_fire_with_typescript_language(tmp_path: Path) -> None:
    """확장자만 통과시키고 언어 추론을 빠뜨리면, languages:[typescript] 룰이
    조용히 건너뛰어진다 — 파일은 '검사됨'인데 룰은 안 도는 최악의 상태."""
    _write(tmp_path / "mod.mts", _TS_MODULE_SNIPPET)
    _write(tmp_path / "mod.cts", _TS_MODULE_SNIPPET)

    report = scan_path(tmp_path)

    hit = {Path(f.location.file).name for f in report.findings
           if f.rule_id == "KISA-JS-INPUT-04"}
    assert hit == {"mod.mts", "mod.cts"}, f"KISA-JS-INPUT-04 미발화: {hit}"


def test_mts_external_connection_is_inventoried(tmp_path: Path) -> None:
    """미탐의 실제 피해는 '외부 연결 11건 누락'이었다 — 룰뿐 아니라
    외부 연결 인벤토리도 .mts 에서 수집되는지 함께 고정한다."""
    _write(
        tmp_path / "client.mts",
        'export const r = await fetch("https://generativelanguage.googleapis.com/v1/models");\n',
    )

    report = scan_path(tmp_path)

    hosts = {c.target for c in report.external_surface}
    assert "generativelanguage.googleapis.com" in hosts, f"수집된 host: {hosts}"


def test_mts_infers_typescript_so_python_rules_do_not_leak() -> None:
    """확장자를 포함 목록에만 넣고 언어 매핑을 빠뜨리면 eff_lang=None 이 되고,
    언어 필터는 '알 수 없으면 통과'라서 **파이썬 전용 룰까지 발화**한다 —
    미탐을 고치다 오탐을 만드는 전형. `.ts` 와 결과가 같아야 한다."""
    from gvskb.scanner import scan_code

    snippet = 'eval(request.args.get("q"))\nos.system(cmd)\npickle.loads(data)\n'
    baseline = {f.rule_id for f in scan_code(snippet, filename="x.ts").findings}
    for name in ("x.mts", "x.cts"):
        got = {f.rule_id for f in scan_code(snippet, filename=name).findings}
        assert got == baseline, f"{name} 결과가 .ts 와 다릅니다: {got ^ baseline}"


def test_mts_comment_lines_are_skipped() -> None:
    """주석 판정도 확장자 목록으로 갈린다. 빠지면 주석 속 예시 코드가
    전부 발견으로 올라온다(살아있지 않은 코드에 대한 오탐)."""
    from gvskb.scanner import scan_code

    commented = "// el.innerHTML = userInput;\n/* document.write(x) */\n"
    for name in ("x.mts", "x.cts"):
        ids = {f.rule_id for f in scan_code(commented, filename=name).findings}
        assert "KISA-JS-INPUT-04" not in ids, f"{name}: 주석 줄에서 발화 {ids}"


def test_mts_multiline_taint_is_tracked() -> None:
    """js-taint 는 자체 확장자 목록을 들고 있다. 빠지면 '윗줄 조립 + 아랫줄 실행'
    패턴이 통째로 사각지대가 된다 — regex 층이 가려 주지 못하는 고유 손실."""
    from gvskb.scanner import scan_code

    code = (
        'const q = "SELECT * FROM users WHERE name = \'" + name + "\'";\n'
        "db.query(q);\n"
    )
    for name in ("x.mts", "x.cts"):
        engines = {f.engine for f in scan_code(code, filename=name).findings
                   if f.rule_id == "KISA-JS-INPUT-01"}
        assert "js-taint" in engines, f"{name}: 다줄 taint 미탐 {engines}"


# ---------------------------------------------------------------------------
# max_files — 상한 절단을 '몇 개 못 봤는지'까지 정직하게 말한다
#
# 실측(lexdiff, 2026-08-08): 검사 대상 568개 중 500개만 검사되고 68개가 잘렸는데,
# skipped_files 에 한 줄만 들어가 리포트 제외 요약에는 "최대 파일 수 도달 1건"으로
# 보였다. 담당자가 읽는 숫자는 1, 실제 미검사는 68. 의존성 절단과 같은 결함이다.
# ---------------------------------------------------------------------------

def _missed_count(report) -> int | None:
    """절단 사유에서 미검사 건수를 **정확히** 뽑는다.

    `"5개 파일이…" in reason` 같은 부분문자열 검사는 쓰지 않는다 —
    "35개 파일이…" 가 "5개 파일이…" 를 포함해서, 과대계상 변이가 그대로
    통과했다(실제로 변이검사에서 놓쳤다)."""
    import re as _re
    for s in report.skipped_files:
        m = _re.search(r"max_files=\d+ reached — (\d+)개 파일이 검사되지 않았습니다$", s.reason or "")
        if m:
            return int(m.group(1))
    return None


def test_max_files_reports_how_many_were_not_scanned(tmp_path: Path) -> None:
    for i in range(12):
        _write(tmp_path / f"f{i:02d}.py", "x = 1\n")

    report = scan_path(tmp_path, max_files=5)

    assert len(report.scanned_files) == 5
    trunc = [s for s in report.skipped_files if "max_files" in (s.reason or "")]
    assert len(trunc) == 1
    # 핵심: 잘린 7개가 사유 문구 안에 수치로 남아야 한다.
    assert _missed_count(report) == 7, trunc[0].reason


def test_max_files_count_ignores_out_of_scope_files(tmp_path: Path) -> None:
    """검사 대상이 아닌 파일(.png 등)까지 세면 절단 규모가 부풀려진다 —
    과장된 경고는 무시되기 시작하고, 그러면 진짜 절단도 함께 무시된다."""
    # 이름 순서가 중요하다 — 검사 대상 아닌 파일이 상한 **뒤에** 와야 이 층을
    # 실제로 시험한다. png 를 앞에 두면 세는 지점에 도달하기 전에 지나가 버려
    # 필터를 지워도 테스트가 통과한다(변이검사에서 실제로 통과했다).
    for i in range(8):
        _write(tmp_path / f"a{i:02d}.py", "x = 1\n")
    for i in range(30):
        _write(tmp_path / f"z_img{i:02d}.png", "not-really-an-image")

    report = scan_path(tmp_path, max_files=3)

    trunc = [s for s in report.skipped_files if "max_files" in (s.reason or "")]
    assert len(trunc) == 1
    assert _missed_count(report) == 5, trunc[0].reason


def test_no_truncation_notice_when_under_limit(tmp_path: Path) -> None:
    """상한에 닿지 않았는데 경고가 뜨면 그것 자체가 오탐이다."""
    _write(tmp_path / "a.py", "x = 1\n")
    report = scan_path(tmp_path, max_files=100)
    assert not [s for s in report.skipped_files if "max_files" in (s.reason or "")]


def test_default_max_files_covers_a_realistic_repository() -> None:
    """기본값이 낮으면 아무도 옵션을 안 주는 기본 경로에서 조용히 잘린다.
    실측 저장소가 568개였으므로 기본값은 그보다 한참 위여야 한다."""
    from gvskb.scanner import DEFAULT_MAX_FILES

    assert DEFAULT_MAX_FILES >= 10_000, DEFAULT_MAX_FILES


# ---------------------------------------------------------------------------
# 제외 디렉터리는 '안 본 것'이지 '없는 것'이 아니다
#
# 실측(2026-08-10): 보안 포털의 `tmp/scan-targets/` 에 업로드된 타 기관 프로젝트가
# 남아 있었고, 그 안의 유효한 와일드카드 TLS **개인키 6사본**이 스캔·제외 어디에도
# 나타나지 않았다. `tmp` 가 빌드 산출물로 분류돼 디렉터리째 잘렸기 때문이다.
# 파일 단위에서는 같은 실패를 이미 고쳤지만(`_is_secret_filename` 우회), os.walk 는
# dirnames 를 먼저 쳐내므로 그 안전장치가 디렉터리 프루닝을 이기지 못했다.
# ---------------------------------------------------------------------------

_FAKE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAvV3fZ2p8Qw9sT1nKbGxRr7YmLd4HcJq0WsAeUiOpNvXtZgBk\n"
    "-----END RSA PRIVATE KEY-----\n"
)


def test_private_key_in_tmp_is_still_found(tmp_path: Path) -> None:
    """제외 디렉터리 안이라도 개인키는 반드시 보여야 한다."""
    _write(tmp_path / "src" / "app.py", "import os\n")
    _write(tmp_path / "tmp" / "scan-targets" / "up" / "ssl" / "site_key.pem", _FAKE_KEY)

    report = scan_path(tmp_path)

    scanned = {f.replace("\\", "/") for f in report.scanned_files}
    assert "tmp/scan-targets/up/ssl/site_key.pem" in scanned
    assert any(f.rule_id.startswith("GOV-SECRET") for f in report.findings)


def test_tmp_sweep_ignores_vendored_ca_bundles(tmp_path: Path) -> None:
    """과잉 교정 방지 — 중첩 .venv 의 공개 CA 번들까지 끌어오면 노이즈가 신호를 덮는다."""
    _write(tmp_path / "src" / "app.py", "import os\n")
    _write(
        tmp_path / "tmp" / "up" / ".venv" / "Lib" / "certifi" / "cacert.pem",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    _write(tmp_path / "tmp" / "up" / "ssl" / "real_key.pem", _FAKE_KEY)

    report = scan_path(tmp_path)

    scanned = {f.replace("\\", "/") for f in report.scanned_files}
    assert "tmp/up/ssl/real_key.pem" in scanned
    assert not [f for f in scanned if "cacert.pem" in f]


def test_excluded_directory_reports_how_many_files_were_not_scanned(tmp_path: Path) -> None:
    """디렉터리를 1건으로 세면 그 뒤의 수천 건이 보고서에서 사라진다."""
    _write(tmp_path / "src" / "app.py", "import os\n")
    for i in range(7):
        _write(tmp_path / "tmp" / "up" / f"f{i}.txt", "x\n")
    for i in range(4):
        _write(tmp_path / "dist" / f"b{i}.js", "var a=1;\n")

    report = scan_path(tmp_path)

    staging = next(s for s in report.skipped_files if s.path.rstrip("/").endswith("tmp"))
    assert "7개 파일 미검사" in staging.reason
    assert "임시·업로드 디렉터리" in staging.reason
    build = next(s for s in report.skipped_files if s.path.rstrip("/").endswith("dist"))
    assert "4개 파일 미검사" in build.reason
    assert "빌드 산출물" in build.reason      # 리포트 집계가 이 부분 문자열을 쓴다


# ---------------------------------------------------------------------------
# 자기 참조 — 보고서에는 증거 문구가 인용돼 있어 재검사하면 발견이 증식한다.
# 가드가 `.check-reports` 라는 **이름 하나**에만 걸려 있어, 산출물을 `reports/` 에
# 쓰는 프로젝트에서는 그대로 우회됐다(실측: 발견 49건 중 24건이 에코).
# ---------------------------------------------------------------------------

def test_gvskb_report_is_skipped_whatever_the_folder_is_called(tmp_path: Path) -> None:
    from gvskb.scanner import SELF_REPORT_SKIP_REASON

    _write(tmp_path / "src" / "app.py", "import os\n")
    _write(
        tmp_path / "reports" / "2026-08-09_보안점검.json",
        '{"target": "x", "engine_version": "0.3.0", "ruleset_digest": "abc",\n'
        ' "scanned_files": [], "findings": [{"evidence": "-----BEGIN RSA PRIVATE KEY-----"}]}\n',
    )
    # `.md` 는 애초에 검사 대상 확장자가 아니라 더 앞에서 걸러진다. 실제로 에코를
    # 만든 형식은 `.json` 과 `.html` 이었다(실측: HTML 보고서 1개에서 5건).
    _write(
        tmp_path / "산출물" / "점검.html",
        "<title>코드 보안 검사 결과</title>\n<code>-----BEGIN RSA PRIVATE KEY-----</code>\n",
    )

    report = scan_path(tmp_path)

    skipped = {s.path.replace("\\", "/"): s.reason for s in report.skipped_files}
    assert skipped.get("reports/2026-08-09_보안점검.json") == SELF_REPORT_SKIP_REASON
    assert skipped.get("산출물/점검.html") == SELF_REPORT_SKIP_REASON
    # 에코가 사라져야 한다 — 남의 보고서를 읽고 만든 발견은 이 프로젝트의 위험이 아니다.
    assert not [f for f in report.findings if "보안점검" in f.location.file or "점검" in f.location.file]


def test_real_source_is_not_mistaken_for_a_report(tmp_path: Path) -> None:
    """과잉 교정 방지 — 보고서를 다루는 **코드**까지 빼면 진짜 사각지대가 생긴다."""
    _write(
        tmp_path / "report_writer.py",
        '# 코드 보안 검사 결과 를 만드는 모듈\n'
        'API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz"\n',
    )
    _write(
        tmp_path / "data.json",
        '{"engine_version": "1.0", "note": "우리 서비스 설정"}\n',
    )

    report = scan_path(tmp_path)

    scanned = {f.replace("\\", "/") for f in report.scanned_files}
    assert "report_writer.py" in scanned
    assert "data.json" in scanned
    assert any(f.rule_id.startswith("GOV-SECRET") for f in report.findings)


def test_large_report_is_detected_even_though_markers_come_late(tmp_path: Path) -> None:
    """앞부분만 보면 놓친다 — 거대한 findings 배열이 마커를 한참 뒤로 민다.

    실측: 131KB 보고서에서 `ruleset_digest` 가 72,070자 지점에 있어, 앞 4,000자만
    보던 첫 구현이 그 파일 하나를 통째로 놓쳤고 에코 15건이 그대로 남았다.
    """
    from gvskb.scanner import SELF_REPORT_SKIP_REASON

    entry = (
        '    {"rule_id": "GOV-SECRET-APIKEY-001", '
        '"evidence": "-----BEGIN RSA PRIVATE KEY-----"}'
    )
    filler = ",\n".join(entry for _ in range(400))
    body = (
        '{"target": "x",\n "findings": [\n'
        + filler
        + '\n ],\n "engine_version": "0.3.0", "ruleset_digest": "abc"}\n'
    )
    # 마커가 앞 4,000자 밖으로 밀려 있어야 이 테스트가 의미를 갖는다.
    assert body.index('"ruleset_digest"') > 4000
    _write(tmp_path / "점검이력" / "big.json", body)

    report = scan_path(tmp_path)

    skipped = {s.path.replace("\\", "/"): s.reason for s in report.skipped_files}
    assert skipped.get("점검이력/big.json") == SELF_REPORT_SKIP_REASON
    assert not report.findings
