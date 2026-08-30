"""자기검사 8차 — 외부 연결 인벤토리가 '호출'과 '표·주석·문서·테스트'를 구분한다.

실측(2026-08-29, 자기검사): 111행 중 제품 코드의 실제 아웃바운드는 10건. 스캐너 자기
카탈로그 소스의 주석 한 줄이 "서버 공인 IP 노출 ⚠"로, `docs.python.org` 참고 링크가
"Python 설치본 다운로드·개인정보 인접"으로 올라왔다. 개인정보 신호 13건 중 정당한
것은 0건이었다.
"""
from __future__ import annotations

from gvskb.scanners.external_surface import extract_api_connections, _lookup_host, _URL_RE


def _one(code: str, filename: str = "app.py"):
    out = extract_api_connections(code, filename)
    assert out, code
    return out[0]


def test_comment_line_url_is_comment_context():
    c = _one("# 참고: https://api.ipify.org 는 서버 IP 를 돌려준다\nx = 1", "catalog.py")
    assert c.context == "comment" and c.review_level == "info"


def test_catalog_table_is_data_table_context():
    code = '''HOSTS = (
    ("api.openai.com", "ai"),
    ("api.stripe.com", "payment"),   # 결제·카드 토큰
    ("api.mixpanel.com", "analytics"),
)'''
    out = extract_api_connections(code, "catalog.py")
    assert out and all(c.context == "data-table" for c in out)
    assert not any(c.pii_adjacent for c in out), "카탈로그 설명문의 '카드'에 자기 매칭하면 안 된다"


def test_real_call_is_runtime_and_pii_warns():
    c = _one('resp = requests.post("https://api.openai.com/v1/chat", json={"rrn": rrn})', "bot.py")
    assert c.context == "runtime" and c.pii_adjacent and c.review_level == "warn"


def test_pii_word_inside_url_path_does_not_count():
    c = _one('references = ["https://docs.python.org/3/library/secrets.html"]', "rules.py")
    assert not c.pii_adjacent
    assert "문서 사이트" in c.data_summary


def test_test_file_literal_is_test_context():
    c = _one('resp = requests.post("https://api.openai.com/v1/chat", json={"rrn": rrn})', "tests/test_bot.py")
    assert c.context == "test" and c.review_level == "info"


def test_host_lookup_is_suffix_based():
    assert _lookup_host("docs.python.org")[0] == "other"
    assert _lookup_host("www.python.org")[0] == _lookup_host("python.org")[0]
    assert _lookup_host("evilpython.org")[2] is None


def test_fake_version_host_is_not_a_url():
    assert not _URL_RE.search("pip install git+https://github.com/x/y@v0.2.1")  or \
        _URL_RE.search("pip install git+https://github.com/x/y@v0.2.1").group(1) == "github.com"


def test_stats_count_unique_live_hosts(tmp_path):
    from gvskb.report import _external_stats
    from gvskb.scanner import scan_path
    for i in range(3):
        (tmp_path / f"m{i}.py").write_text(
            'requests.post("https://api.openai.com/v1/chat", json={"rrn": rrn})\n', encoding="utf-8")
    (tmp_path / "notes.py").write_text('# https://api.openai.com 참고\n', encoding="utf-8")
    rep = scan_path(str(tmp_path))
    _api, _pkg, gukoe, warn = _external_stats(rep)
    assert gukoe == 1 and warn == 1


def test_ipify_wording_has_no_markdown_emphasis():
    c = _one('ip = requests.get("https://api.ipify.org").text', "net.py")
    assert "**" not in c.data_summary and "전송" in c.data_summary
