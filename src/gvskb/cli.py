"""gvskb CLI — MCP 없이도 단독으로 쓸 수 있는 공공 보안 스캐너 명령어.

공무원이 IT 부서 도움 없이 자기 PC에서 ``gvskb scan ./프로젝트`` 한 줄로
보고용 마크다운을 받아볼 수 있도록 설계되어 있습니다.

Subcommands:
    gvskb scan <path>            파일 또는 디렉토리 검사 → Markdown/JSON
    gvskb check-package <name>   PyPI/npm 패키지 단건 검사 (OSV.dev)
    gvskb report <findings.json> 저장된 ScanReport JSON을 Markdown으로 변환
    gvskb rules                  로드된 룰 수와 ID 목록
    gvskb doctor                 실행 환경·룰·MCP·네트워크 진단
    gvskb validate-rules         룰 frontmatter·중복·regex·만료 검증
    gvskb update-intel           CISA KEV·OSV 등 외부 보안 피드를 로컬 캐시에 갱신
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

from .intel import DEFAULT_PROPOSED_DIR, promote_kev_to_rules
from .report import render_html, render_markdown
from .scanner import DEFAULT_MAX_FILES, scan_path
from .schema import ScanReport

EXIT_OK = 0
EXIT_FINDINGS_WARN = 1
EXIT_FINDINGS_BLOCK = 2
EXIT_USAGE = 64
EXIT_NOT_FOUND = 66


# 라이브러리 기본값을 **그대로** 쓴다. 예전에는 여기에 500 을 따로 적어 두었는데,
# scanner.DEFAULT_MAX_FILES 를 20,000 으로 올렸을 때 이 줄이 남아 CLI 만 500 에
# 묶여 있었다 — 실제로 사용자가 쓰는 경로가 조용히 절단되고 있었다.
# 같은 숫자를 두 곳에 적으면 언젠가 어긋난다. 재선언하지 않는다.
SCAN_MAX_FILES_DEFAULT = DEFAULT_MAX_FILES


def _scan_reproduce_command(args: argparse.Namespace) -> str:
    """Reconstruct the minimal `gvskb scan` invocation that produced this run.

    Only non-default options are emitted so the command stays readable for the
    common case (`gvskb scan <path>`).

    **판정을 바꾸는 옵션은 하나도 빠뜨리면 안 된다.** 보고서는 이 명령 위에
    "같은 결과를 다시 만들거나 다른 환경에서 검증하려면"이라고 적는다 — 재현을
    명시적으로 주장하는 문장이다. 그런데 ``--include-installed``(전이 의존성
    포함 여부)와 ``--env``(쿨다운 기준일 3·7·14일)가 빠져 있었고, 둘 다 빠지면
    **발견이 줄어드는 방향**으로 결과가 달라진다. 검증하러 재실행한 사람이 더
    깨끗한 결과를 받고 "해소됐다"고 읽게 된다 — 도구가 스스로 만드는 초록불이다.

    종료 코드만 바꾸는 것(``--fail-on``)과 부산물만 만드는 것(``--registry-bundle``)
    은 넣지 않는다. 명령이 길어질 뿐 재현되는 판정은 같다.
    """
    parts: list[str] = ["gvskb", "scan", str(args.path)]
    if args.profile and args.profile != "public-default-strict":
        parts += ["--profile", args.profile]
    if args.scenario:
        parts += ["--scenario", args.scenario]
    if args.max_files and args.max_files != SCAN_MAX_FILES_DEFAULT:
        parts += ["--max-files", str(args.max_files)]
    if getattr(args, "check_deps", False):
        parts += ["--check-deps"]
    if getattr(args, "include_installed", False):
        parts += ["--include-installed"]
    if getattr(args, "env", None):
        parts += ["--env", str(args.env)]
    return " ".join(parts)


def _scan_exit_code(report: ScanReport, fail_on: str) -> int:
    """`--fail-on` 정책 → 종료코드.

    판정은 ``gate.gate_status`` 한 곳에서만 계산한다. 예전에는 여기서
    ``report.summary.blocked`` 를 직접 읽었는데, 그 값은 **소스 발견만** 본다 —
    의존성 감사는 스캔이 끝난 뒤에 붙기 때문이다. 그래서 CRITICAL 취약 패키지가
    있어도 보고서 본문은 "배포 불가"인데 종료코드는 0 이었다.
    """
    from .gate import gate_status, should_fail

    if not should_fail(report, fail_on):
        return EXIT_OK
    return (EXIT_FINDINGS_BLOCK if gate_status(report)["blocked"]
            else EXIT_FINDINGS_WARN)


def _emit_doc_report(
    report: ScanReport,
    *,
    fmt: str,
    output: str | None,
    reproduce_command: str | None,
) -> None:
    """Stream or save a human report (markdown/html).

    파일 저장(-o) 시에는 비전공 사용자가 바로 열어볼 수 있도록 항상 .md 와 .html
    을 함께 만든다. stdout 출력일 때만 선택한 형식 하나를 낸다.
    """
    # 저장할 때는 **저장될 경로를 문서 안에 새긴다.** stderr 한 줄은 놓치기 쉽고,
    # 파일만 전달받은 사람은 원본이 어디 있는지 알 방법이 없다. 화면으로만
    # 흘려보내는 경우(`--stdout`)에는 저장 경로가 없으므로 적지 않는다.
    saved_md = str(Path(output).with_suffix(".md")) if output else None

    md = render_markdown(report, reproduce_command=reproduce_command, saved_path=saved_md)
    html_doc = render_html(report, reproduce_command=reproduce_command, saved_path=saved_md)

    if not output:
        text = html_doc if fmt == "html" else md
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return

    out = Path(output)
    # -o 로 규약 밖 경로를 준 경우 한 줄 안내 — 강제하지는 않는다(사용자 선택 존중).
    # 에이전트가 임의 경로를 지정해 점검 이력이 흩어지는 것을 줄이기 위함이다.
    from .report_store import REPORT_DIR_NAME
    if REPORT_DIR_NAME not in str(out).replace("\\", "/"):
        print(
            f"[gvskb] 참고: 표준 보관 위치는 <검사경로>/{REPORT_DIR_NAME}/ 입니다 "
            "(-o 를 생략하면 자동으로 그곳에 저장됩니다).",
            file=sys.stderr,
        )
    out.parent.mkdir(parents=True, exist_ok=True)
    md_path = out.with_suffix(".md")
    html_path = out.with_suffix(".html")
    md_path.write_text(md, encoding="utf-8")
    html_path.write_text(html_doc, encoding="utf-8")
    print(
        f"[gvskb] saved report: {md_path} + {html_path} "
        f"(scanned={len(report.scanned_files)}, findings={report.summary.finding_count})",
        file=sys.stderr,
    )


def _norm_pkg(name: str, ecosystem: str) -> str:
    """패키지 이름 비교용 정규화. pypi 는 ``-``/``_``/``.`` 를 구분하지 않는다(PEP 503)."""
    low = name.strip().lower()
    return re.sub(r"[-_.]+", "-", low) if ecosystem.lower() == "pypi" else low


def _direct_dependency_names(
    found: list[tuple[Path, str, str, str]], ecosystem: str,
) -> set[str]:
    """매니페스트에 **직접 적힌** 패키지 이름 집합.

    락파일이 있어 검사에서 건너뛴 매니페스트도 읽는다 — 여기서 필요한 것은 검사가
    아니라 '무엇이 직접 의존성인가'라는 목록이고, 그건 락파일에는 없다(락파일은
    직접·전이를 구분하지 않고 평면으로 담는다).
    """
    from .scanner import parse_manifest_packages

    names: set[str] = set()
    for p, _rel, eco, kind in found:
        if kind != "manifest" or eco != ecosystem:
            continue
        try:
            text = p.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue  # 읽기 실패는 이미 검사 경로에서 드러난다
        for pkg in parse_manifest_packages(text, eco):
            names.add(_norm_pkg(str(pkg["name"]), eco))
    return names


def _run_dependency_audit(
    root: Path,
    report: ScanReport,
    env_grade: str | None = None,
    include_installed: bool = False,
) -> dict | None:
    """스캔 결과에서 매니페스트를 찾아 패키지 취약·악성 검사를 수행한다.

    requirements*.txt(pypi)는 스캔에서 제외(skipped)되고 package.json(npm)은
    스캔 대상(scanned)이므로 두 목록을 모두 본다. 락파일은 audit_manifest 가
    'unparsed'로 정직하게 거절하므로 여기서는 원본 매니페스트만 수집한다.
    env_grade(E0~E2)는 쿨다운 기준일을 결정한다.
    """
    from .tools.check_package import audit_manifest

    # 락파일은 매니페스트의 **상위 집합**이다(전이 의존성 포함, 버전 고정).
    # 둘 다 있으면 락파일만 검사한다 — 중복 조회를 피하고 더 정확한 쪽을 쓴다.
    _LOCK_NAMES = {
        "poetry.lock": "pypi", "uv.lock": "pypi",
        "package-lock.json": "npm", "pnpm-lock.yaml": "npm", "yarn.lock": "npm",
    }

    def _classify(name: str) -> tuple[str, str] | None:
        """파일명 → (ecosystem, kind). kind: 'lock' | 'manifest'."""
        low = name.lower()
        if low in _LOCK_NAMES:
            return _LOCK_NAMES[low], "lock"
        if low.startswith("requirements") and low.endswith(".txt"):
            return "pypi", "manifest"
        if low == "package.json":
            return "npm", "manifest"
        return None

    found: list[tuple[Path, str, str, str]] = []  # (경로, 표시명, eco, kind)
    if root.is_file():
        hit = _classify(root.name)
        if hit:
            found.append((root, root.name, hit[0], hit[1]))
    else:
        seen: set[str] = set()
        for rel in [s.path for s in report.skipped_files] + list(report.scanned_files):
            name = rel.replace("\\", "/").rsplit("/", 1)[-1]
            hit = _classify(name)
            if not hit or rel in seen:
                continue
            seen.add(rel)
            p = root / rel
            if p.is_file():
                found.append((p, rel, hit[0], hit[1]))

    # 같은 디렉터리·같은 생태계에 락파일이 있으면 매니페스트는 건너뛴다.
    lock_dirs = {
        (rel.replace("\\", "/").rsplit("/", 1)[0] if "/" in rel.replace("\\", "/") else "", eco)
        for _, rel, eco, kind in found if kind == "lock"
    }
    manifests: list[tuple[Path, str, str]] = []  # (절대경로, 표시명, ecosystem)
    for p, rel, eco, kind in found:
        norm = rel.replace("\\", "/")
        d = norm.rsplit("/", 1)[0] if "/" in norm else ""
        if kind == "manifest" and (d, eco) in lock_dirs:
            continue  # 락파일이 이미 상위 집합을 검사한다
        manifests.append((p, rel, eco))

    # 벤더 번들(static/*.min.js)은 매니페스트가 없어도 검사 대상이다 — 매니페스트도
    # node_modules 도 없는 프로젝트에서는 이것이 **유일한 컴포넌트 발견 경로**다.
    vendor_bundles = list(getattr(report, "vendor_bundles", None) or [])

    if not manifests and not include_installed and not vendor_bundles:
        print(
            "[gvskb] --check-deps: 검사할 매니페스트(requirements*.txt·package.json)를 찾지 못했습니다.",
            file=sys.stderr,
        )
        return None

    async def _gather() -> list[dict]:
        out: list[dict] = []
        for p, rel, eco in manifests:
            try:
                text = p.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeDecodeError) as exc:
                out.append({
                    "ecosystem": eco, "manifest": rel, "verdict": "unparsed",
                    "requires_review": True, "parsed_count": 0, "checked_count": 0,
                    "unchecked_count": 0, "blocked": False, "checks": [],
                    "note": f"파일을 읽지 못했습니다: {exc}",
                })
                continue
            # filename 을 넘겨야 락파일 형식을 파일명으로 확정할 수 있다.
            audit = await audit_manifest(text, ecosystem=eco, env_grade=env_grade, filename=rel)
            audit["manifest"] = rel
            out.append(audit)

        # 설치 흔적(.venv·휠·node_modules)까지 확대 — 매니페스트에 적힌 직접
        # 의존성만 보면 **전이 의존성의 취약점을 통째로 놓친다**(상용 SCA 대비
        # 유일한 실질 격차였음). 목록만 읽고 패키지를 실행하지 않는다.
        if include_installed:
            from .tools.installed_packages import collect_installed_packages, to_requirements_text

            inv = collect_installed_packages(root)
            for eco, pkgs in (("pypi", inv["pypi"]), ("npm", inv["npm"])):
                if not pkgs:
                    continue
                text = to_requirements_text(pkgs, ecosystem=eco)
                audit = await audit_manifest(
                    text, ecosystem=eco, limit=len(pkgs), env_grade=env_grade,
                )
                audit["manifest"] = f"<설치된 패키지: {eco}>"
                audit["source"] = "installed-inventory"
                audit["inventory_stats"] = inv["stats"]
                # 설치본 중 **매니페스트에 이름이 있는 것은 직접 의존성**이다
                # (레지스트리 요청 §3). 이름은 매니페스트에, 정확한 버전은 설치
                # 흔적에 있으므로 둘을 합쳐야 "직접 의존성 + 실제 버전"이 되고,
                # 그 판단은 둘 다 읽는 이쪽에서만 할 수 있다.
                #
                # 이 구분이 없으면 심사 대기열이 구조적으로 빈다 — 매니페스트
                # 경로는 경계값이라 제출에서 걸리고, 설치본 경로는 전이 의존성과
                # 뭉뚱그려져 큐에 안 올라간다. 특히 not_found(슬롭스쿼팅 최강
                # 신호)가 그 사이로 조용히 빠진다.
                direct = _direct_dependency_names(found, eco)
                for c in audit.get("checks", []):
                    c["source_scope"] = (
                        "manifest" if _norm_pkg(str(c.get("name", "")), eco) in direct
                        else "installed"
                    )
                # 라이선스는 설치 메타데이터에서만 얻을 수 있다 — 검사 결과에 병기.
                lic_by_name = {
                    str(p.get("name", "")).lower(): p.get("license") for p in pkgs
                }
                for c in audit.get("checks", []):
                    lic = lic_by_name.get(str(c.get("name", "")).lower())
                    if lic and not (c.get("registry_metadata") or {}).get("license"):
                        c.setdefault("registry_metadata", {})
                        if isinstance(c["registry_metadata"], dict):
                            c["registry_metadata"]["license"] = lic
                        c["license_source"] = "installed-metadata"
                out.append(audit)

        # 벤더 번들(`static/*.min.js`) — 그 자체가 프로젝트가 실행하는 남의 코드다.
        # 실측(공공 Flask 프로젝트): `xlsx 0.18.5` 가 CVE-2023-30533 등에 해당하는데, 예전에는
        # '빌드 산출물'로 제외돼 매니페스트·설치본 어느 경로에도 걸리지 않았다.
        if vendor_bundles:
            from .tools.vendor_bundle import audit_vendor_bundles

            out.append(await audit_vendor_bundles(vendor_bundles, env_grade=env_grade))
        return out

    return {"audits": asyncio.run(_gather())}


def _emit_registry_bundle(
    args: argparse.Namespace,
    dependency_audit: dict | None,
    saved_report: Path | None,
) -> None:
    """반입 번들을 쓴다 — 명시 경로(``--registry-bundle``)와 리포트 사이드카.

    리포트를 파일로 남길 때만 사이드카를 만든다. 화면으로만 출력한 실행(``--stdout``)
    에서 파일이 슬그머니 생기면, 담당자가 만든 줄 모르는 반출 심사 대상이 디스크에
    남게 된다.
    """
    if not dependency_audit or not (dependency_audit.get("audits") or []):
        return
    explicit = getattr(args, "registry_bundle", None)
    if not explicit and saved_report is None:
        return

    from .tools.registry_bundle import bundle_notice, build_bundle, write_bundle

    bundle = build_bundle(dependency_audit, caller="cli:manual")
    targets: list[Path] = []
    if explicit:
        targets.append(Path(explicit))
    if saved_report is not None:
        targets.append(saved_report.with_name(saved_report.stem + ".registry-bundle.json"))

    for t in targets:
        try:
            path, sidecar = write_bundle(bundle, t)
        except OSError as exc:
            # 번들 쓰기 실패가 검사 실패는 아니다 — 단, 침묵하지도 않는다.
            print(f"[gvskb] ⚠ 반입 번들을 쓰지 못했습니다({t}): {exc}", file=sys.stderr)
            continue
        print(f"[gvskb] 반입 번들 저장: {path} (+ {sidecar.name})", file=sys.stderr)
    print(bundle_notice(bundle), file=sys.stderr)


def _cmd_scan(args: argparse.Namespace) -> int:
    # (#1) 존재하지 않는 경로를 "위험 없음"으로 침묵 처리하지 않는다 — 보안
    # 도구에서 경로 오타를 통과시키면 거짓 안심을 준다. 명확히 실패시킨다.
    target = Path(args.path)
    if not target.exists():
        print(
            f"[gvskb] 경로를 찾을 수 없습니다: {target}\n"
            f"         경로(오타·상대경로)를 확인하세요. 검사를 수행하지 않았습니다.",
            file=sys.stderr,
        )
        return EXIT_NOT_FOUND

    # (#4) 알 수 없는 프로파일을 조용히 수용하지 않는다 — 오타 시 의도와 다른
    # 정책이 적용될 수 있으므로 즉시 경고한다.
    #
    # **여기서 args.profile 을 바꾸지 않는다.** 예전에는 기본값으로 미리 치환했는데,
    # 그러면 스캐너가 정상 프로파일을 받은 것으로 보여 `profile_fallback` 이 남지
    # 않았다 — stderr 경고는 휘발되고 **결재 붙임으로 나가는 리포트에는 운영자가
    # 무엇을 요청했는지 흔적이 없었다**(하네스 지적, 2026-08-03).
    # 스캐너가 대체·기록을 함께 처리하므로 여기서는 알리기만 한다. 재현 명령에도
    # 운영자가 실제로 친 값이 남아, 그 명령을 다시 실행하면 같은 결과가 나온다.
    try:
        from .profiles import DEFAULT_PROFILE_ID, list_profiles
        known = set(list_profiles())
        if known and args.profile not in known:
            print(
                f"[gvskb] ⚠ 알 수 없는 프로파일 '{args.profile}' — 기본값 "
                f"'{DEFAULT_PROFILE_ID}'로 진행합니다. (사용 가능: {', '.join(sorted(known))})",
                file=sys.stderr,
            )
    except Exception:
        pass  # 프로파일 목록을 못 읽어도 스캔 자체는 진행

    report = scan_path(
        args.path,
        scenario=args.scenario,
        profile=args.profile,
        max_files=args.max_files,
    )

    # --check-deps: 발견된 매니페스트(requirements.txt·package.json)의 패키지
    # 취약·악성 검사를 함께 수행해 리포트에 병합한다 — 보안팀이 "코드+패키지"
    # 위험을 한 문서에서 보게 한다. 전송 데이터는 패키지명·버전뿐이다.
    if getattr(args, "check_deps", False):
        report.dependency_audit = _run_dependency_audit(
            target, report,
            env_grade=getattr(args, "env", None),
            include_installed=getattr(args, "include_installed", False),
        )

    # (#1) 경로는 존재하지만 검사 대상 파일이 0개인 경우(빈 폴더·확장자 불일치)
    # 도 "위험 없음"으로 오해하지 않도록 경고한다.
    if not report.scanned_files:
        print(
            "[gvskb] ⚠ 검사된 파일이 없습니다 (스캔 대상 0개). "
            "지원 확장자·제외 디렉터리·--max-files 설정을 확인하세요.",
            file=sys.stderr,
        )

    if args.format in ("json", "sarif"):
        if args.format == "sarif":
            from .report import render_sarif
            payload = render_sarif(report)
        else:
            payload = report.model_dump(mode="json")
        output_text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(output_text, encoding="utf-8")
            print(
                f"[gvskb] saved {args.format} report to {out_path} "
                f"(scanned={len(report.scanned_files)}, findings={report.summary.finding_count})",
                file=sys.stderr,
            )
            _emit_registry_bundle(args, report.dependency_audit, out_path)
        else:
            sys.stdout.write(output_text)
            if not output_text.endswith("\n"):
                sys.stdout.write("\n")
            _emit_registry_bundle(args, report.dependency_audit, None)
    else:
        # -o 를 주지 않아도 **규약 위치에 저장**한다(--stdout 으로만 끈다).
        # 기존에는 화면에 흘려보내 사라졌고, 결재에 첨부할 파일이 남지 않았다.
        output = args.output
        if not output and not getattr(args, "stdout", False):
            from .report_store import ensure_writable, gitignore_hint, resolve_report_path
            base, fallback_note = ensure_writable(resolve_report_path(args.path))
            output = str(base)
            if fallback_note:
                print(f"[gvskb] ⚠ {fallback_note}", file=sys.stderr)
            else:
                print(f"[gvskb] {gitignore_hint()}", file=sys.stderr)
        _emit_doc_report(
            report,
            fmt=args.format,
            output=output,
            reproduce_command=_scan_reproduce_command(args),
        )
        _emit_registry_bundle(args, report.dependency_audit, Path(output) if output else None)

    _emit_sbom(args, report)
    return _scan_exit_code(report, args.fail_on)


def _emit_sbom(args: argparse.Namespace, report: ScanReport) -> None:
    """`--sbom <경로>` 로 CycloneDX 를 저장한다.

    의존성 검사 없이 SBOM 만 달라고 하면 **빈 문서를 조용히 쓰지 않는다** —
    컴포넌트 0개짜리 SBOM 은 "의존성이 없다"로 읽히는데, 실제로는 안 본 것이다.
    """
    path = getattr(args, "sbom", None)
    if not path:
        return
    from .sbom import to_cyclonedx

    audit = report.dependency_audit
    if not audit or not any((a.get("checks") or []) for a in _sbom_audits(audit)):
        print(
            "[gvskb] ⚠ --sbom: 의존성 검사 결과가 없어 SBOM 을 쓰지 않았습니다. "
            "`--check-deps` 를 함께 주세요 — 컴포넌트 0개짜리 SBOM 은 "
            "'의존성이 없다'로 읽힙니다.",
            file=sys.stderr,
        )
        return
    doc = to_cyclonedx(
        audit,
        target=str(report.target),
        engine_version=report.engine_version,
        ruleset_version=report.ruleset_version,
        ruleset_digest=report.ruleset_digest,
        generated_at=report.generated_at,
    )
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    n_vuln = len(doc.get("vulnerabilities") or [])
    print(f"[gvskb] SBOM(CycloneDX {doc['specVersion']}) 저장: {out} "
          f"— 컴포넌트 {len(doc['components'])}개 · 취약점 {n_vuln}건", file=sys.stderr)


def _sbom_audits(audit: dict) -> list[dict]:
    inner = audit.get("audits")
    return [a for a in inner if isinstance(a, dict)] if isinstance(inner, list) else [audit]


def _cmd_sbom(args: argparse.Namespace) -> int:
    """건네받은 SBOM 을 그대로 검사한다 — 소스가 없어도 컴포넌트는 볼 수 있다."""
    import asyncio as _asyncio

    from .sbom import SbomParseError, parse_sbom
    from .tools.check_package import check_package_impl

    try:
        text = Path(args.file).read_text(encoding="utf-8-sig")
    except OSError as exc:
        print(f"[gvskb] SBOM 파일을 읽지 못했습니다: {exc}", file=sys.stderr)
        return EXIT_NOT_FOUND
    try:
        parsed = parse_sbom(text)
    except SbomParseError as exc:
        print(f"[gvskb] {exc}", file=sys.stderr)
        return EXIT_USAGE

    pkgs = parsed["packages"][: args.limit]
    dropped = len(parsed["packages"]) - len(pkgs)

    async def _run() -> list[dict]:
        return [await check_package_impl(p["name"], version=p["version"],
                                         ecosystem=p["ecosystem"])
                for p in pkgs]

    checks = _asyncio.run(_run()) if pkgs else []
    vuln = [c for c in checks if c.get("verdict") in ("vulnerable", "malicious")]
    unchecked = [c for c in checks if not c.get("checked")]

    if args.json:
        sys.stdout.write(json.dumps({
            "format": parsed["format"], "spec_version": parsed["spec_version"],
            "checked_count": len(checks), "vulnerable_count": len(vuln),
            "unchecked_count": len(unchecked),
            "skipped": parsed["skipped"], "truncated_count": max(0, dropped),
            "checks": checks,
        }, ensure_ascii=False, indent=2) + "\n")
    else:
        print(f"SBOM: {parsed['format']} {parsed['spec_version'] or ''}".rstrip())
        print(f"  컴포넌트 {len(parsed['packages'])}개 중 {len(checks)}개 검사 · "
              f"취약 {len(vuln)}종 · 판정 불가 {len(unchecked)}종")
        for c in vuln:
            print(f"  [{c.get('max_cve') or '?'}] {c['name']} {c.get('version')} "
                  f"— 취약점 {c.get('vulnerability_count')}건"
                  + (f" · 권고 {c['recommended_version']}" if c.get("recommended_version") else ""))
        # 건너뛴 것과 잘린 것은 **반드시** 말한다. 조용히 빠지면 "안전"으로 읽힌다.
        if parsed["skipped"]:
            print(f"  ⚠ SBOM 에서 읽지 못한 컴포넌트 {len(parsed['skipped'])}개 "
                  "— '안전'이 아니라 '보지 못함'입니다:")
            for s in parsed["skipped"][:5]:
                print(f"      · {s['name']}: {s['reason']}")
            if len(parsed["skipped"]) > 5:
                print(f"      · 외 {len(parsed['skipped']) - 5}개")
        if dropped > 0:
            print(f"  ⚠ 상한(--limit {args.limit})에 걸려 {dropped}개를 검사하지 "
                  "않았습니다 — 상한을 올려 다시 검사하세요.")
        if unchecked:
            print("  ⚠ 판정 불가는 '안전'이 아닙니다 — 온라인 환경에서 다시 검사하세요.")

    if vuln:
        return EXIT_FINDINGS_BLOCK
    return EXIT_FINDINGS_WARN if (unchecked or parsed["skipped"] or dropped > 0) else EXIT_OK


def _cmd_check_package(args: argparse.Namespace) -> int:
    from .tools.check_package import check_package_impl

    result = asyncio.run(check_package_impl(
        name=args.name, ecosystem=args.ecosystem, version=args.version,
        env_grade=getattr(args, "env", None),
    ))
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2))
    sys.stdout.write("\n")
    if (
        result.get("is_malicious_package")
        or result.get("verdict") in ("not_found", "registry_rejected")
    ):
        # 미존재(슬롭스쿼팅 의심)는 VCPS-C4-EXISTENCE 기준 차단급이다.
        # 기관 레지스트리가 명시적으로 차단한 패키지도 CI 를 통과시키면 안 된다.
        return EXIT_FINDINGS_BLOCK
    if result.get("vulnerability_count"):
        return EXIT_FINDINGS_WARN
    # 판정 불가(캐시 없는 오프라인·API 실패)는 '안전'이 아니다 — CI 게이트가
    # "검사 못 함"을 통과(0)로 처리하지 않도록 warn 코드로 실패시킨다.
    if not result.get("checked", False) or result.get("requires_review"):
        print(
            "[gvskb] ⚠ 판정 불가 — 검사가 수행되지 않았거나 추가 검토가 필요합니다. "
            "'안전'이 아닙니다 (온라인 환경 또는 `gvskb update-intel` 후 재검사).",
            file=sys.stderr,
        )
        return EXIT_FINDINGS_WARN
    return EXIT_OK


def _cmd_report(args: argparse.Namespace) -> int:
    src = Path(args.findings_json)
    if not src.exists():
        print(f"[gvskb] file not found: {src}", file=sys.stderr)
        return EXIT_NOT_FOUND
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[gvskb] invalid JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        report = ScanReport.model_validate(data)
    except Exception as exc:
        print(f"[gvskb] not a ScanReport: {exc}", file=sys.stderr)
        return EXIT_USAGE
    _emit_doc_report(
        report,
        fmt=getattr(args, "format", "markdown"),
        output=args.output,
        reproduce_command=args.reproduce_command,
    )
    return EXIT_OK


def _cmd_version(_args: argparse.Namespace) -> int:
    from . import __version__
    print(f"vibecode-checker (gvskb) {__version__}")
    return EXIT_OK


def _cmd_rules(_args: argparse.Namespace) -> int:
    from .scanner import RULES as RUNTIME_RULES

    print(f"runtime rules loaded: {len(RUNTIME_RULES)}")
    for r in RUNTIME_RULES:
        print(f"  {r['rule_id']:32s} {r['severity'].value:8s} {r['plain_title']}")
    return EXIT_OK


def _resolve_rules_dir_for_eval(override: str | None) -> Path:
    if override:
        return Path(override)
    from .scanners.regex_scanner import _resolve_rules_dir as _rd
    return _rd()


def _cmd_evaluate(args: argparse.Namespace) -> int:
    from . import evaluation

    rules_dir = _resolve_rules_dir_for_eval(args.rules_dir)
    report = evaluation.evaluate_all(rules_dir)

    if args.format == "json":
        text = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
    elif args.format == "markdown":
        text = evaluation.format_markdown(report)
    else:
        text = evaluation.format_text(report)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        print(
            f"[gvskb] saved {args.format} evaluation to {out_path}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")

    # Any rule below 100% precision or recall surfaces as WARN exit so CI can gate.
    has_miss = any(
        (m.recall is not None and m.recall < 1.0)
        or (m.precision is not None and m.precision < 1.0)
        for m in report.per_rule
    )
    return EXIT_FINDINGS_WARN if has_miss else EXIT_OK


def _cmd_doctor(args: argparse.Namespace) -> int:
    from . import diagnostics

    network = not args.offline
    report = diagnostics.run_diagnostics(network=network)

    if args.json:
        sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(diagnostics.format_text_report(report))
        sys.stdout.write("\n")

    overall = report["overall"]
    if overall == "error":
        return EXIT_FINDINGS_BLOCK
    if overall == "warn":
        return EXIT_FINDINGS_WARN
    return EXIT_OK


def _cmd_update_intel(args: argparse.Namespace) -> int:
    from .intel import IntelCache, default_cache_dir, update_sources
    from .intel.sources.base import SOURCES

    cache_dir = Path(args.cache_dir) if args.cache_dir else default_cache_dir()
    cache = IntelCache(cache_dir)

    # GVSKB_MODE=offline → force --from-cache so the air-gapped policy is honored
    # without callers needing to remember the flag.
    offline_env = os.environ.get("GVSKB_MODE", "").lower() == "offline"
    if offline_env and not args.from_cache:
        print("[gvskb] GVSKB_MODE=offline detected — using cache only", file=sys.stderr)
        args.from_cache = True

    # Determine which sources to refresh
    if args.all:
        source_ids = list(SOURCES.keys())
    elif args.source:
        source_ids = [args.source]
    else:
        print("[gvskb] specify --source <id> or --all", file=sys.stderr)
        return EXIT_USAGE

    if args.from_cache:
        # Air-gapped mode: do not call network. Just report cache contents.
        # 신선도 초과 캐시를 [ OK ]로 보여주면 몇 달 묵은 반입 캐시가 최신처럼
        # 보인다 — age를 표시하고 stale이면 WARN으로 강등한다.
        out: list[dict] = []
        for sid in source_ids:
            entry = cache.load(sid)
            if entry is None:
                out.append({
                    "source_id": sid, "status": "warn", "item_count": 0,
                    "cache_path": str(cache.path_for(sid)), "fetched_at": "",
                    "error": "no cached data",
                })
                continue
            age = entry.age_days()
            stale = entry.is_stale()
            out.append({
                "source_id": sid,
                "status": "warn" if stale else "ok",
                "item_count": entry.item_count,
                "cache_path": str(cache.path_for(sid)),
                "fetched_at": entry.fetched_at,
                "age_days": age,
                "error": (
                    f"stale: {'?' if age is None else age}일 경과 — 외부망에서 update-intel 후 재반입 권장"
                    if stale else ""
                ),
            })
        if args.promote:
            out.append(_promote_kev_from_cache(cache, args))
        _print_update_results(out, json_mode=args.json)
        return EXIT_OK if all(r["status"] == "ok" for r in out) else EXIT_FINDINGS_WARN

    results = update_sources(source_ids, cache=cache)
    out = [r.to_dict() for r in results]

    # 감사로그(옵트인) — 어떤 피드를 언제 갱신했는지 남긴다.
    from .audit import record_update_intel
    record_update_intel(source_ids)

    if args.promote:
        out.append(_promote_kev_from_cache(cache, args))

    _print_update_results(out, json_mode=args.json)

    if any(r["status"] == "error" for r in out):
        return EXIT_FINDINGS_BLOCK
    if any(r["status"] == "warn" for r in out):
        return EXIT_FINDINGS_WARN
    return EXIT_OK


def _cmd_intel_bundle(args: argparse.Namespace) -> int:
    """망분리 반입 번들 — export(외부망)·import(망분리, sha256 전수 검증)."""
    from .intel.bundle import export_bundle, import_bundle

    cache_dir = Path(args.cache_dir) if args.cache_dir else None
    if args.action == "export":
        result = export_bundle(args.bundle, cache_dir=cache_dir)
    else:
        result = import_bundle(args.bundle, cache_dir=cache_dir)
        if result.get("ok"):
            from .audit import record_update_intel
            record_update_intel(list(result.get("sources", [])), tool="intel-bundle-import")

    if args.json:
        sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    elif result.get("ok"):
        verb = "내보냈습니다" if args.action == "export" else "반입했습니다(무결성 검증 통과)"
        print(f"[gvskb] 번들 {verb}: {result.get('bundle') or result.get('cache_dir')}")
        print(f"        sources: {', '.join(result.get('sources', []))}")
        if args.action == "import":
            print("        다음: `gvskb doctor --offline` 로 캐시 존재·신선도를 확인하세요.")
    else:
        print(f"[gvskb] ✖ {result.get('error', 'unknown error')}", file=sys.stderr)
    return EXIT_OK if result.get("ok") else EXIT_FINDINGS_WARN


def _cmd_intel_sync(args: argparse.Namespace) -> int:
    """인텔 캐시 자동 동기화 — 설정된 소스(폴더·URL)에서 번들을 당겨 반입한다."""
    from .intel.autopull import autopull_status, maybe_auto_update

    if args.status:
        st = autopull_status()
        if args.json:
            sys.stdout.write(json.dumps(st, ensure_ascii=False, indent=2) + "\n")
        else:
            print(f"[gvskb] 자동 갱신: {'켜짐' if st['enabled'] else '꺼짐(GVSKB_AUTO_UPDATE=off)'}")
            print(f"        갱신 필요: {'예' if st['needs_refresh'] else '아니오'} — {st['reason']}")
            print(f"        소스(폴더): {st['source_dir'] or '<미설정>'}")
            print(f"        소스(URL) : {st['source_url']}")
            if st["last_attempt_at"]:
                print(f"        마지막 시도: {st['last_attempt_at']} ({st['last_result']})")
        return EXIT_OK

    result = maybe_auto_update(force=args.force, verbose=not args.json)
    if args.json:
        sys.stdout.write(json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n")
    elif result.skipped_reason:
        print(f"[gvskb] 건너뜀: {result.skipped_reason}")
    elif result.ok:
        print(f"[gvskb] 인텔 캐시 갱신 완료 ← {result.source}")
        print(f"        sources: {', '.join(result.sources_updated or [])}")
    else:
        print(f"[gvskb] ✖ {result.error}", file=sys.stderr)

    if result.ok:
        from .audit import record_update_intel
        record_update_intel(list(result.sources_updated or []), tool="intel-sync")
        return EXIT_OK
    # 건너뜀(이미 최신)은 성공으로 본다 — CI에서 불필요한 실패를 만들지 않는다.
    return EXIT_OK if result.skipped_reason else EXIT_FINDINGS_WARN


def _promote_kev_from_cache(cache, args: argparse.Namespace) -> dict:
    """Convert the cached CISA KEV catalog into proposed-rule MD files."""
    entry = cache.load("cisa-kev")
    if entry is None:
        return {
            "source_id": "promote-kev",
            "status": "warn",
            "item_count": 0,
            "cache_path": str(cache.path_for("cisa-kev")),
            "error": "no cisa-kev cache to promote (run --source cisa-kev first)",
        }
    rules_dir = Path(args.rules_dir) if args.rules_dir else Path(DEFAULT_PROPOSED_DIR)
    limit = args.promote_limit if args.promote_limit and args.promote_limit > 0 else None
    result = promote_kev_to_rules(
        entry,
        rules_dir,
        overwrite=args.promote_overwrite,
        limit=limit,
    )
    # 수명주기: 승격과 함께, 기한(review_due)이 지나도록 승인되지 않은 초안을
    # 자동 폐기한다 — 사람이 카드를 하나하나 정리하지 않아도 목록이 최신으로 유지.
    from .intel import prune_expired_proposed
    prune = prune_expired_proposed(rules_dir)
    payload = result.to_dict()
    payload.update({
        "source_id": "promote-kev",
        "status": "ok",
        "item_count": payload["created_count"] + payload["skipped_existing_count"],
        "delta": payload["created_count"],
        "cache_path": payload["rules_dir"],
        "pruned_expired_count": prune["pruned_count"],
        "pruned_expired": prune["pruned"],
    })
    return payload


def _print_update_results(results: list[dict], *, json_mode: bool) -> None:
    if json_mode:
        sys.stdout.write(json.dumps(results, ensure_ascii=False, indent=2))
        sys.stdout.write("\n")
        return
    for r in results:
        marker = {"ok": "[ OK ]", "warn": "[WARN]", "error": "[ERR ]"}.get(r["status"], "[ ?? ]")
        delta = r.get("delta")
        delta_str = f" (Δ {delta:+d})" if delta else ""
        line = f"{marker}  {r['source_id']:20s} items={r.get('item_count', 0)}{delta_str}"
        print(line)
        if r.get("fetched_at"):
            print(f"        fetched_at: {r['fetched_at']}")
        if r.get("cache_path"):
            print(f"        cache: {r['cache_path']}")
        if r.get("error"):
            print(f"        error: {r['error']}")


def _cmd_ruleset(args: argparse.Namespace) -> int:
    """룰셋 신원 확인·갱신 — 게이트의 재현성 전제.

    확인만 하는 것이 기본이고, `--bump` 를 줘야 잠금 파일을 쓴다. 룰을 고칠
    때마다 자동으로 갱신하면 '버전을 올렸다'는 사람의 판단이 사라져, 잠금
    파일이 그냥 현재 상태를 따라다니는 장식이 된다.
    """
    from . import ruleset as ruleset_mod
    from .diagnostics import _resolve_rules_dir
    from .loader import load_all_rules

    rules_dir = Path(args.rules_dir) if args.rules_dir else _resolve_rules_dir()[0]
    if not rules_dir.exists():
        print(f"[gvskb] rules dir not found: {rules_dir}", file=sys.stderr)
        return EXIT_NOT_FOUND

    rules = load_all_rules(rules_dir)
    verdict = ruleset_mod.verify_lock(rules, rules_dir)

    if args.bump:
        path = ruleset_mod.write_lock(
            rules_dir, version=args.bump,
            digest=verdict["actual"], rule_count=verdict["rule_count"],
        )
        if args.json:
            sys.stdout.write(json.dumps(
                {"written": str(path), "version": args.bump, "digest": verdict["actual"],
                 "rule_count": verdict["rule_count"], "previous": verdict["version"]},
                ensure_ascii=False, indent=2) + "\n")
        else:
            prev = verdict["version"] or "(없음)"
            print(f"룰셋 잠금 갱신: {prev} → {args.bump}")
            print(f"  지문 {verdict['actual']} · 룰 {verdict['rule_count']}건")
            print(f"  {path}")
        return EXIT_OK

    if args.json:
        sys.stdout.write(json.dumps(verdict, ensure_ascii=False, indent=2) + "\n")
    else:
        mark = {"ok": "OK", "drift": "드리프트", "missing": "선언 없음"}[verdict["status"]]
        print(f"[{mark}] {verdict['message']}")
        print(f"  룰 {verdict['rule_count']}건 · 지문 {verdict['actual']}")
    return EXIT_OK if verdict["status"] == "ok" else EXIT_FINDINGS_BLOCK


def _cmd_validate_rules(args: argparse.Namespace) -> int:
    from . import validation
    from .diagnostics import _resolve_rules_dir

    rules_dir = Path(args.rules_dir) if args.rules_dir else _resolve_rules_dir()[0]
    if not rules_dir.exists():
        print(f"[gvskb] rules dir not found: {rules_dir}", file=sys.stderr)
        return EXIT_NOT_FOUND

    report = validation.validate_rules_dir(rules_dir)

    if args.json:
        sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(validation.format_text_report(report))
        sys.stdout.write("\n")

    overall = report["overall"]
    if overall == "error":
        return EXIT_FINDINGS_BLOCK
    # `--fail-on error` 는 CI 용이다. `review_due` 만료처럼 **달력 때문에 언젠가
    # 반드시 켜지는** WARN 이 있어서, 기본값으로 CI 를 걸면 어느 날 아무도 코드를
    # 바꾸지 않았는데 빨간불이 된다. 그러면 팀은 검사를 통째로 꺼 버린다.
    # 재현성(룰셋 드리프트)과 오탐 archetype 은 ERROR 라 이 설정에서도 막힌다.
    if overall == "warn" and getattr(args, "fail_on", "warn") != "error":
        return EXIT_FINDINGS_WARN
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gvskb",
        description="공공 바이브코딩 보안 가드레일 (vibecode-checker) CLI",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="파일/디렉토리 검사")
    scan.add_argument("path", help="검사할 파일 또는 디렉토리 경로")
    scan.add_argument(
        "--format", choices=["markdown", "html", "json", "sarif"], default="markdown",
        help="출력 형식 (기본: markdown). markdown/html 은 파일 저장(-o) 시 .md·.html 을 함께 생성. "
             "sarif 는 CI·보안도구 연동용 SARIF 2.1.0 (GitHub code scanning 업로드 가능)",
    )
    scan.add_argument(
        "--output", "-o",
        help="결과 저장 경로(확장자 제외). 미지정 시 <검사경로>/.check-reports/ 에 "
             "날짜·시각 이름으로 자동 저장합니다. GVSKB_REPORT_DIR 로 기관 공용 폴더 지정 가능",
    )
    scan.add_argument(
        "--stdout", action="store_true",
        help="파일로 저장하지 않고 화면에만 출력(파이프 연결용)",
    )
    scan.add_argument("--scenario", help="시나리오 힌트 (예: data-pipeline, llm-integration)")
    scan.add_argument(
        "--profile", default="public-default-strict",
        help="정책 프로파일 이름 (기본: public-default-strict)",
    )
    scan.add_argument("--max-files", type=int, default=SCAN_MAX_FILES_DEFAULT,
                      help=f"최대 검사 파일 수 (기본 {SCAN_MAX_FILES_DEFAULT})")
    scan.add_argument(
        "--check-deps", action="store_true",
        help="의존성 매니페스트(requirements*.txt·package.json)의 취약·악성 패키지 검사를 "
             "함께 수행해 리포트에 병합 (온라인: OSV.dev 조회 — 패키지명·버전만 전송 / "
             "오프라인: 로컬 인텔 캐시. 판정 불가는 '안전'이 아님)",
    )
    scan.add_argument(
        "--sbom", metavar="경로",
        help="검사 결과를 CycloneDX 1.6 SBOM 으로 저장 (조달 제출·자산 대장용). "
             "`--check-deps` 와 함께 쓰세요 — 의존성을 검사하지 않으면 컴포넌트 0개짜리 "
             "문서가 되어 '의존성이 없다'로 읽힙니다(그래서 그 경우 쓰지 않고 알립니다). "
             "판정 불가·상한 절단도 문서에 그대로 기록됩니다",
    )
    scan.add_argument(
        "--include-installed", action="store_true",
        help="의존성 검사 범위를 **설치 흔적까지** 확대(.venv의 dist-info·*.whl·node_modules). "
             "매니페스트에 없는 전이 의존성의 취약점까지 잡습니다. --check-deps 와 함께 사용",
    )
    scan.add_argument(
        "--registry-bundle", metavar="파일", default=None,
        help="기관 레지스트리 반입용 번들(JSON)을 이 경로에 생성. 패키지 판정만 담기며 "
             "코드 조각·파일 경로·findings 는 담기지 않습니다(연동합의 §3). "
             "무결성 확인용 .sha256 을 함께 만듭니다. --check-deps 와 함께 사용. "
             "번들 자체도 '어떤 기관이 어떤 패키지를 쓰는가'라는 정보이므로 반출 심사 대상입니다",
    )
    scan.add_argument(
        "--env", choices=["E0", "E1", "E2"], default=None,
        help="실행환경 등급 — 쿨다운(발행 후 대기) 기준일 결정: E0=개인PC 일회성(3일), "
             "E1=개인PC 반복도구(7일, 기본), E2=내부서버 공용(14일). --check-deps 와 함께 사용",
    )
    scan.add_argument(
        "--fail-on", choices=["block", "warn", "never", "dependency"], default="warn",
        help="0이 아닌 종료 코드를 낼 최소 수준 (기본 warn). "
             "CI 게이트에서 block만 차단하고 warn은 통과시키려면 --fail-on block, "
             "절대 실패시키지 않으려면 --fail-on never. "
             "dependency 는 **의존성 차단만** 실패시키고 소스 발견은 보고만 합니다 — "
             "의존성은 사실 조회라 오탐이 거의 없고 소스 룰은 추론이라 맥락을 타므로, "
             "소스 오탐 하나 때문에 게이트를 통째로 끄는 것을 막습니다",
    )
    scan.set_defaults(func=_cmd_scan)

    pkg = sub.add_parser("check-package", help="단일 패키지의 실재·취약점·악성·쿨다운 검사")
    pkg.add_argument("name", help="패키지 이름")
    pkg.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi")
    pkg.add_argument("--version", help="검사할 버전 (권장 — 미지정 시 전체 이력 기준의 보수적 판정)")
    pkg.add_argument(
        "--env", choices=["E0", "E1", "E2"], default=None,
        help="실행환경 등급(쿨다운 기준일): E0=3일, E1=7일(기본), E2=14일",
    )
    pkg.set_defaults(func=_cmd_check_package)

    rep = sub.add_parser("report", help="저장된 ScanReport JSON을 Markdown/HTML로 변환")
    rep.add_argument("findings_json", help="ScanReport가 저장된 JSON 파일 경로")
    rep.add_argument("--output", "-o", help="결과 저장 경로. 미지정 시 stdout")
    rep.add_argument(
        "--format", choices=["markdown", "html"], default="markdown",
        help="stdout 출력 형식 (기본: markdown). 파일 저장(-o) 시 .md·.html 을 함께 생성",
    )
    rep.add_argument(
        "--reproduce-command",
        default=None,
        help="리포트의 재현 절차 섹션에 표시할 정확한 명령어. 미지정 시 target/profile 기반 자동 생성",
    )
    rep.set_defaults(func=_cmd_report)

    rules = sub.add_parser("rules", help="로드된 런타임 룰 목록 출력")
    rules.set_defaults(func=_cmd_rules)

    ver = sub.add_parser("version", help="설치된 버전 출력")
    ver.set_defaults(func=_cmd_version)

    eva = sub.add_parser(
        "evaluate",
        help="룰 examples 기반 precision/recall/F1 메트릭 출력",
    )
    eva.add_argument(
        "--format",
        choices=["text", "markdown", "json"],
        default="text",
        help="출력 형식 (기본 text)",
    )
    eva.add_argument(
        "--rules-dir",
        default=None,
        help="평가에 사용할 룰 디렉토리. 미지정 시 패키지 기본 위치",
    )
    eva.add_argument(
        "--output", "-o",
        default=None,
        help="결과 저장 경로. 미지정 시 stdout",
    )
    eva.set_defaults(func=_cmd_evaluate)

    doctor = sub.add_parser("doctor", help="실행 환경·룰·MCP·네트워크 진단")
    doctor.add_argument("--json", action="store_true", help="JSON 출력 (자동화용)")
    doctor.add_argument("--offline", action="store_true",
                        help="네트워크 점검 건너뛰기 (망분리 환경)")
    doctor.set_defaults(func=_cmd_doctor)

    sb = sub.add_parser(
        "sbom",
        help="건네받은 SBOM(CycloneDX·SPDX JSON)의 컴포넌트를 검사 — 소스가 없어도 됩니다",
    )
    sb.add_argument("file", help="SBOM 파일 경로 (.json)")
    sb.add_argument("--limit", type=int, default=2000,
                    help="검사할 최대 컴포넌트 수 (기본 2000). 초과분은 건수를 알려 줍니다")
    sb.add_argument("--json", action="store_true", help="JSON 출력")
    sb.set_defaults(func=_cmd_sbom)

    rs = sub.add_parser("ruleset", help="룰셋 버전·지문 확인(게이트 재현성) · --bump 로 갱신")
    rs.add_argument("--rules-dir", help="대상 룰 디렉토리 (기본: 자동 해석)")
    rs.add_argument("--bump", metavar="버전", help="잠금 파일을 이 버전으로 갱신 (예: 2026.08.2)")
    rs.add_argument("--json", action="store_true", help="JSON 출력")
    rs.set_defaults(func=_cmd_ruleset)

    validate = sub.add_parser("validate-rules", help="룰 frontmatter·중복·regex·만료 검증")
    validate.add_argument("--rules-dir", help="검증할 룰 디렉토리 (기본: 자동 해석)")
    validate.add_argument("--json", action="store_true", help="JSON 출력")
    validate.add_argument(
        "--fail-on", choices=["error", "warn"], default="warn",
        help="0이 아닌 종료 코드를 낼 최소 수준 (기본 warn). "
             "CI 에서는 error 를 쓰세요 — review_due 만료처럼 **달력 때문에 언젠가 "
             "반드시 켜지는** 경고가 있어 warn 으로 걸면 어느 날 아무도 코드를 "
             "바꾸지 않았는데 빨간불이 됩니다(그러면 팀은 검사를 꺼 버립니다). "
             "룰셋 드리프트와 오탐 archetype 은 ERROR 라 이 설정에서도 막힙니다",
    )
    validate.set_defaults(func=_cmd_validate_rules)

    upd = sub.add_parser(
        "update-intel",
        help="외부 보안 피드(CISA KEV, OSV 등)를 로컬 캐시에 갱신",
    )
    upd.add_argument("--source", help="갱신할 단일 source id (예: cisa-kev, osv-malicious)")
    upd.add_argument("--all", action="store_true", help="등록된 모든 출처 갱신")
    upd.add_argument("--from-cache", action="store_true",
                     help="네트워크 호출 없이 캐시 상태만 보고 (망분리 환경)")
    upd.add_argument("--cache-dir", help="캐시 디렉토리 오버라이드 (기본: ~/.gvskb/cache)")
    upd.add_argument("--json", action="store_true", help="JSON 출력")
    upd.add_argument("--promote", action="store_true",
                     help="CISA KEV 캐시를 status=proposed 룰 MD로 자동 생성")
    upd.add_argument("--rules-dir",
                     help="proposed 룰을 쓸 디렉토리 (기본: rules/intel-proposed)")
    upd.add_argument("--promote-limit", type=int, default=0,
                     help="한 번에 생성할 룰 수 상한 (기본 0=무제한)")
    upd.add_argument("--promote-overwrite", action="store_true",
                     help="기존 proposed 파일을 덮어쓰기 (기본: skip)")
    upd.set_defaults(func=_cmd_update_intel)

    bundle = sub.add_parser(
        "intel-bundle",
        help="망분리 반입 번들 — export(외부망)에서 만들고 import(망분리)에서 sha256 전수 검증 후 반입",
    )
    bundle.add_argument("action", choices=["export", "import"], help="export=캐시→zip, import=zip→캐시(검증)")
    bundle.add_argument("bundle", help="번들 zip 경로")
    bundle.add_argument("--cache-dir", help="캐시 디렉토리 오버라이드 (기본: ~/.gvskb/cache)")
    bundle.add_argument("--json", action="store_true", help="JSON 출력")
    bundle.set_defaults(func=_cmd_intel_bundle)

    sync = sub.add_parser(
        "intel-sync",
        help="인텔 캐시 자동 동기화 — 설정된 소스(GVSKB_INTEL_DIR 폴더 → GVSKB_INTEL_URL)에서 번들을 당겨 반입",
    )
    sync.add_argument("--force", action="store_true",
                      help="신선도·재시도 간격을 무시하고 즉시 당김")
    sync.add_argument("--status", action="store_true",
                      help="당김 없이 현재 설정·필요 여부만 출력")
    sync.add_argument("--json", action="store_true", help="JSON 출력")
    sync.set_defaults(func=_cmd_intel_sync)

    return p


def _force_utf8_streams() -> None:
    """Ensure stdout/stderr accept Korean and em-dashes on Windows cp949 consoles."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    # 구버전 사본이 현재 코드를 가리는 상태면 결과를 믿기 전에 사용자가 보게 한다.
    # (doctor 는 자체 진단에 이미 포함하므로 중복 출력하지 않는다)
    if getattr(args, "command", None) != "doctor":
        try:
            from .diagnostics import warn_if_install_broken
            warn_if_install_broken()
        except Exception:  # noqa: BLE001 — 진단 실패가 명령 실행을 막으면 안 된다
            pass
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
