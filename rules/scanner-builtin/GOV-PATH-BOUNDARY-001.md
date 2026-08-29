---
id: GOV-PATH-BOUNDARY-001
title_ko: 경로 경계 검사 우회 - startsWith(루트) 접두어 비교에 구분자 없음
title_en: Path boundary check bypass - startsWith(root) prefix compare without separator
status: approved
source_layer: baseline
sources:
  - publisher: MITRE
    document: CWE
    item: CWE-22 Improper Limitation of a Pathname to a Restricted Directory
  - publisher: 경기도 보안 게이트 포털
    document: 체커 개선요청 #34 (2026-08-30) — 포털 자체 점검에서 사람이 찾은 실제 취약점
cwe: [CWE-22]
severity: medium
decision_default: warn
domains: [gov-vibe]
languages: [javascript, typescript, python]
scenarios: [web-app, file-upload]
related_baseline: [KISA-PY-INPUT-03, KISA-JS-INPUT-03]
verified_at: 2026-08-30
review_due: 2027-02-28
detection:
  patterns:
    # `resolved.startsWith(path.resolve(root))` — 구분자 없이 접두어만 비교한다.
    # `/data/uploads` 를 루트로 두면 `/data/uploads-backup/…` 도 통과한다. 같은 줄에
    # `+ path.sep`·`+ "/"`·`sep` 이 있으면 exclude_patterns 가 걸러 낸다.
    - '\.startsWith\s*\(\s*(?:path\.)?(?:resolve|join|normalize)\s*\('
    # `resolved.startsWith(root)` / `(baseDir)` / `(UPLOAD_ROOT)` — 이름이 디렉터리·루트·경로임을
    # 드러내는 식별자 하나만 비교. 포털 실제 사례가 이 모양이었다.
    - '\.startsWith\s*\(\s*(?:[A-Za-z_$][\w$]*)?(?:[Rr]oot|[Dd]ir|[Bb]ase|[Pp]ath|ROOT|DIR|BASE|PATH)[\w$]*\s*\)'
    # Python 판 — `abs_path.startswith(os.path.abspath(root))` / `.startswith(base_dir)`
    - '\.startswith\s*\(\s*(?:os\.path\.)?(?:abspath|realpath|join|normpath)\s*\('
    - '\.startswith\s*\(\s*(?:[A-Za-z_]\w*)?(?:[Rr]oot|[Dd]ir|[Bb]ase|[Pp]ath|ROOT|DIR|BASE|PATH)\w*\s*\)'
  exclude_patterns:
    # 구분자를 붙여 비교하면 경계가 닫힌다.
    - 'path\.sep|os\.sep|\+\s*["''`][/\\]'
    # 올바른 API 를 쓰는 줄 — 접두어 비교가 보조 조건일 뿐이다.
    - 'is_relative_to|commonpath|path\.relative\s*\(|relative_to\s*\('
    # Python 관용구 `os.path.join(base, '')` 은 끝에 구분자를 붙인다 — 경계가 닫힌 비교.
    - 'os\.path\.join\s*\([^)]*,\s*["'']{2}\s*\)'
    # URL·문자열 접두어 비교는 경로 경계가 아니다.
    - '\.startsWith\s*\(\s*["''`]https?:|url\w*\.startsWith|href\w*\.startsWith'
  category: gov-secure-coding
  confidence: pattern-only
  why_it_matters: >-
    업로드·다운로드 경로를 "루트 디렉터리로 시작하는가"로만 검사하면 루트와 이름이
    같은 접두어를 가진 **형제 디렉터리**(`uploads` vs `uploads-old`, `data` vs `data2`)
    가 통과합니다. 정규화(resolve)를 했더라도 구분자 없이 접두어만 비교하는 것은 경계
    검사가 아닙니다. 포털 자체 점검에서 사람이 직접 찾은 실제 취약점이며, 정규식
    패턴만 보던 체커는 놓쳤습니다.
  public_sector_impact:
    - 형제 디렉터리의 다른 사업·다른 기관 파일 열람
    - 업로드 격리 실패 → 보고서·개인정보 파일 노출
  safe_fix: |
    구분자를 붙여 비교하거나, 경계 검사 전용 API 를 쓰세요.
        // Node
        const rootWithSep = path.resolve(root) + path.sep;
        if (!resolved.startsWith(rootWithSep) && resolved !== path.resolve(root)) throw new Error("bad path");
        // 또는
        const rel = path.relative(root, resolved);
        if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("bad path");
        # Python
        Path(resolved).resolve().is_relative_to(Path(root).resolve())   # 3.9+
  references:
    - CWE-22 Improper Limitation of a Pathname to a Restricted Directory
    - Node.js path.relative / Python pathlib.Path.is_relative_to
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "if (!resolved.startsWith(path.resolve(root))) throw new Error('bad');"
    - "if (!resolved.startsWith(root)) return res.status(400).end();"
    - "ok = target.startsWith(UPLOAD_DIR);"
    - "if not abs_path.startswith(os.path.abspath(base_dir)): abort(400)"
    - "if not abs_path.startswith(base_dir): abort(400)"
  negative:
    - "if (!resolved.startsWith(path.resolve(root) + path.sep)) throw new Error('bad');"
    - "if (!resolved.startsWith(root + '/')) throw new Error('bad');"
    - "const rel = path.relative(root, resolved);"
    - "if not Path(p).resolve().is_relative_to(base): abort(400)"
    - "if (url.startsWith('https://')) return;"
    - "if (name.startsWith('tmp')) continue;"
---

## 무엇이 위험한가
`resolved.startsWith(root)` 는 `root` 가 `/srv/uploads` 일 때 `/srv/uploads-archive/secret.pdf` 도 통과시킵니다. `path.resolve` 로 `..` 을 정규화했더라도 이 비교는 **디렉터리 경계**가 아니라 **문자열 접두어**를 보는 것입니다.

## 안전한 패턴
```js
const base = path.resolve(root);
const target = path.resolve(base, userPath);
const rel = path.relative(base, target);
if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("bad path");
```
```python
from pathlib import Path
if not Path(target).resolve().is_relative_to(Path(root).resolve()):
    abort(400)
```

## 이 룰의 한계
같은 줄만 봅니다. 구분자 처리가 다음 줄에 있거나 별도 함수에 있으면 경고가 남을 수 있습니다 — 그래서 `warn` 입니다. 경고가 남으면 구분자 처리가 어디 있는지 한 줄 주석으로 남기고 예외 파일에 사유를 적으세요.
