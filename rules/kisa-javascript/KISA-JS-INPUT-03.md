---
id: KISA-JS-INPUT-03
title_ko: JavaScript 경로 조작 - fs.readFile / path.join에 외부 입력 직접 결합
title_en: Path traversal in Node.js fs/path operations
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 3. 경로 조작 및 자원 삽입
cwe: [CWE-22, CWE-23]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, file-upload]
related_baseline: [MOIS-49-INPUT-03]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - "fs\\.(?:readFile|readFileSync|createReadStream)\\s*\\(\\s*(?:req\\.|request\\.)"
    - "fs\\.(?:writeFile|writeFileSync|createWriteStream)\\s*\\(\\s*(?:req\\.|request\\.)"
    - "path\\.join\\s*\\([^)]*req\\.(?:params|query|body)\\."
    - "res\\.sendFile\\s*\\(\\s*(?:req\\.|request\\.)"
    - "res\\.download\\s*\\(\\s*(?:req\\.|request\\.)"
  category: kisa-secure-coding
  why_it_matters: >-
    Express의 req.params.filename 등을 fs/path 함수에 직접 넘기면 `../../etc/
    passwd` 같은 경로 탈출이 가능합니다. 공공 민원·결재 시스템의 첨부 다운로드
    엔드포인트에서 자주 발견됩니다.
  public_sector_impact:
    - 서버 파일 유출 (/etc/passwd, .env)
    - 민원 첨부 노출
    - 행정 시스템 설정 파일 접근
  safe_fix: |
    path.normalize → base 디렉터리 안에 있는지 검증.
    const safeBase = path.resolve("/var/uploads");
    const target = path.resolve(safeBase, path.basename(req.params.name));
    if (!target.startsWith(safeBase + path.sep)) return res.status(400).end();
  references:
    - KISA JS 가이드 제2절 3
    - MOIS-49-INPUT-03
    - CWE-22
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "fs.readFile(req.query.path, (err, data) => send(data));"
    - "res.sendFile(req.params.filename);"
    - "const target = path.join(BASE_DIR, req.query.file);"
  negative:
    - "fs.readFile(SAFE_REPORT_PATH, (err, data) => send(data));"
    - "res.sendFile(path.resolve(ALLOWED_DIR, allowlist[key]));"
---

## 무엇이 위험한가
`fs.readFile(req.params.file, ...)`처럼 사용자 경로를 그대로 전달하면 경로 조작 공격에 노출됩니다.

## 안전한 패턴
```javascript
const path = require("path");
const SAFE_BASE = path.resolve("/var/uploads");
function serveFile(req, res) {
  const target = path.resolve(SAFE_BASE, path.basename(req.params.name));
  if (!target.startsWith(SAFE_BASE + path.sep)) {
    return res.status(400).end();
  }
  res.sendFile(target);
}
```
