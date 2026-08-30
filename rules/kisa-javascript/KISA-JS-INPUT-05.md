---
id: KISA-JS-INPUT-05
title_ko: Node.js에서 운영체제 명령어 삽입 - child_process.exec/execSync/spawn shell:true
title_en: OS command injection in Node.js (child_process.exec/execSync/spawn shell:true)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 5. 운영체제 명령어 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-12
cwe: [CWE-78]
severity: critical
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript, data]
scenarios: [backend-node, agent, batch-job]
related_baseline: [MOIS-49-INPUT-05]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    - 'child_process\.exec(?:Sync)?\s*\('
    - "require\\s*\\(\\s*[\"']child_process[\"']\\s*\\)\\s*\\.exec"
    - 'child_process\.spawn(?:Sync)?\s*\([^)]*shell\s*:\s*true'
    # 수신자가 **정규식**이면 child_process 가 아니다. 실측(2026-08-08) 오탐 2건이
    # 둘 다 `/^[A-Za-z]+/.exec(...)` · `lineRegex.exec(...)` 였다 — 정규식의
    # `.exec()` 는 명령을 실행하지 않는다. 고정폭 부정 후방탐색을 이어 붙여
    # 정규식 리터럴(`/…/`)·`new RegExp(…)`·regex/pattern 계열 변수명을 제외한다.
    # (아래 bare `exec(` 패턴들은 그대로 둔다 — 그쪽은 구조분해 import 경로다.)
    # 표기 변형은 `(?i:)` 로 한 번에 덮는다. 처음엔 Regex/regex/RegExp/regexp 를
    # 하나씩 나열했는데, `urlRegexp`(혼합 표기)가 그 사이로 빠져나갔다 —
    # 나열은 끝이 없고 빠진 자리가 조용하다. 후방탐색은 폭이 고정이어야 하므로
    # 접미사별로 나누되, 각각은 대소문자를 가리지 않게 한다.
    - "(?<![/\\)])(?<!(?i:regex))(?<!(?i:regexp))(?<!(?i:pattern))(?<!(?i:_re))\\.exec(?:Sync)?\\s*\\([^)]*(?:\\+\\s*\\w|`[^`]*\\$\\{)"
    - '\.execFile\s*\([^,)]*,\s*\[[^\]]*\$\{'
    # 구조분해 import( const { exec } = require('child_process') )로 호출한
    # bare exec( ... + 입력 ) — 앞에 점/식별자문자가 없는 exec만(점 있는 .exec는
    # 위 패턴이 처리, execFile은 shell 미경유라 제외).
    - '(?<![.\w])exec\s*\(\s*["`][^"`]*["`]\s*\+'
    - '(?<![.\w])exec\s*\([^)]*req\.(?:query|params|body)'
  category: kisa-secure-coding
  why_it_matters: >-
    Node.js의 child_process.exec와 execSync는 *셸을 통과해 명령을 실행*하므로
    문자열의 ;, &, |, $() 같은 메타문자가 추가 명령으로 해석됩니다. spawn에
    shell:true 옵션을 주는 것도 동일한 위험을 가집니다. 사용자 입력이 명령에
    결합되면 즉시 RCE입니다.
  public_sector_impact:
    - Node.js 서버 원격 명령 실행
    - 행정 시스템 침해
    - 자동화 배치 작업의 권한 탈취
  safe_fix: |
    셸을 거치지 않는 spawn 또는 execFile를 인자 배열로 사용하세요.
    const { spawn } = require("child_process");
    const child = spawn("convert", ["--", filename], { shell: false });
    파일 경로/이름에 사용자 입력이 섞이면 path.normalize + base dir 검증 추가.
  references:
    - KISA JavaScript 가이드 제2절 5
    - MOIS-49-INPUT-05
    - CWE-78
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "child_process.exec(\"convert \" + req.query.name);"
    - "child_process.spawnSync(cmd, args, { shell: true });"
  negative:
    - "const out = spawnSync(\"git\", [\"status\", \"--porcelain\"]);"
    - "execFile(\"/usr/bin/convert\", [inputPath, outputPath], cb);"
---

## 무엇이 위험한가
```javascript
const { exec } = require("child_process");
exec(`convert ${filename} out.png`, callback);   // RCE 가능
```
*filename*에 `a.png; rm -rf /tmp/*` 같은 문자열이 들어가면 두 번째 명령이 실행됩니다. `spawn(..., { shell: true })`도 동일한 위험을 가집니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
const { spawn } = require("child_process");
const child = spawn("convert", ["--", filename, "out.png"], { shell: false });
child.on("error", err => log(err));
```

## False positive 주의
- 정적 명령(`exec("npm test")` 등 변수 없음)은 검출되지만 운영 코드에서는 적절성을 확인 후 예외 처리 가능합니다.
