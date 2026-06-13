---
id: KISA-JS-INPUT-06
title_ko: Node.js 위험한 형식 파일 업로드 - multer 화이트리스트·MIME 검증 누락
title_en: Unrestricted file upload in Node.js (multer without fileFilter)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 6. 위험한 형식 파일 업로드
cwe: [CWE-434]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, file-upload]
related_baseline: [MOIS-49-INPUT-06]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  # multer 호출에 fileFilter / limits 가 없는 경우만 매칭하기 위해 옵션이 dest
  # 단독으로만 들어간 형태를 잡습니다. fileFilter·limits를 포함한 multer 호출은
  # 라인 끝까지 더 긴 옵션이 따라오므로 매칭에서 빠집니다.
  patterns:
    - "multer\\s*\\(\\s*\\{\\s*dest\\s*:\\s*[\"'][^\"']+[\"']\\s*\\}\\s*\\)"
    - "(?:req|request)\\.files\\.[a-zA-Z_]+\\.mv\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\+"
  category: kisa-secure-coding
  why_it_matters: >-
    `multer({ dest: "uploads/" })` 한 줄만 쓰고 `fileFilter`/`limits`를 지정
    하지 않으면 .js·.html·.php 등 어떤 파일도 업로드 가능합니다. 정적 자산
    경로에 직접 저장하면 즉시 웹쉘 또는 stored XSS로 이어집니다.
  public_sector_impact:
    - 웹쉘 업로드
    - stored XSS / HTML 인젝션
    - 정적 자산 경로 변조
  safe_fix: |
    fileFilter + limits로 확장자·크기 제한. 저장 디렉터리는 정적 서빙 경로 외부.
    const upload = multer({
      dest: "/var/uploads",  // 정적 경로 외부
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, [".pdf", ".hwp", ".png"].includes(ext));
      },
    });
  references:
    - KISA JS 가이드 제2절 6
    - MOIS-49-INPUT-06
    - CWE-434
  can_auto_fix: false
---

## 무엇이 위험한가
multer 기본 설정은 *모든 파일 타입을 허용*합니다. fileFilter를 명시하지 않으면 .html, .js 같은 파일도 그대로 저장됩니다.

## 안전한 패턴
```javascript
const multer = require("multer");
const path = require("path");
const ALLOWED = new Set([".pdf", ".hwp", ".docx", ".png", ".jpg"]);

const upload = multer({
  dest: "/var/uploads",   // express static 경로와 분리
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, ALLOWED.has(ext));
  },
});
```
