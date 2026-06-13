---
id: KISA-JS-ERR-01
title_ko: Node.js 오류 메시지 정보노출 - err 객체/스택 트레이스를 그대로 응답에 노출
title_en: Information exposure through error message in Node.js (raw err/stack to client)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제4절 1. 오류 메시지 정보노출
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-35
cwe: [CWE-209, CWE-200]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [backend-node, web-app, api]
related_baseline: [MOIS-49-ERR-01]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "res\\.(?:status\\s*\\(\\s*\\d+\\s*\\)\\.)?(?:send|json|end)\\s*\\(\\s*err(?:or)?\\s*\\)"
    - "res\\.(?:status\\s*\\(\\s*\\d+\\s*\\)\\.)?(?:send|json|end)\\s*\\(\\s*\\{[^}]*\\b(?:stack|trace|err|error)\\b\\s*:\\s*(?:err(?:or)?(?:\\.(?:stack|message|toString\\s*\\(\\s*\\)))?)"
    - "res\\.(?:status\\s*\\(\\s*\\d+\\s*\\)\\.)?(?:send|json|end)\\s*\\(\\s*err(?:or)?\\.(?:stack|toString\\s*\\(\\s*\\))"
    - "throw\\s+err\\s*;[\\s\\S]{0,200}?res\\.send\\s*\\(\\s*err"
  category: kisa-secure-coding
  why_it_matters: >-
    `res.status(500).send(err)`처럼 Node.js `Error` 객체를 그대로 응답에 보내면
    파일 경로, 모듈 버전, 내부 변수명, DB 컬럼명, 스택 트레이스가 클라이언트로
    유출됩니다. 공격자는 이를 통해 서버 디렉터리 구조, 사용 중인 ORM, 인증
    미들웨어 위치를 파악해 후속 공격을 설계합니다. 가이드 §제4절 1은 *예외
    발생 시 미리 정의된 메시지를 제공*하라고 명시합니다.
  public_sector_impact:
    - 내부 파일 경로/모듈 버전 노출로 인한 정찰 보조
    - DB 스키마/쿼리 누출로 SQL 인젝션 페이로드 정교화
    - 스택 트레이스를 통한 보안 미들웨어 우회 경로 탐지
  safe_fix: |
    클라이언트에는 미리 정의된 일반 메시지만 보내고, 상세 오류는 서버 로그에만 남기세요.
    if (err) {
      logger.error({ err, reqId: req.id }, 'file read failed');
      return res.status(500).send({ message: '잘못된 요청입니다.' });
    }
    Express는 errorHandler 미들웨어를 가장 마지막에 두고 에러 종류별로
    표준화된 메시지를 반환하도록 구성하세요.
  references:
    - KISA JavaScript 가이드 제4절 1
    - MOIS-49-ERR-01
    - CWE-209
    - OWASP Improper Error Handling
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "if (err) { return res.status(500).send(err); }"
    - "app.use((err, req, res, next) => { res.status(500).json({ error: err.stack }); });"
    - "fs.readFile(p, (err, data) => { if (err) return res.send({ trace: err.toString() }); });"
  negative:
    - "if (err) { logger.error(err); return res.status(500).send({ message: '잘못된 요청입니다.' }); }"
    - "app.use((err, req, res, next) => { res.status(500).json({ message: 'Internal Server Error' }); });"
    - "fs.readFile(p, (err, data) => { if (err) return res.status(500).send('fail'); res.send(data); });"
---

## 무엇이 위험한가
Node.js의 `Error` 인스턴스는 직렬화 시 `message`/`stack` 필드를 포함하며, JSON 응답으로 그대로 내보내면 절대 경로, 모듈 버전, 내부 함수명까지 통째로 유출됩니다. 가이드 §제4절 1은 *서버 내부에서 에러 발생 시 그 정보를 그대로 클라이언트에 전달하지 않고 자체적인 기준에 따라 제한된 정보만 클라이언트에 반환해야 한다*고 명시합니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
router.get("/vuln", (req, res) => {
  const filePath = "./file/secret/password";
  fs.readFile(filePath, (err, data) => {
    if (err) {
      // 에러 내용을 그대로 전달하지 않고 필터링 처리
      return res.status(500).send({ message: "잘못된 요청입니다" });
    } else {
      return res.send(data);
    }
  });
});
```

## False positive 주의
- 응답에 `err` 자체가 아니라 일반 메시지 문자열(`'fail'`, `{ message: '...' }`)이 들어가면 매칭하지 않습니다.
- 로깅 함수(`logger.error(err)`, `console.error(err)`)는 서버 측 기록이므로 매칭 대상이 아닙니다.
- `err.code`처럼 오류 분류용 짧은 코드만 노출하는 경우는 매칭되지 않지만, 그래도 코드 리뷰에서 외부 노출 적정성을 점검하세요.
- 개발 환경에서 `NODE_ENV !== 'production'` 가드로 감싼 상세 응답은 환경 분기를 코드 리뷰로 확인하세요.
