---
id: KISA-JS-SEC-02
title_ko: Node.js 부적절한 인가 - 권한 검증 없이 삭제/수정 작업 수행
title_en: Improper authorization in Node.js (delete/update without role check)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 2. 부적절한 인가
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-33
cwe: [CWE-285, CWE-862, CWE-639]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [auth, backend-node, web-app]
related_baseline: [MOIS-49-SEC-02]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?:router|app)\\.delete\\s*\\(\\s*['\"][^'\"]+['\"]\\s*,(?![\\s\\S]{0,800}?(?:req\\.session\\.role|req\\.user\\.role|isAdmin|hasPermission|canDelete|authorize|ac\\.can|checkRole|requireRole|requireAuth|ensureAdmin))[\\s\\S]{0,800}?(?:delete\\w+FromDB|\\.destroy\\s*\\(|\\.remove\\s*\\(|\\.delete\\s*\\(|DELETE\\s+FROM)"
    - "(?:router|app)\\.(?:put|patch)\\s*\\(\\s*['\"][^'\"]*(?:admin|user|role|content)[^'\"]*['\"]\\s*,(?![\\s\\S]{0,800}?(?:req\\.session\\.role|req\\.user\\.role|isAdmin|hasPermission|authorize|requireRole|checkRole|requireAuth|ensureAdmin))[\\s\\S]{0,800}?(?:update\\w+FromDB|\\.update\\s*\\(|UPDATE\\s+\\w+\\s+SET)"
  category: kisa-secure-coding
  why_it_matters: >-
    `router.delete(...)` 핸들러가 로그인 여부만 보고 `req.body.contentId`로 바로
    DB 삭제를 호출하면, 일반 사용자가 *다른 사용자의 자원*을 ID만 알아내면 삭제할
    수 있습니다. KISA 가이드 §제2절 2는 *사용자의 권한에 따른 ACL 관리*와
    *세션에 저장된 권한 확인 후 작업 수행*을 요구합니다. 공공 게시판·민원·민감
    파일 삭제 API에서 BOLA/IDOR 형태로 흔히 노출됩니다.
  public_sector_impact:
    - 타 시민의 민원/게시글 무단 삭제·수정
    - 일반 사용자에 의한 관리자 기능 호출
    - 권한 상승으로 인한 행정 데이터 변조
  safe_fix: |
    세션 권한 검사 후 자원 소유권 검증을 반드시 수행하세요.
    const role = req.session.role;
    if (role !== "admin") return res.status(403).send("권한 없음");
    // 또는 소유권 검사:
    const item = await getItem(contentId);
    if (item.ownerId !== req.session.userid) return res.status(403).send("권한 없음");
    await deleteContentFromDB(contentId);
  references:
    - KISA JavaScript 가이드 제2절 2
    - MOIS-49-SEC-02
    - CWE-285
    - OWASP Authorization Cheat Sheet
    - OWASP API Top 10 - BOLA
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "router.delete('/content', (req, res) => { const contentId = req.body.contentId; deleteContentFromDB(contentId); return res.send('삭제 완료'); });"
    - "app.delete('/users/:id', async (req, res) => { await User.destroy({ where: { id: req.params.id } }); res.send('ok'); });"
    - "router.put('/admin/role', (req, res) => { db.query('UPDATE user SET role=? WHERE id=?', [req.body.role, req.body.id]); res.send('ok'); });"
  negative:
    - "router.delete('/content', (req, res) => { const role = req.session.role; if (role !== 'admin') return res.status(403).send('no'); deleteContentFromDB(req.body.contentId); });"
    - "app.delete('/users/:id', requireRole('admin'), async (req, res) => { await User.destroy({ where: { id: req.params.id } }); });"
    - "router.get('/content/:id', (req, res) => { res.json(getContent(req.params.id)); });"
---

## 무엇이 위험한가
부적절한 인가(Broken Authorization)는 OWASP API Top 10의 1위 BOLA와 직결됩니다. 가이드 §제2절 2의 안전하지 않은 예제는 `req.body.contentId`만 받아 곧바로 `deleteContentFromDB`를 호출합니다. 시민 누구나 `contentId`만 추측하면 타인의 자료를 삭제·수정할 수 있습니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
router.delete("/patched", (req, res) => {
  const contentId = req.body.contentId;
  const role = req.session.role;
  // 삭제 기능을 수행할 권한이 있는 경우에만 삭제 작업 수행
  if (role === "admin") {
    deleteContentFromDB(contentId);
    return res.send("삭제가 완료되었습니다.");
  } else {
    return res.send("권한이 없습니다.");
  }
});
```

## False positive 주의
- 핸들러 본문 또는 미들웨어 위치에 `req.session.role`, `req.user.role`, `isAdmin`, `hasPermission`, `authorize`, `requireRole`, `checkRole` 등이 보이면 매칭에서 제외합니다.
- `GET` 핸들러는 조회 의도가 우세하므로 매칭하지 않습니다(별도 정보노출 룰에서 다룹니다).
- ORM의 `.destroy()`/`.delete()`가 미들웨어(`requireRole(...)`)로 보호되는 경우는 두 번째 인자에서 키워드를 잡아 제외합니다. 그래도 검증이 함수 분리되어 있으면 false negative가 가능합니다.
