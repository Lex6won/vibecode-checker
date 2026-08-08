---
id: KISA-JS-SEC-01
title_ko: Node.js 적절한 인증 없는 중요 기능 허용 - 현재 패스워드 미확인 / 재인증 누락
title_en: Missing authentication for critical function in Node.js (password change without current-password check)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 1. 적절한 인증 없는 중요 기능 허용
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-32
cwe: [CWE-306, CWE-862]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [auth, backend-node, web-app]
related_baseline: [MOIS-49-SEC-01]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "(?:router|app)\\.(?:post|put|patch|delete)\\s*\\(\\s*['\"][^'\"]*(?:password|passwd|pwd|account|withdraw|delete|transfer)[^'\"]*['\"][^)]*\\)[\\s\\S]{0,400}?updatePasswordFromDB\\s*\\("
    - "updatePasswordFromDB\\s*\\(\\s*(?:user|userId|req\\.session\\.[a-zA-Z_]+)\\s*,\\s*(?:newHashPassword|newPassword|req\\.body\\.[a-zA-Z_]+)\\s*\\)"
    # 라우트 등록줄에 **역할 기반 인가 미들웨어**가 있으면 제외한다. 실측
    # (2026-08-08) 오탐 1건이 `app.post("/api/users/:id/reset-password",
    # requireAuth(['admin']), …)` 였다 — 관리자가 **남의** 비밀번호를 초기화하는
    # 경로에 그 사람의 옛 비밀번호를 요구할 수는 없다. 반면 역할 없는
    # `requireAuth()`(= 그냥 로그인)는 **계속 잡는다** — 본인 비밀번호 변경에
    # 재인증을 생략할 근거가 되지 않기 때문이다. 그래서 `\(\s*\[`(역할 배열)를
    # 요구한다. 뒤쪽 부정 전방탐색은 `=> {` 이후만 보므로 여기엔 쓸 수 없어,
    # 라우트 문자열~화살표 구간을 tempered dot 으로 막는다.
    - "(?:router|app)\\.(?:post|put|patch)\\s*\\(\\s*['\"][^'\"]*(?:changePassword|change-password|reset-password|withdraw|delete-account)[^'\"]*['\"](?:(?!requireAuth\\s*\\(\\s*\\[|requireRole|requireAdmin|adminOnly|isAdmin)[\\s\\S]){0,300}?\\)\\s*=>\\s*\\{(?![\\s\\S]{0,400}?(?:currentPassword|oldPassword|reauth|verifyPassword|bcrypt\\.compare))"
  category: kisa-secure-coding
  why_it_matters: >-
    비밀번호 변경, 계좌이체, 회원탈퇴 등 *중요 기능*은 세션만으로 신뢰하면 안 됩니다.
    세션 탈취·CSRF·공용 PC 잔류 등 정상 로그인 후 공격 시나리오에서 공격자가
    피해자의 계정을 즉시 장악합니다. KISA 가이드 §제2절 1은 *중요한 정보가 있는
    페이지는 재인증을 적용*하라고 명시합니다. 공공 민원·세무·복지 시스템에서 가장
    먼저 점검해야 할 항목입니다.
  public_sector_impact:
    - 세션 탈취 후 비밀번호 무단 변경
    - 본인확인 없는 민원 취소·환급 처리
    - CSRF로 계정 장악 후 권한 상승
  safe_fix: |
    중요 기능 실행 전 *현재 비밀번호* 또는 추가 인증을 요구하세요.
    const ok = await bcrypt.compare(req.body.currentPassword, user.passwordHash);
    if (!ok) return res.status(401).send("재인증 실패");
    await updatePasswordFromDB(userId, newHash);
    // 또는 OTP/이메일 재인증, step-up auth 적용.
  references:
    - KISA JavaScript 가이드 제2절 1
    - MOIS-49-SEC-01
    - CWE-306
    - OWASP Access Control Cheat Sheet
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "router.post('/changePassword', (req, res) => { const newPassword = req.body.newPassword; const user = req.session.userid; updatePasswordFromDB(user, newPassword); return res.send('ok'); });"
    - "app.put('/reset-password', async (req, res) => { const newPassword = req.body.newPassword; await db.update(newPassword); res.send('done'); });"
    - "updatePasswordFromDB(req.session.userid, req.body.newPassword);"
  negative:
    - "router.post('/changePassword', async (req, res) => { const currentPassword = req.body.currentPassword; const ok = await bcrypt.compare(currentPassword, user.passwordHash); if (!ok) return res.status(401).send('fail'); await updatePasswordFromDB(user.id, newHash); });"
    - "router.get('/profile', (req, res) => { res.json({ name: req.session.name }); });"
    - "updatePasswordFromDB(userId, newHash); // verified by bcrypt.compare(oldPassword) above"
---

## 무엇이 위험한가
세션 쿠키만 신뢰하고 비밀번호 변경·탈퇴·이체 같은 *중요 기능*을 곧바로 실행하면, 세션이 어떤 경로로든 탈취되었을 때(공용 PC, XSS, CSRF, 세션고정) 공격자가 피해자 계정을 즉시 장악합니다. 가이드 §제2절 1은 *중요한 정보가 있는 페이지는 재인증을 적용*하라고 못박습니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
router.post("/patched", (req, res) => {
  const newPassword = req.body.newPassword;
  const user = req.session.userid;
  const oldPassword = getPasswordFromDB(user);
  const currentPassword = req.body.currentPassword;
  const currentHashPassword = hs.update(currentPassword + salt).digest("base64");
  // 현재 패스워드 확인 후 사용자 정보 업데이트
  if (currentHashPassword === oldPassword) {
    const newHashPassword = hs.update(newPassword + salt).digest("base64");
    updatePasswordFromDB(user, newHashPassword);
    return res.send({ message: "패스워드가 변경되었습니다." });
  } else {
    return res.send({ message: "패스워드가 일치하지 않습니다." });
  }
});
```

## False positive 주의
- `currentPassword` / `oldPassword` / `bcrypt.compare` / `verifyPassword`가 핸들러 본문에 포함된 경우는 재인증을 수행한 것으로 보고 매칭하지 않습니다.
- 단순 조회(`GET /profile`) 핸들러는 중요 기능 키워드(`password|withdraw|delete`)가 경로에 없으므로 매칭 대상이 아닙니다.
- 라우터 외부의 헬퍼 함수에서 재인증을 분리한 경우 false negative가 발생할 수 있으니 코드 리뷰로 보완하세요.
