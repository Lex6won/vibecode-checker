---
id: GOV-RESPONSE-SECRET-001
title_ko: 응답 본문에 비밀·로그인 링크 노출 - 비밀번호·API 키·개발용 로그인 URL 반환
title_en: Secret or login link returned in HTTP response body
status: approved
source_layer: baseline
sources:
  - publisher: MITRE
    document: CWE
    item: CWE-200 Exposure of Sensitive Information / CWE-522 Insufficiently Protected Credentials
  - publisher: 경기도 보안 게이트 포털
    document: 체커 개선요청 #34 (2026-08-30) — 개발 모드에서 로그인 링크를 API 응답으로 반환
cwe: [CWE-200, CWE-522]
severity: medium
decision_default: warn
domains: [gov-vibe]
languages: [javascript, typescript, python]
scenarios: [web-app, api]
related_baseline: [KISA-JS-ERR-01, KISA-PY-ERR-01]
verified_at: 2026-08-30
review_due: 2027-02-28
detection:
  patterns:
    # Express/Koa/Fastify: res.json({ password: …, api_key: …, dev_login_url: … })
    # `token` 하나만은 잡지 않는다 — 로그인 응답의 액세스 토큰은 정상 설계다. 잡는 키는
    # 응답에 실릴 이유가 없는 것들: 비밀번호·API 키·개인키·개발용 로그인 링크·재설정 토큰.
    - '\b(?:res|reply|response)(?:\.\w+\s*\([^)]*\))*\.(?:json|send|end)\s*\(\s*\{[^}]*\b(?:password|passwd|pwd|secret|api_?key|private_?key|dev_?login_?url|login_?url|magic_?link|reset_?token|otp)\s*:'
    # 헬퍼 함수형 — json(res, 200, { … }) · send(response, { … }). 포털 실제 코드가 이 모양이었다.
    - '\b(?:json|send|respond|reply)\s*\(\s*(?:res|response|reply)\b[^{]*\{[^}]*\b(?:password|passwd|pwd|secret|api_?key|private_?key|dev_?login_?url|login_?url|magic_?link|reset_?token|otp)\s*:'
    # Koa: ctx.body = { … }
    - '\bctx\.body\s*=\s*\{[^}]*\b(?:password|passwd|pwd|secret|api_?key|private_?key|dev_?login_?url|login_?url|magic_?link|reset_?token|otp)\s*:'
    # Flask/FastAPI: jsonify({...}) · JSONResponse({...}) · return {"password": ...}
    - '(?:jsonify|JSONResponse|JsonResponse|HttpResponse)\s*\(\s*\{[^}]*["''](?:password|passwd|pwd|secret|api_?key|private_?key|dev_?login_?url|login_?url|magic_?link|reset_?token|otp)["'']\s*:'
  exclude_patterns:
    # 검증·마스킹·에러 문구는 값이 아니다.
    - '(?:password|secret|api_?key)\s*:\s*(?:["''](?:\*{3,}|\[?REDACTED\]?|masked|hidden|required|invalid|missing|wrong|incorrect)|null|None|undefined|false|""|'''')'
    - '(?:password|secret)_?(?:changed|updated|reset|required|policy|rules|length|strength)\s*:'
    - '(?:has|is|needs|require)_?(?:password|secret)\s*:'
  category: gov-secure-coding
  confidence: pattern-only
  why_it_matters: >-
    응답 본문에 비밀번호·API 키·개인키·개발용 로그인 링크가 실리면 로그·프록시 캐시·
    브라우저 개발자도구·화면 녹화에 그대로 남고, 개발 모드 분기가 운영에 남으면
    **누구나 임의 계정으로 로그인**할 수 있습니다. 포털 자체 점검에서 사람이 찾은 실제
    취약점(개발 모드에서 로그인 링크를 API 응답으로 반환)이며, "취약 함수 호출"이 아니라
    "응답에 민감정보를 싣는 데이터 흐름"이라 패턴만 보던 체커는 놓쳤습니다.
  public_sector_impact:
    - 인증 우회 — 임의 계정 로그인
    - 키·비밀번호가 로그·캐시·감사 기록에 평문 잔존
  safe_fix: |
    응답에는 식별자·상태만 싣고 비밀은 서버에 둡니다. 개발용 로그인 링크는 응답이 아니라
    서버 로그(개발 환경 한정)나 CLI 에 출력하고, 운영 빌드에서는 분기 자체를 제거하세요.
        // 나쁨
        res.json({ ok: true, dev_login_url: `/login?token=${token}` });
        // 좋음
        if (process.env.NODE_ENV !== "production") logger.debug("dev login: %s", url);
        res.json({ ok: true });
  references:
    - CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
    - CWE-522 Insufficiently Protected Credentials
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "res.json({ ok: true, dev_login_url: `/login?token=${token}` });"
    - "res.send({ user: u.name, password: u.password });"
    - "reply.send({ api_key: key });"
    - "json(response, 200, { status: 'sent', mode: 'dev', dev_login_url: loginPath });"
    - "return jsonify({'ok': True, 'password': temp_pw})"
    - "return JSONResponse({\"reset_token\": tok})"
  negative:
    - "res.json({ token: accessToken, expires_in: 3600 });"
    - "res.json({ ok: true, user: { id: u.id, name: u.name } });"
    - "res.status(400).json({ error: 'password required', password: null });"
    - "res.json({ password_changed: true });"
    - "return jsonify({'has_password': bool(user.pw_hash)})"
    - "const cfg = { password: process.env.DB_PASS };"
---

## 무엇이 위험한가
API 응답은 서버 밖으로 나가는 순간 통제할 수 없습니다. 프록시·CDN 캐시, 브라우저 히스토리, 화면 공유, 모니터링 도구의 응답 로그에 남습니다. 개발 편의로 넣은 `dev_login_url` 같은 분기는 운영에 남기 쉽고, 남으면 인증이 통째로 무의미해집니다.

## 안전한 패턴
```js
app.post("/api/login", async (req, res) => {
  const user = await auth(req.body);
  res.json({ ok: true, user: { id: user.id, name: user.name } });   // 비밀은 싣지 않는다
});
```

## 이 룰의 한계
같은 줄의 객체 리터럴만 봅니다. 여러 줄에 걸친 객체나 변수로 조립한 응답은 잡지 못합니다(흐름 분석 범위). 반대로 `password: null` 같은 검증 응답은 제외했습니다.
