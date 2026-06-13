---
id: KISA-JS-SEC-12
title_ko: Node.js 영속 쿠키 / 안전하지 않은 쿠키 속성 - 과도한 만료 / secure·httpOnly 누락
title_en: Persistent or insecure cookie attributes in Node.js (long expiry, missing secure/httpOnly)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 12. 사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-43
cwe: [CWE-539, CWE-614, CWE-1004]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [web-app, backend-node, auth]
related_baseline: [MOIS-49-SEC-12]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "res\\.cookie\\s*\\([^)]*expires\\s*:\\s*new\\s+Date\\s*\\(\\s*Date\\.now\\s*\\(\\s*\\)\\s*\\+\\s*(?:[3-9]\\d{2,}|\\d{4,})\\s*\\*"
    - "res\\.cookie\\s*\\(\\s*['\"](?!locale|theme|lang|i18n|tz)[a-zA-Z_][\\w-]*['\"][^)]*maxAge\\s*:\\s*(?:\\d{9,}|[3-9]\\d{7,})"
    - "res\\.cookie\\s*\\(\\s*['\"](?:session|sid|sess|auth|token|jwt|rememberme|userId|loginToken)['\"]\\s*,\\s*[^,)]+\\s*,\\s*\\{(?:(?!secure\\s*:\\s*true)[^}])*\\}\\s*\\)"
    - "res\\.cookie\\s*\\(\\s*['\"](?:session|sid|sess|auth|token|jwt|rememberme|userId|loginToken)['\"]\\s*,\\s*[^,)]+\\s*,\\s*\\{(?:(?!httpOnly\\s*:\\s*true)[^}])*\\}\\s*\\)"
    - "document\\.cookie\\s*=\\s*[`\"'][^`\"']*(?:expires|max-age)[^`\"']*(?:20[3-9]\\d|209\\d|GMT\\s*\\+\\d{4})"
  category: kisa-secure-coding
  why_it_matters: >-
    쿠키 만료를 1년 등으로 길게 잡으면 *영속 쿠키*가 사용자 하드디스크에 평문
    저장되어, 공용 PC·악성코드·디스크 포렌식으로 탈취될 위험이 급증합니다.
    `secure` 누락 시 http 채널로 쿠키가 평문 전송되고, `httpOnly` 누락 시 XSS로
    document.cookie가 즉시 노출됩니다. 가이드 §제2절 12는 *만료시간 최소화 +
    secure + httpOnly* 조합을 권고합니다. 공공 시민포털·민원 사이트에서 가장
    흔한 설정 미흡입니다.
  public_sector_impact:
    - 공용 PC 영속 쿠키로 인한 세션 도용
    - http 채널 쿠키 노출로 인한 MITM 탈취
    - XSS와 결합한 즉시 세션 탈취
  safe_fix: |
    만료는 세션 또는 1시간 내외, secure·httpOnly 항상 활성화.
    res.cookie('sid', token, {
      maxAge: 60 * 60 * 1000,    // 1시간
      secure: true,              // HTTPS 전용
      httpOnly: true,            // JS 접근 차단
      sameSite: 'lax'            // CSRF 완화
    });
    영속 쿠키에는 권한·세션ID 등 중요정보를 절대 담지 마세요.
  references:
    - KISA JavaScript 가이드 제2절 12
    - MOIS-49-SEC-12
    - CWE-539
    - CWE-1004
    - OWASP Session Management Cheat Sheet
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "res.cookie('rememberme', '1', { expires: new Date(Date.now() + 365*24*60*60*1000) });"
    - "res.cookie('sid', token, { maxAge: 31536000000 });"
    - "res.cookie('session', sid, { httpOnly: true });"
  negative:
    - "res.cookie('rememberme', '1', { expires: new Date(Date.now() + 60*60*1000), secure: true, httpOnly: true });"
    - "res.cookie('sid', token, { maxAge: 3600000, secure: true, httpOnly: true, sameSite: 'lax' });"
    - "res.cookie('locale', 'ko', { maxAge: 365*24*60*60*1000 });"
---

## 무엇이 위험한가
- 기본 쿠키는 *세션 쿠키*로 브라우저 종료 시 사라지지만, `expires`/`maxAge`를 길게 주면 디스크에 영속 저장됩니다. 공용 PC·노트북 도난·디스크 포렌식 한 번으로 인증 토큰이 유출됩니다.
- `secure` 미설정 시 같은 출처의 http 요청에서도 쿠키가 전송되어 평문 노출됩니다.
- `httpOnly` 미설정 시 XSS 한 번이 곧 세션 탈취입니다.

## 안전한 패턴 (가이드 원문 인용)
```javascript
router.get("/patched", (req, res) => {
  // 쿠키의 만료 시간을 적절하게 부여하고 secure 옵션을 활성화
  res.cookie('rememberme', '1', {
    expires: new Date(Date.now() + 60*60*1000),
    secure: true,
    httpOnly: true
  });
  return res.send("쿠키 발급 완료");
});
```

## False positive 주의
- 보안과 무관한 환경설정 쿠키(`locale`, `theme`)는 쿠키 이름이 세션/인증 키워드(`session|sid|auth|token|jwt|rememberme|userId|loginToken`)에 포함되지 않으므로 매칭되지 않습니다.
- `secure: true`와 `httpOnly: true`를 모두 명시한 인증 쿠키는 부정 lookahead로 매칭에서 제외합니다.
- 짧은 만료(`60 * 60 * 1000` 이하)는 영속 쿠키가 아니므로 매칭하지 않습니다.
