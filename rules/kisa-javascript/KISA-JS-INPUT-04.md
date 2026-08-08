---
id: KISA-JS-INPUT-04
title_ko: JavaScript XSS 위험 - innerHTML/outerHTML/document.write/dangerouslySetInnerHTML
title_en: JavaScript XSS via innerHTML / document.write / dangerouslySetInnerHTML
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Javascript 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 4. 크로스사이트 스크립트(XSS)
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-23
cwe: [CWE-79]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [javascript, typescript]
scenarios: [web-app, web-frontend]
related_baseline: [MOIS-49-INPUT-04, GOV-LLM-OUTPUT-HANDLING-001]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    # innerHTML/outerHTML/dangerouslySetInnerHTML 는 같은 줄에서 DOMPurify·sanitize
    # 등으로 정화한 경우 오탐이므로 부정 전방탐색으로 제외한다(실측: 정화 후 렌더가
    # 정상 방어인데 차단으로 오탐). document.write·jQuery .html()·insertAdjacentHTML 은
    # 정화 래핑이 드물고 실제 위험(DocView document.write 등)이라 그대로 둔다.
    # innerHTML·outerHTML 도 dangerouslySetInnerHTML 과 같은 자리로 옮긴다.
    # 예전 부정 전방탐색은 줄에 `sanitize` 라는 **글자**만 있으면 발견을 취소했고,
    # `sanitizeMaybe(h){return h.trim()}` 에 그대로 뚫렸다(우리 룰 린터의
    # `sanitizer-allowlist-substring` 이 이 두 줄을 지목했다 — 자기 도구가 자기
    # 룰의 남은 결함을 찾은 사례다). 정화 판단은 함수 **본문**을 볼 수 있는
    # `scanners/html_sink_context.py` 가 하고, 결과는 삭제가 아니라 감쇄다.
    - '\.innerHTML\s*=\s*'
    - '\.outerHTML\s*=\s*'
    - 'document\.write(?:ln)?\s*\('
    # 여기서는 **거르지 않는다**. 예전에는 같은 줄에 `sanitize` 라는 글자가
    # 있으면 발견을 통째로 취소했는데, 두 가지가 잘못이었다:
    #   ① 부분문자열이라 `sanitizeMaybe(h){return h.trim()}` 처럼 **이름만 정화**인
    #      함수도 통과했다(적대적 검증 2026-08-08에서 실제로 뚫렸다).
    #   ② 통과가 곧 **삭제**였다 — 판단이 틀리면 위험이 보고서에서 사라진다.
    # 정화 여부 판단은 `scanners/html_sink_context.py` 로 옮겼다. 그쪽은 함수
    # **본문**을 보고, 정화로 보이면 지우지 않고 block → warn 으로 낮추며 이유를
    # 남긴다. 탐지는 넓게, 판단은 문맥을 아는 곳에서, 결과는 삭제가 아니라 감쇄.
    - 'dangerouslySetInnerHTML\s*[:=]'
    # `.html()` 은 **인자가 없으면 getter**(HTML 을 읽기만 함)라 주입이 일어나지
    # 않는다. 실측(2026-08-08) 오탐 3건이 전부 cheerio 의 `$("body").html()`
    # 읽기였다. 인자가 하나라도 있어야(= 닫는 괄호가 바로 오지 않아야) 설정이다.
    # 줄바꿈으로 인자를 넘긴 경우 줄 끝에서 멈추므로 그대로 잡힌다(보수적).
    - "\\$\\([^)]*\\)\\.html\\s*\\(\\s*(?![\\s)])"
    - 'insertAdjacentHTML\s*\('
  category: kisa-secure-coding
  why_it_matters: >-
    innerHTML, outerHTML, document.write, jQuery .html(), React의
    dangerouslySetInnerHTML는 *HTML 문자열을 그대로 DOM에 주입*합니다. 사용자
    입력이나 LLM 출력이 그대로 들어가면 즉시 XSS가 발생합니다. 공공 민원
    사이트, 통계 대시보드, 챗봇 UI에서 가장 빈번한 약점입니다.
  public_sector_impact:
    - 사용자 세션·CSRF 토큰 탈취
    - 행정 사이트 신뢰 손상
    - LLM 응답 표시 시 즉시 XSS
  safe_fix: |
    텍스트만 표시할 때는 .textContent 또는 React의 일반 props 사용.
    HTML이 필요하면 DOMPurify.sanitize(rawHtml)로 정화 후 사용.
    예: el.textContent = userInput;  // 안전
        el.innerHTML = DOMPurify.sanitize(richHtml);  // sanitize 후
  references:
    - KISA JavaScript 가이드 제2절 4
    - MOIS-49-INPUT-04
    - CWE-79
    - OWASP ASVS V1.3
  can_auto_fix: false
examples:
  language: javascript
  positive:
    - "el.innerHTML = userInput;"
    - "document.write(payload);"
    - "$(target).html(raw);"
    - "<div dangerouslySetInnerHTML={{__html: post.content}} />"
  negative:
    - "el.textContent = userInput;"
    - "const safe = DOMPurify.sanitize(rawHtml);"
    - "el.innerHTML = DOMPurify.sanitize(richHtml);"
    - "<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}} />"
---

## 무엇이 위험한가
XSS는 OWASP Top 10에 매년 등장하는 약점입니다. JavaScript에서는 다음 6개 패턴이 거의 모든 XSS 사례를 차지합니다:
1. `el.innerHTML = userText`
2. `el.outerHTML = userText`
3. `document.write(userText)`
4. `$(el).html(userText)` (jQuery)
5. `<div dangerouslySetInnerHTML={{__html: userText}} />` (React)
6. `el.insertAdjacentHTML('beforeend', userText)`

## 안전한 패턴 (가이드 원문 인용)
```javascript
// 텍스트만 필요한 경우
el.textContent = userInput;

// HTML이 필요한 경우 - 화이트리스트 sanitize
import DOMPurify from "dompurify";
el.innerHTML = DOMPurify.sanitize(rawHtml, { ALLOWED_TAGS: ["b", "i", "u"] });

// React
<div>{userText}</div>  // JSX 자동 escape
```

## 관련
[GOV-LLM-OUTPUT-HANDLING-001](../scanner-builtin/GOV-LLM-OUTPUT-HANDLING-001.md)이 LLM 출력 특정 패턴을 잡습니다. 본 룰은 *LLM 외 일반 사용자 입력* 케이스를 포함합니다.
