# KISA JavaScript 시큐어코딩 가이드 (2023년 개정본)

KISA가 공공·민간 개발자에게 제공하는 **35개 JavaScript 보안약점** 가이드를 기반으로 한 룰 모음입니다. Node.js와 브라우저 JS 양쪽에 적용 가능합니다.

## 출처
- **발행**: 한국인터넷진흥원(KISA), 2023년 개정본
- **원문**: Javascript 시큐어코딩 가이드(2023년 개정본) PDF, 153페이지
- **저작권**: 정부 가이드, 인용·재구조화 형태. 본문 전체 복제 금지

## 카테고리 구성 (원문 기준)

| 절 | 카테고리 | 항목 수 | 본 디렉토리 룰 |
|---|---|---|---|
| 제2절 | 입력데이터 검증 및 표현 | 13 | KISA-JS-INPUT-* |
| 제3절 | 보안기능 | 16 | KISA-JS-SEC-* |
| 제4절 | 시간 및 상태 | 1 | KISA-JS-TIME-* |
| 제5절 | 에러처리 | 3 | KISA-JS-ERR-* |
| 제6절 | 코드오류 | 3 | KISA-JS-CODE-* |
| 제7절 | 캡슐화 | 4 | KISA-JS-ENCAP-* |
| 제8절 | API 오용 | 2 | KISA-JS-API-* |

**현재 룰 수**: 5 (시범 단계, INPUT 4 + SEC 1)

## Python 가이드와의 차이
- JavaScript는 Python보다 **인젝션·XSS 표면**이 넓음 (브라우저+Node.js)
- 동일 약점이라도 *언어 특화 패턴* 필요 (예: `eval` 외에 `new Function`, `setTimeout(문자열)` 등)
- 브라우저 측 룰은 `domains: [web-frontend]`, Node.js 측은 `[backend-node]`로 구분

## 시범 단계 (2026-05-31)
입력 검증 + 취약 암호화부터 시작. 안정 후 나머지 항목 단계적으로 추가합니다.
