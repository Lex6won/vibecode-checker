---
id: KISA-PY-INPUT-09
title_ko: Python XPath/XQuery 삽입 - 문자열 결합으로 만든 XPath 쿼리
title_en: XPath / XQuery injection via string concatenation in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 9. XML 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-09
cwe: [CWE-643, CWE-91]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline]
related_baseline: [MOIS-49-INPUT-09]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - '\.xpath\s*\([^)]*\+\s*[a-zA-Z_]'
    - '\.xpath\s*\(\s*f["'']'
    - '\.xpath\s*\([^)]*%\s*[a-zA-Z_]'
    - '\.xpath\s*\([^)]*\.format\s*\('
    - '\.find(?:all)?\s*\(\s*f["'']'
  category: kisa-secure-coding
  why_it_matters: >-
    `root.xpath("/users/user[@name='" + name + "']")` 같은 문자열 결합 XPath는
    `name`에 `' or '1'='1`을 넣어 쿼리 구조를 바꿔 *권한 우회·전체 사용자 노출*
    이 가능합니다. 공공 LDAP 디렉터리 검색, XML 기반 권한 매트릭스, HWPX 메타
    데이터 추출 등에서 자주 발견됩니다. 표준 `xml.etree.ElementTree`는
    파라미터화 XPath를 지원하지 않아 lxml로 옮겨야 합니다.
  public_sector_impact:
    - 사용자/권한 정보 무단 열람
    - 인증 우회
    - 행정 메타데이터 변조
  safe_fix: |
    lxml의 *파라미터화 XPath* 사용:
        from lxml import etree
        query = "/collection/users/user[@name = $paramname]/home/text()"
        elmts = root.xpath(query, paramname=user_name)
    파라미터화가 불가능한 경우는 화이트리스트(영문/숫자만 허용 등) 검증 후
    사용하고, 인용부호와 쿼리 예약어를 제거하세요.
  references:
    - KISA Python 가이드 제1절 9
    - MOIS-49-INPUT-09
    - CWE-643
    - OWASP XPath Injection
  can_auto_fix: false
examples:
  language: python
  positive:
    - "elmts = root.xpath(\"/users/user[@name='\" + user_name + \"']\")"
    - "elmts = root.xpath(f\"/users/user[@name='{user_name}']\")"
    - "elmts = root.xpath('/users/user[@name=\"%s\"]' % user_name)"
  negative:
    - "elmts = root.xpath('/users/user[@name = $paramname]', paramname=user_name)"
    - "elmts = root.xpath('/users/user')"
    - "elmts = tree.findall('./user')"
---

## 무엇이 위험한가
XPath는 SQL과 같은 *문자열 기반 쿼리 언어*이고 동일한 삽입 공격에 노출됩니다. `f"/users/user[@name='{name}']"` 패턴은 `name`에 `' or '1'='1` 또는 `']/.. /..` 같은 문자열을 넣어 전체 트리를 노출시키는 데 사용됩니다. 파이썬 표준 `xml.etree.ElementTree`는 파라미터화를 지원하지 않으므로 *lxml로 옮겨 `$paramname` 바인딩을 써야* 합니다.

## 안전한 패턴 (가이드 원문 인용)
```python
from lxml import etree
tree = etree.parse("user.xml", etree.XMLParser(resolve_entities=False))
root = tree.getroot()

# 파라미터화된 XPath — lxml 전용
query = "/collection/users/user[@name = $paramname]/home/text()"
elmts = root.xpath(query, paramname=user_name)
```

## False positive 주의
- 정적 XPath (`root.xpath('/users/user')`) 또는 `xpath(query, paramname=...)` 같은 파라미터화 호출은 매칭되지 않습니다.
- 일반 `findall`/`find`도 f-string 인자만 잡아 일반 사용에는 영향 없습니다.
