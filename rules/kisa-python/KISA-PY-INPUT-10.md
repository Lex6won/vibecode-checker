---
id: KISA-PY-INPUT-10
title_ko: Python LDAP 삽입 - 이스케이프 없는 사용자 입력의 LDAP 필터 결합
title_en: LDAP injection via unescaped user input in Python LDAP filters
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 10. LDAP 삽입
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-10
cwe: [CWE-90]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, auth]
related_baseline: [MOIS-49-INPUT-10]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - '["''][^"'']*\(\s*(?:cn|uid|sn|mail|objectclass|givenname|userprincipalname)\s*=[^"'']*["'']\s*%\s*[a-zA-Z_]'
    - '["''][^"'']*\(\s*(?:cn|uid|sn|mail|objectclass|givenname|userprincipalname)\s*=[^"'']*["'']\s*\+\s*[a-zA-Z_]'
    - 'conn\.search\s*\([^)]*["''][^"'']*%[sd]'
    - '\.search_s\s*\([^)]*["''][^"'']*%[sd]'
  category: kisa-secure-coding
  why_it_matters: >-
    `'(&(objectclass=%s))' % search_keyword` 같이 사용자 입력을 LDAP 필터에
    그대로 끼우면 `*)(uid=*)`처럼 와일드카드를 넣어 *전체 사용자 열람·인증
    우회·권한 상승*이 가능합니다. 공공기관의 GPKI/디렉터리 기반 SSO,
    조직도 검색 API에서 자주 발견됩니다. ldap3 라이브러리는
    `escape_filter_chars()`를 제공하므로 반드시 통과시켜야 합니다.
  public_sector_impact:
    - 디렉터리 전체 사용자 정보 노출
    - 관리자 권한 우회 로그인
    - GPKI/SSO 인증 우회
  safe_fix: |
    *반드시* ldap3의 `escape_filter_chars()`로 메타문자(`* ( ) \ NUL`)를
    이스케이프하세요.
        from ldap3.utils.conv import escape_filter_chars
        safe = escape_filter_chars(search_keyword)
        search_str = f'(&(objectclass={safe}))'
        conn.search('dc=company,dc=com', search_str, attributes=[...])
    추가로 입력값을 화이트리스트(영문/숫자만)로 검증하고 LDAP 바인딩 계정의
    권한을 최소화하세요.
  references:
    - KISA Python 가이드 제1절 10
    - MOIS-49-INPUT-10
    - CWE-90
    - OWASP LDAP Injection Prevention Cheat Sheet
  can_auto_fix: false
examples:
  language: python
  positive:
    - "search_str = '(&(objectclass=%s))' % search_keyword"
    - "filter = '(cn=' + name + ')'"
    - "conn.search('dc=company,dc=com', '(uid=%s)' % user_input)"
  negative:
    - "from ldap3.utils.conv import escape_filter_chars\nsafe = escape_filter_chars(search_keyword)\nconn.search('dc=co,dc=kr', f'(&(objectclass={safe}))')"
    - "conn.search('dc=co,dc=kr', '(objectclass=person)')"
    - "conn.search('dc=co,dc=kr', '(&(uid=admin)(objectclass=person))')"
---

## 무엇이 위험한가
LDAP 필터의 메타문자(`* ( ) \`)는 *쿼리 구조 자체*를 바꿉니다. `(&(objectclass=%s))` 패턴에서 `search_keyword`가 `*)(uid=*` 이면 필터가 `(&(objectclass=*)(uid=*))`가 되어 디렉터리 전체가 노출됩니다. 인증 시나리오에서 `*` 단독 입력은 *임의 계정으로 로그인*을 허용할 수도 있습니다. AI 코딩 도우미가 `f-string`으로 LDAP 필터를 만드는 패턴이 특히 위험합니다.

## 안전한 패턴 (가이드 원문 인용)
```python
from ldap3 import Connection, Server, ALL
from ldap3.utils.conv import escape_filter_chars

server = Server('ldap.goodsource.com', get_info=ALL)
conn = Connection(server, dn, password, auto_bind=True)

# 사용자 입력은 escape_filter_chars로 메타문자 이스케이프
safe_keyword = escape_filter_chars(search_keyword)
search_str = f'(&(objectclass={safe_keyword}))'

conn.search(
    'dc=company,dc=com',
    search_str,
    attributes=['sn', 'cn', 'mail', 'mobile', 'uid'],
)
```

## False positive 주의
- 정적 필터 (`'(objectclass=person)'`)는 매칭되지 않습니다.
- `escape_filter_chars()`를 거친 변수를 f-string에 끼우는 패턴은 본 룰이 잡습니다 (안전한 코드도 일단 매칭됨). 명시적으로 이스케이프했음을 확인했다면 `# gvskb: ignore KISA-PY-INPUT-10`로 억제하세요.
- 위 false positive를 줄이려고 ldap3 패키지의 *별도 정적 분석*은 python-ast 어댑터 확장 시점에 추가 예정입니다.
