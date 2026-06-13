---
id: KISA-PY-SEC-11
title_ko: Python 부적절한 인증서 유효성 검증 (verify=False / CERT_NONE / check_hostname=False)
title_en: Improper TLS certificate validation in Python (verify=False / CERT_NONE)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 11. 부적절한 인증서 유효성 검증
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-43
cwe: [CWE-295, CWE-297]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline, llm-integration]
related_baseline: [MOIS-49-SEC-11]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - 'requests\.(?:get|post|put|delete|patch|head|options|request)\s*\([^)]*verify\s*=\s*False'
    - 'httpx\.(?:get|post|put|delete|patch|Client|AsyncClient)\s*\([^)]*verify\s*=\s*False'
    - 'aiohttp\.(?:TCPConnector|ClientSession)\s*\([^)]*(?:ssl|verify_ssl)\s*=\s*False'
    - 'urllib3\.disable_warnings\s*\('
    - 'ssl\.SSLContext\s*\(\s*\)'
    - 'verify_mode\s*=\s*ssl\.CERT_NONE'
    - 'check_hostname\s*=\s*False'
    - 'ssl\._create_unverified_context\s*\('
    - 'ssl\._create_default_https_context\s*=\s*ssl\._create_unverified_context'
  category: kisa-secure-coding
  why_it_matters: >-
    `requests.get(url, verify=False)`나 `CERT_NONE`은 *TLS 자체를 무력화*합니다.
    중간자 공격자는 패킷을 자유롭게 위조하고 토큰·세션을 가로챕니다.
    공공기관에서는 *내부 자가 서명 인증서* 회피용으로 무심코 쓰는 경우가
    많은데, 운영에 그대로 배포되어 외부 API 호출까지 검증을 풀어 버리는
    사고가 반복됩니다. `ssl.SSLContext()` 기본 생성자도 verify_mode가
    CERT_NONE이라 동일하게 위험합니다.
  public_sector_impact:
    - TLS 무력화로 토큰·인증정보 중간자 탈취
    - 외부 행정 API 응답 위·변조
    - 정보보안 기본지침의 통신 무결성 요건 위배
  safe_fix: |
    기본 검증을 켜고, 사설 CA가 필요하면 CA 번들을 명시:
        requests.get(url)                              # 기본 verify=True
        requests.get(url, verify="/etc/ssl/certs/my-ca.pem")
    저수준 ssl:
        ctx = ssl.create_default_context()             # verify_mode=CERT_REQUIRED, check_hostname=True
        ctx.load_verify_locations(cafile="my-ca.pem")  # 사설 CA가 필요할 때만
    `urllib3.disable_warnings`로 경고를 숨기는 행위 자체를 금지하세요.
  references:
    - KISA Python 가이드 제2절 11
    - MOIS-49-SEC-11
    - CWE-295, CWE-297
    - https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification
    - https://docs.python.org/3/library/ssl.html#ssl.create_default_context
  can_auto_fix: false
examples:
  language: python
  positive:
    - "import requests\nrequests.get('https://api.example.com', verify=False)"
    - "import ssl\ncontext = ssl.SSLContext()\ncontext.verify_mode = ssl.CERT_NONE"
    - "import urllib3\nurllib3.disable_warnings()"
  negative:
    - "import requests\nrequests.get('https://api.example.com')"
    - "import requests\nrequests.get('https://api.example.com', verify='/etc/ssl/certs/my-ca.pem')"
    - "import ssl\ncontext = ssl.create_default_context()"
---

## 무엇이 위험한가
TLS의 *유일한 안전 보장*은 인증서 검증입니다. 그걸 끄면 HTTPS는 그저 *암호화된 평문*과 같습니다 — 공격자가 자기 CA로 발급한 인증서를 끼워 넣어 통째로 가로챕니다. "테스트 환경에서만"이라는 주석과 함께 들어간 `verify=False`가 운영 배포 단계에서 *그대로* 살아남는 사례가 압도적으로 많습니다. `ssl.SSLContext()` 직접 생성자 호출도 매우 위험합니다 — 기본값이 `CERT_NONE`이라 명시적으로 끈 것과 동일합니다.

## 안전한 패턴 (가이드 원문 인용)
```python
# requests / httpx — 기본 verify=True 그대로 사용
import requests
resp = requests.get("https://api.example.go.kr/v1/...", timeout=5)

# 사설 CA가 필요한 경우 — 검증은 켠 채로 CA 파일만 지정
resp = requests.get(url, verify="/etc/ssl/certs/agency-internal-ca.pem")

# 저수준 ssl — 절대 SSLContext()를 직접 호출하지 말고
# create_default_context() 사용
import ssl
context = ssl.create_default_context()
# 필요 시: context.load_verify_locations(cafile="...")
with socket.create_connection((HOST, 443)) as sock, \
     context.wrap_socket(sock, server_hostname=HOST) as ssock:
    ssock.send(...)
```

## False positive 주의
- 본 룰은 `ssl.SSLContext()` *인자 없는 호출*만 잡습니다. `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` 처럼 클라이언트 컨텍스트를 지정한 경우는 자동으로 `CERT_REQUIRED` + `check_hostname=True`가 되어 안전하므로 매칭되지 않습니다.
- 테스트 코드(`pytest` 픽스처 등)에서 자가 서명 서버 검증을 끄는 경우는 *테스트 파일 한정*으로 무시 주석을 사용하세요. 같은 모듈에서 운영 코드와 섞이면 룰이 정상 동작합니다.
- `urllib3.disable_warnings()`은 단독 호출만으로 매칭됩니다 — 경고를 숨기는 것 자체가 보통 `verify=False` 사용과 함께 가기 때문에 의도적으로 포함했습니다.
