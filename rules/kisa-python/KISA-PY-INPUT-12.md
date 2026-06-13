---
id: KISA-PY-INPUT-12
title_ko: Python SSRF - 사용자 입력 URL을 검증 없이 requests/urllib에 전달
title_en: Server-Side Request Forgery (SSRF) via unvalidated user URL in Python HTTP clients
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제1절 12. 서버사이드 요청 위조
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-12-SSRF
cwe: [CWE-918]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, agent, llm-integration]
related_baseline: [MOIS-49-INPUT-12]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - 'requests\.(?:get|post|put|patch|delete|head|options|request)\s*\([^)]*request\.(?:GET|POST|args|form|values|params|json)'
    - 'httpx\.(?:get|post|put|patch|delete|head|options|request)\s*\([^)]*request\.(?:GET|POST|args|form|values|params|json)'
    - 'aiohttp\.ClientSession\s*\([^)]*\)\.[a-z]+\s*\([^)]*request\.(?:GET|POST|args|form|values|params|json)'
    - 'urllib\.request\.urlopen\s*\([^)]*request\.(?:GET|POST|args|form|values|params|json)'
    - '(?<![A-Za-z0-9_.])urlopen\s*\(\s*request\.(?:GET|POST|args|form|values|params|json)'
  category: kisa-secure-coding
  why_it_matters: >-
    `requests.get(request.POST['url'])` 같은 패턴은 *서버 내부망으로의 임의
    요청*을 허용합니다. 공격자는 `http://192.168.x.x/admin`, `http://169.254.169.254/`
    (클라우드 메타데이터), `file:///etc/passwd` 등을 요청해 내부 자원을
    탈취합니다. 공공 클라우드(G-Cloud) 마이그레이션 시 메타데이터 토큰 노출
    위험이 특히 큽니다. LLM 에이전트가 "URL 가져오기" 도구를 노출하는 경우
    동일한 패턴이 다시 등장합니다.
  public_sector_impact:
    - 내부망 자원·관리 페이지 접근
    - 클라우드 메타데이터 토큰 탈취 (G-Cloud, AWS IMDS)
    - 사설 IP/file:// 스킴으로 서버 파일 노출
  safe_fix: |
    1) 허용 URL을 화이트리스트로 관리하고 *정확 일치* 검증.
    2) 사용자 URL이 필요하면 urllib.parse.urlparse로 scheme/host 검증:
        - scheme은 https만 허용
        - host는 사설/메타데이터 IP(10/8, 172.16/12, 192.168/16, 169.254/16, 127/8) 차단
        - DNS rebinding 방지를 위해 socket.gethostbyname으로 IP 해석 후 재검증
    3) requests에서는 timeout과 allow_redirects=False 설정.
    4) 가능하면 별도 outbound 프록시를 통해서만 외부 호출 허용.
  references:
    - KISA Python 가이드 제1절 12
    - MOIS-49-INPUT-12
    - CWE-918
    - OWASP Server Side Request Forgery Prevention Cheat Sheet
  can_auto_fix: false
examples:
  language: python
  positive:
    - "import requests\nresult = requests.get(request.POST.get('address', '')).text"
    - "import requests\nresp = requests.post(request.args['url'], json={'a': 1})"
    - "from urllib.request import urlopen\nurlopen(request.GET['target'])"
  negative:
    - "import requests\nif addr in ALLOW_SERVER_LIST:\n    result = requests.get(addr, timeout=5).text"
    - "import requests\nresult = requests.get('https://api.myservice.go.kr/v1/status').text"
    - "import requests\nresp = requests.get(BASE_URL + '/health')"
---

## 무엇이 위험한가
SSRF는 *방화벽 안쪽에 있는 자원*을 외부에서 호출하게 만드는 공격입니다. `requests.get(request.POST['url'])` 한 줄로 공격자는:
- `http://localhost:8080/admin` — 같은 호스트의 관리 페이지
- `http://169.254.169.254/latest/meta-data/` — 클라우드 메타데이터 (G-Cloud/AWS의 IAM 토큰까지)
- `file:///etc/passwd` — 로컬 파일
- `http://internal-db:5432/` — 내부 DB 핑/스캔
같은 요청을 *서버 권한으로* 실행할 수 있습니다. 공공기관 클라우드 전환에서 가장 빠르게 발견되는 취약점 중 하나입니다.

## 안전한 패턴 (가이드 원문 인용)
```python
import requests
from urllib.parse import urlparse
import ipaddress, socket

ALLOW_SERVER_LIST = [
    'https://api.myservice.go.kr/v1/public',
    'https://login.myservice.go.kr/oauth',
]

# 1) 화이트리스트 정확 매칭
if addr not in ALLOW_SERVER_LIST:
    return render(request, '/error.html', {'error': '허용되지 않은 서버입니다.'})

# 2) 동적 URL이 필요하면 scheme + 해석된 IP까지 검증
u = urlparse(addr)
if u.scheme != 'https': abort(400)
ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
if ip.is_private or ip.is_loopback or ip.is_link_local:
    abort(400)  # 사설/메타데이터 IP 차단

result = requests.get(addr, timeout=5, allow_redirects=False).text
```

## False positive 주의
- 정적 URL, BASE_URL+path 결합, 화이트리스트 통과 후 호출은 `request.*`을 요구하므로 매칭되지 않습니다.
- 사용자 입력을 변수에 받아 다른 라인에서 검증 후 호출하는 패턴은 본 룰에 잡히지 않습니다 — 단일 라인 검출의 한계이며, 의도된 false-negative입니다. python-ast 어댑터가 향후 흐름 추적을 보강할 예정입니다.
