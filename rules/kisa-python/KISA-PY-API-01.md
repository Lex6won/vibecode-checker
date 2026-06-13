---
id: KISA-PY-API-01
title_ko: Python DNS lookup에 의존한 보안결정 - socket.gethostbyname 결과로 trust 판정
title_en: Security decision based on DNS lookup result in Python (gethostbyname trust)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제8절 1. DNS lookup에 의존한 보안결정
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-41
cwe: [CWE-247, CWE-350, CWE-807]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, auth, data-pipeline]
related_baseline: [MOIS-49-API-01]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "socket\\.gethostbyname\\s*\\("
    - "socket\\.gethostbyaddr\\s*\\("
    - "socket\\.getfqdn\\s*\\("
    - "(?i)request\\.(?:META\\[['\"]REMOTE_HOST['\"]\\]|host_name|remote_host)"
    - "(?i)request\\.(?:headers\\.get\\(['\"]Host['\"].*\\)|host)\\s*==\\s*['\"][A-Za-z0-9.-]+['\"]"
  category: kisa-secure-coding
  why_it_matters: >-
    `socket.gethostbyname()`이 돌려준 IP를 *신뢰 결정*(접근 통제, 로그인 우회,
    내부망 판정)에 사용하면 공격자가 *로컬/캐시 DNS 오염*만으로 보호 우회가
    가능합니다. 마찬가지로 HTTP `Host` 헤더·역방향 DNS(`gethostbyaddr`)는
    *공격자가 임의로 조작*할 수 있어 보안 판단의 근거가 될 수 없습니다.
    KISA 가이드는 "보안결정에서 도메인명을 이용한 DNS lookup을 하지 않도록
    한다"고 명시합니다. 공공기관 인트라넷에서 *내부망 판정을 도메인으로*
    하는 미들웨어가 가장 흔한 사례입니다.
  public_sector_impact:
    - DNS 캐시 오염을 통한 인증 우회
    - 내부망 판정 위장 (외부 공격자가 내부망 사용자로 가장)
    - Host 헤더 조작을 통한 권한 상승
  safe_fix: |
    *고정된 IP·CIDR* 또는 *암호학적 신원*(mTLS 클라이언트 인증서, JWT 등)으로
    판정하세요.
        # 가이드 안전 예시: IP 직접 비교
        import socket, ipaddress
        TRUSTED_IPS = {ipaddress.ip_address("192.168.10.7")}
        client_ip = ipaddress.ip_address(request.META["REMOTE_ADDR"])
        if client_ip in TRUSTED_IPS:
            ...
        # 더 안전한 방법: mTLS / OIDC 토큰
        cert = request.environ.get("SSL_CLIENT_CERT")
        verify_certificate(cert, ca_bundle)
    내부망 판정이라면 *CIDR 매칭*으로:
        INTERNAL = ipaddress.ip_network("10.0.0.0/8")
        if client_ip in INTERNAL: ...
  references:
    - KISA Python 가이드 제8절 1
    - MOIS-49-API-01
    - CWE-247, CWE-350, CWE-807
    - https://docs.python.org/3/library/socket.html
    - https://owasp.org/www-community/attacks/Host_Header_Injection
  can_auto_fix: false
examples:
  language: python
  positive:
    - "if socket.gethostbyname(host) == '192.168.10.7':\n    trusted = True"
    - "name, _, _ = socket.gethostbyaddr(client_ip)"
    - "if request.host == 'admin.internal':\n    grant_admin = True"
  negative:
    - "import ipaddress\nif ipaddress.ip_address(client_ip) in ipaddress.ip_network('10.0.0.0/8'):\n    trusted = True"
    - "cert = request.environ.get('SSL_CLIENT_CERT')\nverify_certificate(cert, ca_bundle)"
    - "logger.info('client_host=%s', socket.getfqdn.__name__)"
---

## 무엇이 위험한가
KISA 가이드 본문 *안전하지 않은 예시*:

```python
def is_trust(host_domain_name):
    trusted = False
    trusted_host = "trust.example.com"
    # 공격자에 의해 실행되는 서버의 DNS가 변경될 수 있으므로 안전하지 않다
    if trusted_host == host_name:
        trusted = True
    return trusted
```

공격자가 사용할 수 있는 우회 경로:
- *로컬 DNS 캐시 오염*: 사용자 측 또는 중간 DNS 서버 캐시 변조
- *HTTP Host 헤더 조작*: HTTP 클라이언트는 임의 Host 헤더 전송 가능
- *역방향 DNS 위조*: `gethostbyaddr()` 결과는 공격자가 운영하는 PTR 레코드로 자유롭게 설정 가능
- *Rebinding*: TTL을 짧게 두고 첫 lookup 후 IP를 바꾸는 DNS rebinding

이 패턴은 공공기관 *내부망 전용 미들웨어*에서 가장 흔히 보입니다. 외부 공격자가 단지 HTTP 요청의 `Host: admin.internal` 헤더 한 줄로 내부망 권한을 요구하는 시나리오가 실제로 가능합니다.

## 안전한 패턴 (가이드 원문 인용)
```python
import socket, ipaddress

# 가이드 안전 예시: 도메인 비교 대신 IP 직접 비교
def is_trust(host_domain_name):
    trusted_ip = ipaddress.ip_address("192.168.10.7")
    dns_resolved_ip = ipaddress.ip_address(socket.gethostbyname(host_domain_name))
    return dns_resolved_ip == trusted_ip
```

더 강한 방법:
```python
# 1) CIDR 매칭 (내부망 판정)
INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12")]
def is_internal(client_ip: str) -> bool:
    ip = ipaddress.ip_address(client_ip)
    return any(ip in net for net in INTERNAL)

# 2) mTLS 클라이언트 인증서 (가장 안전)
def authenticated_client(request) -> str | None:
    cert_pem = request.environ.get("SSL_CLIENT_CERT")
    if not cert_pem:
        return None
    return verify_and_extract_cn(cert_pem, trusted_ca_bundle)
```

## False positive 주의
- *로깅 목적*의 DNS lookup(`logger.info("client=%s", socket.gethostbyname(...))`)은 보안 결정이 아니지만 패턴은 매칭됩니다. 의도가 분명하면 `# gvskb: ignore KISA-PY-API-01`로 억제하세요.
- `request.host == 'localhost'`처럼 *개발 환경 가드*는 false positive일 수 있습니다. 패턴은 `[A-Za-z0-9.-]+` 임의 도메인을 잡기 때문입니다. 개발 코드라면 억제하거나 `if os.environ["ENV"] == "dev"` 같은 별도 가드를 두세요.
- 본 룰은 *socket.gethostbyname/gethostbyaddr/getfqdn*과 *프레임워크의 host 속성 직접 비교*를 잡습니다. `ipaddress.ip_address(...) in network` 패턴은 잡지 않습니다(가이드 권장 방식).
- AST 기반으로 *호출 결과가 실제 보안 결정에 쓰였는지*까지 추적하려면 별도 어댑터가 필요합니다. 현재는 *signal* 룰로 유지하여 사람 검토를 유도합니다.
