---
id: KISA-PY-SEC-15
title_ko: Python 무결성 검사 없는 코드 다운로드 - 원격 코드 fetch 후 해시·서명 미검증
title_en: Download of code without integrity check in Python
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 15. 무결성 검사없는 코드 다운로드
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-55
cwe: [CWE-494]
severity: high
decision_default: block
domains: [kisa-secure-coding]
languages: [python]
scenarios: [data-pipeline, package-install, web-app]
related_baseline: [MOIS-49-SEC-15]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) 다운로드 결과를 *바로* 실행 — KISA 가이드 안전하지 않은 예시의 핵심 위험
    - "(?:eval|exec)\\s*\\(\\s*(?:requests|httpx|urllib(?:\\.request)?)\\.(?:get|post|urlopen|urlretrieve)\\s*\\("
    - "(?:eval|exec)\\s*\\(\\s*open\\s*\\([^)]+\\)\\.read\\s*\\(\\s*\\)\\s*\\)"
    # 2) requests.get(...).content / .text 를 파일에 쓰면서 해시 검증 부재 신호
    - "(?:requests|httpx)\\.(?:get|post)\\s*\\([^)]*\\)\\.content"
    - "urllib\\.request\\.urlretrieve\\s*\\("
    # 3) subprocess + curl/wget 으로 원격 코드 가져와 실행 (-O, |sh, |bash, |python)
    - "subprocess\\.(?:run|call|Popen|check_output|check_call)\\s*\\(\\s*\\[?\\s*['\"](?:curl|wget)['\"]"
    - "os\\.system\\s*\\(\\s*['\"](?:curl|wget)\\s+[^'\"]*\\|\\s*(?:sh|bash|python\\d?|zsh)"
    # 4) pip install 을 동적/사용자입력으로 — 무결성(--require-hashes) 미사용 신호
    - "subprocess\\.(?:run|call|Popen|check_output|check_call)\\s*\\(\\s*\\[?\\s*['\"](?:pip|pip3|python)['\"]\\s*,\\s*['\"](?:install|-m)['\"]"
    - "pip\\.main\\s*\\(\\s*\\[\\s*['\"]install['\"]"
  category: kisa-secure-coding
  why_it_matters: >-
    KISA 가이드의 안전하지 않은 예시는 `requests.get("https://www.somewhere.com/storage/code.py")`
    응답 본문을 그대로 파일에 쓰고 *해시 검증 없이* 실행 가능한 상태로 둡니다.
    호스트 서버 변조·DNS 스푸핑·중간자 공격 어느 하나라도 성공하면 *공격자가
    원하는 파이썬 코드가 행정 서버에서 실행*됩니다. 가이드 안전 예시는
    `configparser`로 미리 등록된 SHA-256 해시를 읽어
    `hashlib.sha256(remote_code).hexdigest() == remote_code_hash` 검증을 통과한
    뒤에만 파일을 저장합니다. 더 강한 방식은 *코드 서명 인증서*(KISA-PY-SEC-10)로
    공개키 기반 서명을 검증하는 것입니다. `pip install` 또한 동일한 약점을
    가지며, 공공기관 배포 환경에서는 *반드시* `--require-hashes` 옵션과 함께
    pinned requirements 파일을 사용해야 합니다.
  public_sector_impact:
    - 원격 코드 변조로 행정 서버 RCE
    - 공급망 공격 — 공개 PyPI 패키지 typosquat이 행정 시스템에 그대로 설치
    - DNS 스푸핑으로 정상 도메인 응답이 악성 페이로드로 교체
    - 정보보안 기본지침의 소프트웨어 무결성 요건 위반
  safe_fix: |
    1단계: 다운로드 후 *미리 등록된 해시*와 비교:
        import requests, hashlib, configparser
        config = configparser.RawConfigParser()
        config.read('sample_config.cfg')
        expected_hash = config.get('HASH', 'file_hash')

        response = requests.get(url, timeout=10)   # verify=True 기본값 유지
        remote_code = response.content
        if hashlib.sha256(remote_code).hexdigest() != expected_hash:
            raise Exception('파일이 손상되었습니다.')
        with open('save.py', 'wb') as f:
            f.write(remote_code)
    2단계: 가능하면 *공개키 기반 코드 서명*으로 검증 (KISA-PY-SEC-10):
        if verify_digit_signature(remote_code, signature, vendor_pub_key):
            ...
    3단계: pip 의존성은 hash-pinned requirements 사용:
        pip install -r requirements.txt --require-hashes
    4단계: `curl ... | sh` 패턴은 *원천 금지*. 어떤 환경에서도 사용하지 마세요.
    5단계: 다운로드한 코드는 *최소 권한*으로 실행 (별도 OS 사용자, 컨테이너).
  references:
    - KISA Python 가이드 제2절 15
    - MOIS-49-SEC-15
    - CWE-494 Download of Code Without Integrity Check
    - SANS Top 25 — Download of Code Without Integrity Check
    - https://pip.pypa.io/en/stable/topics/secure-installs/
    - https://docs.python.org/3/library/hashlib.html
  can_auto_fix: false
examples:
  language: python
  positive:
    - "exec(requests.get('https://example.com/payload.py').text)"
    - "eval(open('downloaded.py').read())"
    - "with open('save.py', 'wb') as f: f.write(requests.get(url).content)"
    - "urllib.request.urlretrieve('https://example.com/setup.py', 'setup.py')"
    - "subprocess.run(['curl', 'https://get.example.com/install.sh', '-o', 'install.sh'])"
    - "os.system('curl https://example.com/install.sh | bash')"
    - "subprocess.run(['pip', 'install', user_supplied_package])"
  negative:
    - "response = requests.get(url, timeout=5)\nif hashlib.sha256(response.content).hexdigest() == expected: save(response.content)"
    - "resp = requests.get('https://api.example.com/v1/data', timeout=5)\ndata = resp.json()"
    - "with open('local.py') as f: code = f.read()"
    - "data = requests.get('https://api.example.go.kr/v1/data', timeout=5).json()"
---

## 무엇이 위험한가
원격에서 *실행 가능한 코드*를 받아오는 모든 경로는 공격 표면입니다. KISA 가이드의 안전하지 않은 예시는 `requests.get("https://www.somewhere.com/storage/code.py")` 응답 본문을 그대로 `save.py`에 쓰고 실행 가능한 상태로 둡니다. 이 코드는 다음 세 가지 공격에 모두 취약합니다:

1. *호스트 서버 변조* — 원본 도메인의 storage가 공격자에 의해 교체됨
2. *DNS 스푸핑* — 정상 도메인이 공격자 IP로 해석됨 (특히 내부 캐시 DNS 오염)
3. *중간자 공격* — TLS 검증이 켜져 있어도(`verify=True`), 라우팅 경로상 컴퓨터/네트워크가 신뢰 CA 인증서를 추가 설치한 환경(SSL 인터셉트 프록시 등)에서는 회피 가능

가이드 안전 예시는 *미리 공유된 SHA-256 해시*(설정 파일)와 다운로드 본문의 해시를 비교한 뒤에만 저장합니다. 더 강한 보호는 *공개키 기반 코드 서명*(KISA-PY-SEC-10)으로, 송신자 진위와 무결성을 동시에 보장합니다.

공공기관 패치·플러그인 배포 채널은 *반드시 무결성 검증 + 코드 서명* 두 단계를 모두 적용해야 합니다. 그렇지 않은 채널은 *공급망 공격*에 그대로 노출됩니다. `pip install <user_input>` 패턴도 동일 약점이며, 운영 환경 의존성은 `pip install -r requirements.txt --require-hashes`로 *해시-pinned* 설치만 허용해야 합니다.

특히 `curl ... | bash`, `os.system("curl ... | sh")` 같은 패턴은 *어떤 환경에서도* 사용 금지입니다 — 한 줄로 *원격 임의 코드 실행*을 완성하는 가장 위험한 안티패턴입니다.

## 안전한 패턴 (가이드 원문 인용)
```python
import requests
import hashlib
import configparser

def execute_remote_code():
    config = configparser.RawConfigParser()
    config.read('sample_config.cfg')

    url = "https://www.somewhere.com/storage/code.py"
    remote_code_hash = config.get('HASH', 'file_hash')

    # 원격 코드 다운로드 (verify=True 기본값 유지)
    response = requests.get(url, timeout=10)
    remote_code = response.content

    # 다운로드 받은 파일의 해시값 검증
    sha = hashlib.sha256()
    sha.update(remote_code)
    if sha.hexdigest() != remote_code_hash:
        raise Exception('파일이 손상되었습니다.')

    # 무결성 검증 통과 후에만 저장
    file_name = 'save.py'
    with open(file_name, 'wb') as f:
        f.write(remote_code)
```

더 강한 보호 — 공개키 서명 검증 (KISA-PY-SEC-10 참고):
```python
# 다운로드 + 서명파일 fetch
code = requests.get(code_url).content
sig = requests.get(sig_url).content

# 벤더 공개키로 서명 검증
if not verify_digit_signature(code, sig, vendor_public_key):
    raise SecurityError("코드 서명 검증 실패")

with open('save.py', 'wb') as f:
    f.write(code)
```

pip 의존성 무결성:
```bash
# requirements.txt 생성
pip-compile --generate-hashes requirements.in

# 운영 설치
pip install -r requirements.txt --require-hashes
```

## False positive 주의
- 본 룰은 *같은 라인*에 다운로드 + 실행 패턴이 있거나, 위험 시그니처(`urlretrieve`, `curl|sh`, dynamic `pip install`)가 등장할 때 매칭합니다. 다운로드와 해시 검증이 *별도 라인*으로 구분되어 있어도 본 룰의 일부 패턴(예: `requests.get(...).content`)은 여전히 매칭됩니다 — 의도된 보수적 detection입니다. 검증 코드가 별도 함수에 있다면 `# gvskb: ignore KISA-PY-SEC-15`로 억제하세요.
- `requests.get(url).json()` 처럼 *JSON 데이터*만 받아 처리하는 경우는 `.content`/`.text` 패턴과 다르므로 매칭되지 않습니다. 단, 받은 JSON으로 `eval`/`exec`을 한다면 다른 룰(KISA-PY-INPUT 시리즈)이 잡습니다.
- `subprocess.run(['pip', 'install', '-r', 'requirements.txt', '--require-hashes'])` 처럼 해시 검증이 명시된 호출은 매칭됩니다 (`['pip', 'install'` 패턴이 일치). 본 룰은 *line-level regex 한계로* `--require-hashes` 옵션 유무까지 검증할 수 없습니다. 명시적으로 `# gvskb: ignore KISA-PY-SEC-15` 주석을 붙이거나, 빌드 시스템에서 호출하는 형태(`Makefile`, `Dockerfile`)로 분리하세요.
- `urllib.request.urlretrieve(...)` 는 *결과를 항상 파일로 떨어뜨리는* 동작이라 검증 없이 사용하는 것 자체가 위험 시그널입니다. 의도적으로 매칭 대상입니다.
- `curl ... | bash` 패턴은 어떤 컨텍스트에서도 안전한 사용처가 없으므로 매칭을 끄지 마세요.
