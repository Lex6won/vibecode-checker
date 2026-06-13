---
id: KISA-PY-SEC-08
title_ko: Python 보안 목적에 부적절한 난수 사용 (random / numpy.random / 고정 seed)
title_en: Insecure randomness for security purposes in Python (random / numpy.random)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제2절 8. 적절하지 않은 난수 값 사용
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-41
cwe: [CWE-330, CWE-338]
severity: high
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [auth, web-app, llm-integration]
related_baseline: [MOIS-49-SEC-08]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    # 1) 같은 줄에 보안 키워드 변수 = ... random.<func>(...)
    - "(?i)\\b(?:token|password|passwd|pwd|otp|secret|session(?:_?id|_?key)?|nonce|api[_-]?key|salt|reset[_-]?code|csrf[_-]?token|auth[_-]?code)[A-Za-z0-9_]*\\s*=\\s*[^=\\n]*random\\.(?:choice|choices|randrange|randint|sample|getrandbits|random)\\s*\\("
    # 2) return 식 안에서 random.<func> + 같은 줄 보안 키워드
    - "(?i)\\brandom\\.(?:choice|choices|randrange|randint|sample|getrandbits|random)\\s*\\([^)]*\\)[^\\n]{0,80}(?:token|password|otp|secret|session|nonce|api[_-]?key|salt|reset[_-]?code|csrf|auth[_-]?code)"
    # 3) 보안 키워드가 같은 줄에 등장하는 ''.join(random.choice(...))
    - "(?i)(?:token|password|otp|secret|session|nonce|api[_-]?key|salt|reset[_-]?code|csrf|auth[_-]?code)[^\\n]{0,80}\\.join\\s*\\(\\s*[^)]*random\\.(?:choice|choices)\\s*\\("
    # 4) 고정 seed
    - "random\\.seed\\s*\\(\\s*(?:0|1|42|1234)\\s*\\)"
  category: kisa-secure-coding
  why_it_matters: >-
    파이썬 `random` 모듈(Mersenne Twister)은 *시뮬레이션·게임용*입니다.
    출력 624개만 관찰해도 내부 상태가 복원되어 다음 값을 예측할 수 있습니다.
    OTP·세션ID·비밀번호 리셋 토큰·API 키·CSRF 토큰을 `random`으로 만들면
    공격자가 다음 토큰을 *계산*해서 계정을 탈취합니다. `random.seed(42)`
    같이 고정 시드를 쓰면 즉시 결정적 — 더 위험합니다.
  public_sector_impact:
    - OTP·세션 토큰 예측으로 계정 탈취
    - 비밀번호 리셋 링크 추측
    - 행정 시스템 인증 우회
  safe_fix: |
    Python 3.6 이상: `secrets` 모듈 사용.
        import secrets
        token = secrets.token_urlsafe(32)
        otp   = ''.join(secrets.choice('0123456789') for _ in range(6))
    Python 3.5 이하: `os.urandom(32)` 또는 `random.SystemRandom()`.
    seed가 필요한 시뮬레이션 외에는 `random.seed()` 자체를 호출하지 마세요.
  references:
    - KISA Python 가이드 제2절 8
    - MOIS-49-SEC-08
    - CWE-330, CWE-338
    - https://docs.python.org/3/library/secrets.html
    - OWASP ASVS V6.3 Random Values
  can_auto_fix: false
examples:
  language: python
  positive:
    - "otp = str(random.randrange(100000, 999999))"
    - "session_key = ''.join(random.choice(string.ascii_letters) for _ in range(32))"
    - "random.seed(42)"
  negative:
    - "otp = str(secrets.randbelow(900000) + 100000)"
    - "session_key = ''.join(secrets.choice(string.ascii_letters) for _ in range(32))"
    - "roll = random.randint(1, 6)  # game dice"
---

## 무엇이 위험한가
`random.choice(string.ascii_letters)`로 만든 세션ID는 *암호학적으로 깨진* 토큰입니다. Mersenne Twister는 결정적 PRNG라서 충분한 출력만 관찰하면 다음 값을 *수학적으로* 예측할 수 있습니다. 공공기관 본인확인·간편로그인·OTP·비밀번호 재설정 토큰을 `random`으로 만드는 사례가 여전히 매우 흔합니다. AI 코딩 도우미는 `random.choice` 한 줄짜리 예제를 자주 제시하므로 별도 룰로 잡습니다.

## 안전한 패턴 (가이드 원문 인용)
```python
# 권장: secrets (Python 3.6+)
import secrets, string
session_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
otp        = ''.join(secrets.choice('0123456789') for _ in range(6))
token      = secrets.token_urlsafe(32)
reset_code = secrets.token_hex(16)

# 구버전: SystemRandom 또는 os.urandom
import os, random
sr = random.SystemRandom()
session_key = ''.join(sr.choice(string.ascii_letters) for _ in range(32))
raw_bytes   = os.urandom(32)
```

## False positive 주의
- 본 룰은 *보안 키워드*(`token`, `password`, `otp`, `secret`, `session`, `nonce`, `api_key`, `salt`, `reset_code`)가 같은 라인 또는 같은 함수 본문 안에 등장하는 경우에만 매칭합니다. 일반적인 게임용 `random.randint(1, 6)`이나 ML 데이터 셔플은 매칭되지 않습니다.
- `random.seed(0/1/42/1234/문자열)` 같은 *고정 시드* 호출도 잡습니다. 재현 실험용이라면 보안 로직과 격리한 후 `# gvskb: ignore KISA-PY-SEC-08`로 억제하세요.
- numpy/torch의 시드 고정은 ML 재현용으로 안전하므로 본 룰에서 제외했습니다.
