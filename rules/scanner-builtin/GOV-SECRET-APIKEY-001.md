---
id: GOV-SECRET-APIKEY-001
title_ko: API 키 또는 비밀번호로 보이는 값이 코드에 포함되어 있습니다
title_en: Secret or API key detected
status: approved
source_layer: baseline
sources:
  - publisher: NIST
    document: SP 800-218 SSDF
  - publisher: OWASP
    document: ASVS 5.0
    item: V6 Authentication and Session Management
severity: critical
decision_default: block
domains: [secret-scanning]
languages: [python, javascript, java, yaml, toml]
scenarios: [llm-integration, web-app, data-pipeline, agent]
related_baseline: [OWASP-LLM-2025-02]
verified_at: 2026-05-31
review_due: 2026-11-30
detection:
  patterns:
    # 이름 뒤에 한 마디가 더 붙는 형태(SECRET_KEY, JWT_SECRET_KEY)도 받는다.
    # 예전 패턴은 키워드 바로 뒤에 `[:=]` 를 요구해 Django 의 SECRET_KEY —
    # 파이썬 웹앱에서 가장 흔히 하드코딩되는 시크릿 — 를 통째로 놓쳤다.
    #
    # 뒷마디는 **아무 단어나 받지 않는다.** 처음엔 `[_-][A-Za-z]+` 로 열었다가
    # `token_endpoint`(URL) · `secret_name`(이름) · `password_hint`(안내문) ·
    # `api_key_header`(헤더명) 가 전부 걸렸다 — 시크릿을 *가리키는* 이름이지
    # 시크릿을 *담은* 이름이 아니다. 이름 전체가 여전히 "비밀값"을 뜻하는
    # 단어만 허용한다.
    #
    # 값이 명백한 플레이스홀더(YOUR_KEY_HERE, XXXX…, <your-token>, CHANGEME, 예시 등)면
    # 실제 시크릿이 아니므로 부정 전방탐색으로 제외한다. 실제 키 값에는 이 토큰들이
    # 사실상 나타나지 않으므로 미탐 위험은 무시할 수 있다.
    #
    # `${VAR}` · `{{ var }}` · `%VAR%` 도 같은 부류다 — 오히려 **비밀값을 코드에
    # 두지 않았다는 증거**인데, 실측에서 `DB_PASSWORD = "${DB_PASSWORD}"` 가
    # '치명·차단'으로 잡혀 모범 사례를 막고 있었다. `%VAR%` 는 **대문자만**
    # 받는다: 소문자까지 열면 `pa%ss%word` 같은 실제 비밀번호가 미탐이 된다.
    # 이때 `(?-i:...)` 로 대소문자 구분을 되살려야 한다 — 패턴 앞의 `(?i)` 가
    # 전역이라 그냥 `[A-Z_]` 로 쓰면 소문자까지 먹어 실제로 미탐이 났다(실측).
    # 맨몸 `$VAR` 는 제외하지 않는다 — 실제 비밀번호에 흔한 문자라 미탐 위험이 크다.
    #
    # 두 번째 전방탐색은 *테스트 픽스처*를 제외한다. test-only-key·join_new 처럼
    # 구분자로 끊긴 자리에 test/dummy/fake/mock/sample 등이 오는 값은 가짜다.
    # 구분자를 요구하므로 latest·contest 같은 단어에는 걸리지 않는다.
    - '(?i)(api[_-]?key|secret|password|passwd|token)(?:[_-](?:key|token|secret|password|passwd|pwd|pass))?\s*[:=]\s*["''](?![^"'']*(?:YOUR[_-]|[_-]HERE|X{6,}|CHANGE[_-]?ME|PLACEHOLDER|<[A-Za-z]|\*\*\*|\$\{|\{\{|(?-i:%[A-Z_][A-Z0-9_]*%)|예시|여기))(?!(?:[^"'']*[_\-.])?(?:test|dummy|fake|mock|sample|example|fixture|stub|foo|bar|old|new)(?:[_\-.]|["'']))[^"'']{8,}["'']'
    # 따옴표 **없는** 설정 파일 대입 — `.env`·`.properties`·`.ini`·YAML.
    #
    # 실측(2026-08-08): 위 패턴을 포함해 비밀번호 룰 전부가 값에 따옴표를
    # 요구했다. 그런데 설정 파일은 **따옴표 없이 쓰는 것이 표준**이라
    # `spring.datasource.password=gg2026Secure` 나 `DB_PASSWORD=gg2026Secure`
    # 가 통째로 미탐이었다 — 공공 Java/Spring 프로젝트에서 비밀번호가 가장 흔히
    # 노출되는 자리다.
    #
    # 산문·주석까지 먹지 않도록 **한 줄 전체 모양**을 요구한다: 줄 시작 · 값에
    # 공백/따옴표 없음 · 줄 끝(또는 뒤따르는 `#`·`;` 주석)까지. 이 모양은 코드에서는
    # 문법 오류라 사실상 설정 파일에서만 나온다. `password 정책은 8자 이상입니다`
    # 같은 안내문은 값에 공백이 있어 걸리지 않는다.
    #
    # 값 **전체**가 변수 참조(`${VAR}`·`$VAR`·`%VAR%`·`{{ var }}`)면 제외한다 —
    # 비밀을 코드에 두지 않았다는 증거다. 위 따옴표 패턴이 맨몸 `$VAR` 를 제외하지
    # 않는 것과 다른데, 이유가 있다: 저쪽은 값 **안에** `$` 가 섞인 실제 비밀번호를
    # 놓치지 않으려는 것이고, 여기서는 값이 **오직** 변수 참조뿐인 경우만 뺀다.
    #
    # **코드와 설정을 가르는 것이 이 패턴의 전부다.** 1차 시안은 값의 모양만 보다가
    # `password = getpass.getpass()` 를 차단했다 — 비밀번호를 *올바르게 읽는* 코드다.
    # 모범 사례를 막는 것은 오탐 중에서도 최악이라, 값의 '비밀스러움'을 추측하지 않고
    # **키와 구분자의 모양**으로 가른다. 넷 중 하나여야 한다:
    #   ⓐ `:` 구분자      — YAML/properties. 파이썬 대입문이 아니다
    #   ⓑ 점 있는 키       — `spring.datasource.password`
    #   ⓒ 대문자 키        — `DB_PASSWORD` (.env 관행)
    #   ⓓ 공백 없는 `=`    — `api_key=값` (PEP8 문장은 `=` 양옆에 공백을 넣는다)
    # 값에 괄호가 있으면(=호출) 무조건 뺀다.
    #
    # 남는 미탐: 소문자 키 + 공백 있는 `=` 형태의 설정(`password = 값`)은 코드와
    # 구분되지 않아 잡지 않는다. 놓치는 쪽을 택한 이유는, 여기서 잡으려다 위의
    # `getpass()` 같은 **정상 코드를 막으면 도구가 통째로 꺼지기** 때문이다.
    # 실측 보정(2026-08-08): `google_api_key=GEMINI_API_KEY,` 가 걸렸다 —
    # 파이썬 **키워드 인자**이고 값은 상수 참조다. 두 가지를 더 막는다:
    #   · 값에 쉼표 금지 → 함수 인자는 `,` 로 끝나 줄 끝 앵커에서 탈락한다
    #   · 값이 대문자 상수 이름 하나뿐이면 제외 → `GEMINI_API_KEY` 는 참조다
    # 실제 비밀번호가 전부 대문자·숫자·밑줄로만 이뤄질 수 있지만, 그 미탐보다
    # **정상 코드를 차단하는 쪽이 훨씬 비싸다**(도구를 끄게 만든다).
    - '(?i)^[ \t]*(?:(?:[\w.\-]*[._-])?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|token)[ \t]*:[ \t]*|[\w\-]+(?:\.[\w\-]+)*\.(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|token)[ \t]*=[ \t]*|(?-i:[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|API_?KEY|ACCESS_?KEY|TOKEN)|(?:PASSWORD|PASSWD|PWD|SECRET|API_?KEY|ACCESS_?KEY|TOKEN))[ \t]*=[ \t]*|(?:[\w.\-]*[._-])?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|token)=)(?!(?:\$\{[^}]+\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{\{[^}]+\}\})[ \t]*(?:[#;].*)?$)(?![^\s#;]*(?:YOUR[_-]|[_-]HERE|X{6,}|CHANGE[_-]?ME|PLACEHOLDER|<[A-Za-z]|\*\*\*|예시|여기))(?![^\s#;]*[(),])(?!(?-i:[A-Z][A-Z0-9_]*)[ \t]*(?:[#;].*)?$)[^\s\"'',#;]{6,}[ \t]*(?:[#;].*)?$'
    - 'sk-[A-Za-z0-9_-]{20,}'
    # sk_<벤더>_<본문> 형태 — Stripe(sk_live_·sk_test_), 기관 발급 키 등.
    # `sk_` 만으로는 잡지 않는다: 하이픈과 달리 언더스코어는 식별자에 흔해
    # sk_some_long_variable_name 같은 정상 코드가 오탐이 된다. 그래서
    #   ① 벤더 구절(sk_xxx_)을 요구하고
    #   ② 본문에 숫자나 대문자가 최소 1개 있을 것을 요구한다(전부 소문자면
    #      키가 아니라 식별자일 가능성이 높다. 32자 난수 키가 숫자·대문자를
    #      하나도 안 가질 확률은 무시할 수준).
    - 'sk_[A-Za-z0-9]{2,}_(?=[A-Za-z0-9]*[0-9A-Z])[A-Za-z0-9]{16,}'
    - 'AKIA[0-9A-Z]{16}'
    # ── 벤더 접두사 토큰 ──
    # 접두사가 곧 신원이라 **오탐이 구조적으로 거의 없다**. 값 이름을 보지
    # 않으므로 `headers: {Authorization: "Bearer ghp_..."}` 처럼 변수명 없이
    # 문자열로만 박힌 자리도 잡는다 — 실측(2026-08-08)에서 GitHub 토큰이
    # 통째로 미탐이었고, 이는 실제 유출 사고 유형 1위다.
    # 자릿수를 함께 요구해 `ghp_something` 같은 평범한 식별자와 가른다.
    - 'gh[pousr]_[A-Za-z0-9]{36,}'
    - 'github_pat_[A-Za-z0-9_]{60,}'
    - 'glpat-[A-Za-z0-9_\-]{20,}'
    - 'xox[baprs]-[A-Za-z0-9-]{10,}'
    - 'npm_[A-Za-z0-9]{36}'
    - 'dop_v1_[a-f0-9]{64}'
    - 'SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}'
    # PEM 개인키 블록 — 파일 확장자와 무관하게 소스 안에 붙여 넣은 경우
    - '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'
  category: secret-scanning
  why_it_matters: 키가 저장소나 LLM 프롬프트에 노출되면 행정시스템, 클라우드, 외부 API가 탈취될 수 있습니다.
  public_sector_impact:
    - 계정 탈취
    - 비용 발생
    - 내부 시스템 침해
  safe_fix: 키는 환경변수, 기관 secret manager, 배포 시스템의 안전한 비밀 저장소로 옮기세요.
  references:
    - NIST SSDF
    - OWASP ASVS V6
  can_auto_fix: false
examples:
  language: python
  positive:
    - 'OPENAI_API_KEY = "sk-proj-aaabbbcccdddeeefffggghhhiiijjj"'
    - 'password = "supersecretvalue123"'
    - 'token = "AKIAABCDEFGHIJKLMNOP"'
    # 변수명 없이 값만 인자로 넘기는 형태 — 변수명 기반 패턴이 놓치는 자리
    - 'client = RegistryClient(base_url, "sk_ggtrust_Ab3xK9mQ2pR7sT1uV5wY8zC4dE6fG0hJ")'
    # 실제 벤더 접두사(sk_live_·sk_test_ 등)는 예시에도 쓰지 않는다 — GitHub
    # 푸시 보호가 이 파일을 실제 유출로 판단해 푸시를 거부한다(실측). 형태만
    # 같으면 패턴 검증에는 충분하다.
    - 'client = VendorSDK(api_key="sk_vendor_Ab3xK9mQ2pR7sT1uV5wY8zC4")'
    # 이름 뒤에 한 마디 더 — Django 의 SECRET_KEY 가 대표 사례(예전엔 미탐)
    - 'SECRET_KEY = "d9f2ka83jdkq0zmx84hsly26rbtv51cn"'
    - 'JWT_SECRET_KEY = "Ab3xK9mQ2pR7sT1uV5wY8zC4dE6f"'
    # 'latest' 는 test 를 품지만 구분자로 끊기지 않으므로 제외되지 않는다 —
    # 테스트 픽스처 제외가 평범한 단어를 삼키지 않는지 고정하는 예시
    - 'password = "latestbuild9x2"'
    # % 를 대문자로 한정했으므로 소문자 사이의 % 는 여전히 실제 비밀번호로 본다
    - 'password = "pa%ss%word12"'
    - 'password = "P4ss$WORD123x"'
  negative:
    - "pi = 3.14"
    - 'greeting = "hello world"'
    - "api_key = 'YOUR_KEY_HERE'"
    - 'api_key = "<your-api-key>"'
    - 'password = "XXXXXXXXXXXX"'
    # 언더스코어 식별자는 키가 아니다 — 벤더 구절이 있어도 본문이 전부 소문자면 제외
    - "sk_model_pipeline_transformer = build()"
    # 테스트 픽스처 — 실측 오탐(wiggle_web tests/). 값이 가짜임이 이름에 드러난다
    - 'apiKey = "test-only-key"'
    - 'joinToken = "join_new"'
    - 'password = "dummy_password_1"'
    # 시크릿을 *가리키는* 이름은 시크릿이 아니다 — 뒷마디를 아무 단어나 받았을 때
    # 실제로 걸렸던 네 가지. 이름 전체가 "비밀값"을 뜻해야 한다.
    - 'token_endpoint = "https://auth.acme.invalid/oauth/token"'
    - 'secret_name = "prod-db-credential"'
    - 'password_hint = "생일 8자리를 입력하세요"'
    - 'api_key_header = "X-Api-Key-Value"'
    # 환경변수·템플릿 주입 표기 — 실측 오탐. 비밀값이 코드에 '없다'는 증거다
    - 'DB_PASSWORD = "${DB_PASSWORD}"'
    - 'api_key = "${CIVIL_AI_API_KEY}"'
    - 'VAULT_SECRET = "{{ vault_secret }}"'
    - 'DEPLOY_TOKEN = "%DEPLOY_TOKEN%"'
---

## 무엇이 위험한가
하드코딩된 API 키·비밀번호·토큰은 Git history에 영구 보존되며, LLM 프롬프트로 흘러가면 외부 서비스 로그에도 남습니다. 한 번 노출된 자격증명은 *즉시 폐기·재발급*이 원칙입니다.

## 안전한 패턴
```python
import os
api_key = os.environ["OPENAI_API_KEY"]  # 환경변수
# 또는 secret manager (AWS Secrets Manager / Azure Key Vault / 기관 내부 vault)
```
