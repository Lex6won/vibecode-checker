---
id: KISA-PY-ERR-02
title_ko: Python 오류상황 대응 부재 - except 블록을 pass/...로 비우는 패턴
title_en: "Empty exception handler in Python (except: pass / ellipsis swallowing)"
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제5절 2. 오류상황 대응 부재
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-37
cwe: [CWE-390, CWE-391, CWE-755]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline, batch-job]
related_baseline: [MOIS-49-ERR-02]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "^\\s*except\\b[^:]*:\\s*pass\\s*(?:#.*)?$"
    - "^\\s*except\\b[^:]*:\\s*\\.\\.\\.\\s*(?:#.*)?$"
    - "^\\s*except\\b[^:]*:\\s*continue\\s*(?:#.*)?$"
  category: kisa-secure-coding
  why_it_matters: >-
    `except IndexError: pass`, `except Exception: ...` 같이 예외를 잡아두고
    아무 처리를 하지 않으면 프로그램이 "오류가 없었던 것처럼" 계속 진행됩니다.
    KISA 가이드 본문 예제처럼 *암호화 키 선택 실패 시 pass*하면 기본 평문
    상수 키로 암호화가 이어지는 등 보안 결정이 조용히 부패합니다. 공공기관
    배치/결재 시스템에서 이러한 "조용한 실패"는 *원인 추적이 가장 어려운*
    장애 유형이며 사고 후 책임 소재 규명도 어렵습니다.
  public_sector_impact:
    - 보안 결정 조용한 실패 (암호화 우회 등)
    - 사고 추적 불가
    - 데이터 무결성 위반이 로그에 남지 않음
  safe_fix: |
    예외를 잡으면 *반드시* 로깅 또는 대체 동작을 수행하세요.
        try:
            static_key = static_keys[key_id]
        except IndexError:
            logger.warning("encryption.key_not_found", extra={"key_id": key_id})
            # 평문 키 대신 즉시 안전한 난수 키로 대체
            static_key = {
                "key": secrets.token_bytes(16),
                "iv":  secrets.token_bytes(16),
            }
            static_keys.append(static_key)
    의도적으로 무시해야 한다면 *명시적인 의도*를 주석에 남기세요.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            # 이미 삭제됨 - 의도적으로 무시
            pass
  references:
    - KISA Python 가이드 제5절 2
    - MOIS-49-ERR-02
    - CWE-390, CWE-391, CWE-755
    - https://docs.python.org/3/tutorial/errors.html
  can_auto_fix: false
examples:
  language: python
  positive:
    - "try: static_key = static_keys[key_id]\nexcept IndexError: pass"
    - "except Exception: ..."
    - "except StopIteration: continue"
  negative:
    - "except IndexError:\n    logger.warning('key_not_found')\n    static_key = secrets.token_bytes(16)"
    - "except FileNotFoundError:\n    return True  # already removed"
    - "except Exception as e:\n    logger.exception('save_failed')\n    raise"
---

## 무엇이 위험한가
`except: pass`는 *모든 종류의 사고를 침묵시키는* 패턴입니다. KISA 가이드 본문 예제는 `static_keys[key_id]`가 IndexError를 던졌을 때 `pass`로 넘어가 *상수 0 키*로 AES 암호화를 계속 진행하는 사례를 보여줍니다. 사용자는 "암호화 됐다"고 믿지만 실제로는 보안 결정이 조용히 우회된 상태입니다.

배치·결재·발급 같은 공공기관 트랜잭션에서 이 패턴이 들어가면, 문제가 *몇 달 뒤 외부 감사에서 발견*되며 그 사이 처리된 모든 데이터의 신뢰성이 흔들립니다. 무엇보다 *로그에 흔적이 남지 않아* 사고 후 인과 규명이 불가능합니다.

## 안전한 패턴 (가이드 원문 인용)
```python
import secrets, logging
logger = logging.getLogger(__name__)

try:
    static_key = static_keys[key_id]
except IndexError:
    # 가이드 안전 예시: 기본 상수 키가 아니라 즉시 안전한 난수 키로 대체
    logger.warning("encryption.key_not_found", extra={"key_id": key_id})
    static_key = {
        "key": secrets.token_bytes(16),
        "iv":  secrets.token_bytes(16),
    }
    static_keys.append(static_key)
```

## False positive 주의
- *의도적인 무시*(예: `FileNotFoundError`를 `pass`로 처리)는 패턴 상으로는 매칭됩니다. 의도가 분명할 때는 같은 줄 또는 다음 줄에 `# gvskb: ignore KISA-PY-ERR-02`로 억제하세요.
- 본 룰은 `except X: pass`/`except X: ...`/`except X: continue` 세 가지 *비어있는 단일 라인 핸들러*만 잡습니다. `except X: log_it(e)` 같은 비어있지 않은 핸들러는 매칭되지 않습니다.
- 멀티라인 빈 핸들러(`except X:`<br>`    pass` 형태)는 같은 라인이 아니므로 본 라인 단위 정규식은 잡지 않습니다 — `except X: pass`처럼 한 줄로 쓴 경우만 검출합니다. AST 어댑터에서 보강할 수 있습니다.
