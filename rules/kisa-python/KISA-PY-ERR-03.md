---
id: KISA-PY-ERR-03
title_ko: Python 부적절한 예외 처리 - bare except / 광범위 except Exception 단독 캐치
title_en: Improper exception handling in Python (bare except / overly broad except Exception)
status: approved
source_layer: baseline
sources:
  - publisher: 한국인터넷진흥원
    document: Python 시큐어코딩 가이드(2023년 개정본)
    item: 제4절 3. 부적절한 예외 처리
  - publisher: 행정안전부
    document: 소프트웨어 개발보안 가이드
    item: SW-38
cwe: [CWE-396, CWE-397, CWE-755]
severity: medium
decision_default: warn
domains: [kisa-secure-coding]
languages: [python]
scenarios: [web-app, data-pipeline, batch-job, llm-integration]
related_baseline: [MOIS-49-ERR-03]
verified_at: 2026-06-03
review_due: 2026-12-03
detection:
  patterns:
    - "^\\s*except\\s*:\\s*(?:#.*)?$"
    - "^\\s*except\\s*\\(\\s*Exception\\s*\\)\\s*:\\s*(?:#.*)?$"
    - "^\\s*except\\s+BaseException\\b"
  category: kisa-secure-coding
  why_it_matters: >-
    `except:` 또는 `except (Exception):`처럼 *모든 예외를 한 바구니로* 잡으면
    KeyboardInterrupt·SystemExit까지 삼키고, 더 중요하게는 *예상하지 못한*
    오류(예: SQL 컬럼 불일치, JSON 스키마 위반)를 일반 비즈니스 오류와
    뒤섞어 처리합니다. KISA 가이드 안전 예시처럼 *발생 가능한 오류의 종류와
    순서에 맞춰 세분화*해야 합니다. 광범위 캐치는 LLM이 생성한 코드에서
    가장 흔히 보이는 안티패턴이며, 한 번 들어가면 *진짜 버그가 운영 환경에서
    조용히 살아남습니다*.
  public_sector_impact:
    - 시스템 종료 신호(KeyboardInterrupt) 마저 무시
    - 진짜 버그가 운영에서 발견되지 않음
    - 사고 후 재현·원인 분석 어려움
  safe_fix: |
    가이드 안전 예시처럼 *예외 유형별로 분기*하세요.
        try:
            f = open('myfile.txt')
            s = f.readline()
            i = int(s.strip())
        except FileNotFoundError:
            logger.warning("file_missing")
        except OSError:
            logger.error("cannot_open")
        except ValueError:
            logger.warning("not_an_integer")
    *반드시* 광범위 캐치가 필요한 최상위 핸들러(예: WSGI/ASGI 미들웨어)는
    `logger.exception(...)` + `raise` 또는 일반화된 오류 응답으로 마무리하세요.
  references:
    - KISA Python 가이드 제5절 3
    - MOIS-49-ERR-03
    - CWE-396, CWE-397
    - PEP 8 - Programming Recommendations (do not bare except)
  can_auto_fix: false
examples:
  language: python
  positive:
    - "try: parse(s)\nexcept:\n    print('Unexpected error')"
    - "except (Exception):"
    - "except BaseException as e: raise"
  negative:
    - "except FileNotFoundError:\n    logger.warning('missing')"
    - "except (OSError, ValueError) as e:\n    logger.warning('io_or_value_error', exc_info=e)"
    - "except Exception as e:\n    logger.exception('unhandled')\n    raise"
---

## 무엇이 위험한가
KISA 가이드 본문에는 다음과 같은 *안전하지 않은 예시*가 제시됩니다.

```python
try:
    f = open('myfile.txt')
    s = f.readline()
    i = int(s.strip())
except:                       # 모든 예외를 한 번에 — 위험
    print("Unexpected error")
```

이 한 줄로 *세 종류의 다른 오류*(파일 없음 / 읽기 실패 / 정수 변환 실패)가 동일하게 처리됩니다. 또한 `except:`는 `KeyboardInterrupt`·`SystemExit`도 잡아 *Ctrl-C로 종료조차 못하는* 좀비 프로세스를 만들 수 있습니다.

LLM 생성 코드에서 가장 흔한 패턴이며, 한 번 운영에 들어가면 *진짜 버그가 영영 발견되지 않습니다*.

## 안전한 패턴 (가이드 원문 인용)
```python
def get_content():
    try:
        f = open('myfile.txt')
        s = f.readline()
        i = int(s.strip())
    # 발생할 수 있는 오류의 종류와 순서에 맞춰서 예외 처리한다.
    except FileNotFoundError:
        print("file is not found")
    except OSError:
        print("cannot open file")
    except ValueError:
        print("Could not convert data to an integer.")
```

## False positive 주의
- 본 룰은 *세 가지 단일 라인 패턴*만 잡습니다:
  1. `except:` — bare except
  2. `except (Exception):` — 단독 광범위 캐치 (괄호 + as 없음)
  3. `except BaseException ...` — 시스템 신호까지 잡는 가장 위험한 캐치
- `except Exception as e:` (괄호 없음)는 *최상위 핸들러에서는 정당*하므로 본 룰이 매칭하지 않습니다. 하지만 그 핸들러 본문이 `pass`로 끝나면 [`KISA-PY-ERR-02`](./KISA-PY-ERR-02.md)가 잡습니다.
- 다중 예외 튜플(`except (OSError, ValueError):`)는 *세분화된 의도*이므로 매칭하지 않습니다.
- 의도가 분명한 최상위 미들웨어에서는 `# gvskb: ignore KISA-PY-ERR-03`로 억제하세요.
