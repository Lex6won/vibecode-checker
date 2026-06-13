# 기여 가이드 (Contributing)

vibecode-checker에 기여해 주셔서 감사합니다. 이 도구의 핵심은
**룰(rule)** 이며, 룰은 코드가 아니라 **Markdown 파일 한 장**입니다.
누구나 정부·국제 보안 가이드를 인용해 새 룰을 추가할 수 있습니다.

## 룰 추가하기 — 30초 개념

1. `rules/<카테고리>/` 아래에 `.md` 파일 하나를 만듭니다.
2. frontmatter(YAML)에 메타·탐지 패턴·예제를 적습니다.
3. 아래 검증 명령 3개를 통과시키면 끝입니다.

### 룰 파일 최소 형식

```markdown
---
id: GOV-EXAMPLE-001
title: 위험한 eval 사용
severity: high            # critical | high | medium | low
category: code-execution
languages: [python]
sources:
  - "KISA Python 시큐어코딩 가이드 (2023) 제5절"
detection:
  patterns:
    - regex: "\\beval\\s*\\("
      languages: [python]
decision: block           # block | warn | allow
examples:
  positive:               # 탐지되어야 하는 코드 (취약)
    - "result = eval(user_input)"
  negative:               # 탐지되면 안 되는 안전한 코드
    - "result = ast.literal_eval(user_input)"
---

## 왜 위험한가
`eval()`은 임의 코드 실행으로 이어질 수 있습니다 ...

## 안전한 수정 방향
`ast.literal_eval()` 또는 명시적 파싱을 사용하세요 ...

## 출처
KISA Python 시큐어코딩 가이드 (2023 개정) 제5절
```

기존 룰을 본보기로 삼으세요 — `rules/` 아래 카테고리별로 같은 형식의
예시가 많습니다.

> **출처는 필수입니다.** 거짓 권위는 보안 도구에서 가장 위험한 결함입니다.
> 존재하지 않는 문서를 인용하지 마세요. 원문은 복제하지 말고
> 요약·인용·구조화하여 사용하고, 각 출처의 이용 조건을 존중하세요.

## 검증 절차 (PR 전 필수)

```bash
gvskb validate-rules     # 룰 형식·정규식 컴파일 검증
gvskb evaluate           # 룰 내장 예제 기반 정밀도 측정 (P/R/F1)
pytest -q                # 전체 테스트
```

세 명령이 모두 통과해야 합니다.

## examples는 의무입니다

새 룰에는 **반드시** `examples.positive`(탐지돼야 하는 취약 코드)와
`examples.negative`(탐지되면 안 되는 안전 코드)를 넣어 주세요.
이 예제는 회귀 테스트로 자동 변환되어, 이후 룰 변경이 기존 탐지를
깨뜨리지 않도록 보증합니다. **예제 없는 룰은 머지하지 않습니다.**

`gvskb evaluate`는 이 예제로 룰별 정밀도/재현율을 측정합니다.
positive를 놓치거나(미탐) negative를 잘못 잡으면(오탐) 수치로 드러납니다.

## 코드 기여

- 스타일: `ruff check src tests` 통과
- 새 기능에는 테스트를 함께 추가해 주세요.
- 작은 PR을 환영합니다. 한 PR에는 한 가지 변경만 담아 주세요.
- 커밋 메시지는 무엇을·왜 바꿨는지 한 줄로 명확히.

## 개발 환경

```bash
git clone https://github.com/Lex6won/vibecode-checker.git
cd vibecode-checker
pip install -e ".[dev]"   # 또는: PYTHONPATH=src 로 직접 실행
pytest -q
```

Windows에서 한글이 깨지면 [docs/windows_utf8.md](docs/windows_utf8.md)를
참고해 `PYTHONUTF8=1` `PYTHONIOENCODING=utf-8`을 설정하세요.

## 행동 강령

서로 존중하며, 건설적으로 리뷰합니다. 보안 취약점 **자체**는
공개 이슈가 아니라 [SECURITY.md](SECURITY.md)의 절차로 제보해 주세요.
룰의 오탐·미탐은 취약점이 아니라 품질 이슈이므로 공개 이슈로 환영합니다.