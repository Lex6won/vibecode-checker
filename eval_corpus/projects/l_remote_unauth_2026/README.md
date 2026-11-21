# l_remote_unauth_2026 — 로그인 없이 원격에서 닿는 취약점 말뭉치

인증 없이 네트워크로 닿는 취약점 유형을 Python·JavaScript·TypeScript 로 쓴 채점표다. 합성 코드이며 페이로드와 실제 도메인은 없다.

- `py` · `js` · `ts` — 취약 표본. 파일 하나에 유형 하나(SSRF · 명령 삽입 · 인증 우회 · 무인증 관리 경로 · CORS · 업로드 등 80개).
- `n_py` · `n_js` · `n_ts` — 같은 기능을 안전하게 쓴 쌍둥이 51개. **발견이 하나도 없어야 한다.**
- `hops` — 같은 취약점을 「한 줄 직접 / 변수 경유 / 함수 경유」로 쓴 추적 깊이 대조 57개.
- 실행: `GVSKB_MODE=offline PYTHONPATH=src python scripts/run_holdout.py --corpus l_remote_unauth_2026`
  → `eval_corpus/results/l_remote_unauth_2026_results.md`

`kind: known_gap` 은 지금 못 잡는다고 확인된 항목이다. `rule` 에는 앞으로 그 자리를 잡아야 할 룰을 적었다(아직 없는 ID 포함).
잡히기 시작하면 드라이버가 실패로 알린다 — 정답표에서 `known_gap` 을 지우고 줄 번호를 적는다. 탐지를 늘리는 변경은
이 표의 공백을 줄이면서 쌍둥이 오탐 0을 지켜야 한다.
