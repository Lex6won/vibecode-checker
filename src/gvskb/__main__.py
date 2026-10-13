"""`python -m gvskb …` — `gvskb` 실행 파일이 잠겨 있을 때(Windows 에서 자기 자신을 갱신할 때) 쓴다."""
from .cli import main

raise SystemExit(main())
