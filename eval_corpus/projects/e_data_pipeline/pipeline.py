# 시나리오: AI 코딩 도구로 생성한 통계 파이프라인 (의도적 취약 샘플 — 가짜 PII. 운영 배포 금지)
import os

import pandas as pd


def load_remote_frame(url: str) -> pd.DataFrame:
    return pd.read_pickle(url)  # E-01 read_pickle untrusted


def export_citizens() -> None:
    df = pd.DataFrame(
        [
            {"name": "홍길동", "rrn": "900101-1234567", "phone": "010-2345-6789"},  # E-02 rrn+phone literal (2026-08-29: 1234-5678 은 룰의 예시 제외번호라 교체)
        ]
    )
    df.to_csv("citizens_export.csv", index=False)


def cleanup(fname: str) -> None:
    os.system("del " + fname)  # E-03 os.system concat
