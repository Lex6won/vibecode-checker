# 음성 대조군: 안전하게 작성된 파이프라인 — 여기서 발견되는 항목은 오탐(FP)
import json
import subprocess

import pandas as pd


def load_frame(path: str) -> pd.DataFrame:
    with open(path, encoding="utf-8") as fh:
        return pd.DataFrame(json.load(fh))


def export_citizens() -> None:
    df = pd.DataFrame([{"name": "홍길동", "rrn": "900101-1******", "phone": "010-****-5678"}])
    df.to_csv("citizens_export.csv", index=False)


def cleanup(fname: str) -> None:
    subprocess.run(["cmd", "/c", "del", fname], check=False)
