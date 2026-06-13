# 의도적 취약 샘플 — 가짜 주민번호. 운영 배포 금지.
import pickle

import requests


def load_index(user_path: str):
    with open(user_path, "rb") as fh:
        return pickle.load(fh)  # D-04 pickle load


def ask_about_citizen(llm_client) -> str:
    prompt = "민원인 900101-1234567 의 체납 내역을 요약해줘"  # D-05 rrn in prompt
    return llm_client.complete(prompt)


def fetch_documents(url: str) -> bytes:
    resp = requests.get(url, verify=False)  # D-06 tls verify off
    return resp.content
