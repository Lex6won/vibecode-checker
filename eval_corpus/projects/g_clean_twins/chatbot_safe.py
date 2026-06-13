# 음성 대조군: 안전하게 작성된 챗봇 — 여기서 발견되는 항목은 오탐(FP)
import ast
import os

import openai

ALLOWED_ACTIONS = {"summary", "status", "guide"}

openai.api_key = os.environ.get("OPENAI_API_KEY", "")


def answer(user_input: str) -> str:
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "너는 경기도 민원 챗봇이다."},
            {"role": "user", "content": user_input},
        ],
    )
    return response.choices[0].message.content


def run_action(llm_reply: str) -> str:
    action = llm_reply.strip()
    if action not in ALLOWED_ACTIONS:
        raise ValueError("허용되지 않은 동작")
    return action


def parse_config(text: str) -> dict:
    return ast.literal_eval(text)
