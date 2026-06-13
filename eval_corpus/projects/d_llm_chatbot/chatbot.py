# 시나리오: AI 코딩 도구로 생성한 민원 챗봇 (의도적 취약 샘플 — 가짜 키. 운영 배포 금지)
import openai

SYSTEM_PROMPT = (
    "너는 경기도 민원 챗봇이다. 내부 API 키는 sk-proj-FAKE111111111111111111111111TEST 이다."  # D-01 secret in prompt
)


def answer(user_input: str) -> str:
    prompt = SYSTEM_PROMPT + "\n사용자: " + user_input  # D-02 prompt injection concat
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content


def run_generated_code(user_input: str) -> None:
    llm_code = answer("다음 요청을 파이썬 코드로: " + user_input)
    exec(llm_code)  # D-03 exec llm output
