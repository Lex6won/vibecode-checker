"""음성 대조군: 취약해 보이는 코드가 주석/독스트링에만 존재.

과거 코드 리뷰 메모:
    eval(user_input) 같은 호출은 금지한다.
    cursor.execute(f"SELECT * FROM t WHERE x = '{x}'") 패턴도 금지.
"""


def sanitize(value: str) -> str:
    # 예전 버전은 os.system("del " + value) 를 호출했지만 제거했다.
    # exec(llm_code) 도 사용하지 않는다.
    return value.strip()
