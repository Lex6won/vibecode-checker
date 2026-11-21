import subprocess
from openai import OpenAI

client = OpenAI()

def run_task(user_request: str):
    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": user_request}])
    command = resp.choices[0].message.content
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
