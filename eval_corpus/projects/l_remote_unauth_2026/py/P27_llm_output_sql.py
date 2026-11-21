import sqlite3
from openai import OpenAI

client = OpenAI()

def ask_db(question: str):
    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": question}])
    sql = resp.choices[0].message.content
    return sqlite3.connect("app.db").execute(sql).fetchall()
