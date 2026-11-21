import requests

def call_api(payload):
    return requests.post("https://api.example.go.kr/v1/submit", json=payload, timeout=10)
