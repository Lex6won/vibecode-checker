import httpx
from fastapi import FastAPI

app = FastAPI()

@app.get("/fetch")
async def fetch(target: str):
    async with httpx.AsyncClient() as client:
        r = await client.get(target)
    return {"body": r.text}
