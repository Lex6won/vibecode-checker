from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["https://portal.example.go.kr"], allow_credentials=True, allow_methods=["GET", "POST"])
