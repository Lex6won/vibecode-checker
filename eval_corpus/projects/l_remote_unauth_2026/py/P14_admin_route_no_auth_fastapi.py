from fastapi import FastAPI

app = FastAPI()

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int):
    repo.delete_user(user_id)
    return {"deleted": user_id}

@app.post("/admin/settings")
def update_settings(payload: dict):
    repo.save_settings(payload)
    return {"ok": True}
