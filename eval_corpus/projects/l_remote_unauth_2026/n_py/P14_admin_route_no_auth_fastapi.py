from fastapi import Depends, FastAPI

app = FastAPI()

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, admin=Depends(require_admin)):
    repo.delete_user(user_id)
    return {"deleted": user_id}
