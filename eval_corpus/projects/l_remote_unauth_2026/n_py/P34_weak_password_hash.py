from werkzeug.security import generate_password_hash

def hash_password(password: str) -> str:
    return generate_password_hash(password)
