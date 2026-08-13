import hashlib, random

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def token():
    return str(random.random())

def sha1sum(x):
    return hashlib.sha1(x).hexdigest()
