import os

DEBUG = False
ALLOWED_HOSTS = ["portal.example.go.kr"]
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
SESSION_COOKIE_SECURE = True
