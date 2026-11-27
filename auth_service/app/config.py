import os

ALGORITHM = os.getenv("JWT_ALGORITHM")
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

with open("/keys/private.pem", "r") as f:
	PRIVATE_KEY = f.read()

with open("/keys/public.pem", "r") as f:
	PUBLIC_KEY = f.read()