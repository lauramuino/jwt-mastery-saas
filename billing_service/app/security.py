import os
import jwt
import redis
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

ALGORITHM = os.getenv("JWT_ALGORITHM")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

with open("/keys/public.pem", "r") as f:
	PUBLIC_KEY = f.read()

security = HTTPBearer()


def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
	token = credentials.credentials
	try:
		payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
		if payload.get("sub") is None or payload.get("type") != "access":
			raise HTTPException(status_code=401, detail="Invalid access token")

		if redis_client.exists(f"backlist:{payload.get('jti', '')}") == 1:
			raise HTTPException(status_code=401, detail="Token has been revoked")

		return payload
	except jwt.ExpiredSignatureError:
		raise HTTPException(status_code=401, detail="Token has expired")
	except jwt.InvalidTokenError:
		raise HTTPException(status_code=401, detail="Invalid token signature")
