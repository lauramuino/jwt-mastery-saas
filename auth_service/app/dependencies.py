import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .security import decode_access_token
from .redis_client import is_token_blacklisted


security = HTTPBearer()


def get_current_user_payload(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        if payload.get("sub") is None or payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid access token")

        if is_token_blacklisted(payload.get("jti", "")):
        	raise HTTPException(status_code=401, detail="Token has been revoked")

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(allowed_roles: list[str]):
	def role_checker(payload: dict = Depends(get_current_user_payload)) -> dict:
		user_role = payload.get("role")
		if user_role not in allowed_roles:
			raise HTTPException(
				status_code=403,
				detail=f"Access forbidden. Requires one of {allowed_roles}"
			)
		return payload
	return role_checker