import redis
from .config import REDIS_URL

redis_client = redis.from_url(REDIS_URL, decode_responses=True)


def blacklist_token(jti: str, expires_in_seconds: int):
	# storing the jti in redis with automatic TTL
	if expires_in_seconds > 0:
		redis_client.setex(f"blacklist:{jti}", expires_in_seconds, "revoked")


def is_token_blacklisted(jti: str) -> bool:
	return redis_client.exists(f"blacklist:{jti}") == 1