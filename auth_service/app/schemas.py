from pydantic import BaseModel

class UserCreate(BaseModel):
	username: str
	password: str
	role: str = "free"

class UserLogin(BaseModel):
	username: str
	password: str

class TokenRefreshRequest(BaseModel):
	refresh_token: str