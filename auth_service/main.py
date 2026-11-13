import os
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel

app = FastAPI(title="Phase 1: Basic JWT Auth")

# Load secrets from environment
SECRET_KEY = os.getenv("JWT_SECRET", "fallback_secret")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# Security helpers
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Temporary in-memory database
fake_users_db = {}

class UserAuth(BaseModel):
    username: str
    password: str

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register", status_code=201)
def register(user: UserAuth):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    fake_users_db[user.username] = pwd_context.hash(user.password)
    return {"message": f"User '{user.username}' created successfully"}

@app.post("/login")
def login(user: UserAuth):
    hashed_pw = fake_users_db.get(user.username)
    if not hashed_pw or not pwd_context.verify(user.password, hashed_pw):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # 'sub' (Subject) is the standard JWT claim for user identity
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/profile")
def read_profile(current_user: str = Depends(get_current_user)):
    return {
        "username": current_user,
        "message": "Welcome! You accessed a protected route using a valid JWT."
    }
