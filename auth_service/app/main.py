from datetime import datetime, timezone
import jwt
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from .database import engine, Base, get_db
from .models import User
from .schemas import UserCreate, UserLogin, TokenRefreshRequest
from .security import hash_password, verify_password, create_access_token, create_refresh_token, decode_access_token
from .dependencies import get_current_user_payload, require_role
from .redis_client import is_token_blacklisted, blacklist_token


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Phase 2: Modular JWT Auth")


@app.post("/register", status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if user.role not in ["free", "premium", "admin"]:
        raise HTTPException(status_code=400, detail="Role must be free, premium or admin")
    
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")


    new_user = User(
        username=user.username,
        hashed_password=hash_password(user.password),
        role=user.role
    )
    db.add(new_user)
    db.commit()

    return {"message": f"User '{user.username}' created with role '{user.role}'"}


@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # 'sub' (Subject) is the standard JWT claim for user identity
    token_data = {"sub": user.username, "role": db_user.role}
    return {
        "access_token": create_access_token(token_data),
        "refresh_token": create_refresh_token(token_data),
        "token_type": "bearer"
    }


@app.post("/refresh")
def refresh(request: TokenRefreshRequest):
    try:
        payload = decode_access_token(request.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type. Refresh token required")

        jti = payload.get("jti", "")
        if is_token_blacklisted(jti):
            raise HTTPException(status_code=401, detail="Refresh token has been revoked")

        new_access_token = create_access_token(
            data={"sub": payload["sub"], "role": payload["role"]}
        )
        return {"access_token": new_access_token, "token_type": "bearer"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired. Please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@app.post("/logout")
def logout(request: TokenRefreshRequest, access_payload: dict = Depends(get_current_user_payload)):
    now = int(datetime.now(timezone.utc).timestamp())

    access_ttl = access_payload["exp"] - now
    blacklist_token(access_payload["jti"], access_ttl)

    try:
        refresh_payload = decode_token(request.refresh_token)
        if refresh_payload.get("type") == "refresh":
            refresh_ttl = refresh_payload["exp"] - now
            blacklist_token(refresh_payload["jti"], refresh_ttl)
    except jwt.InvalidTokenError:
        pass
    return {"message": "Successfully logged out. Both tokens revoked."}


@app.get("/free-content")
def get_free_content(payload: dict = Depends(get_current_user_payload)):
    return {
        "message": f"Hello {payload['sub']}. All log in users can view this."
    }


@app.get("/premium-content")
def get_premium_content(payload: dict = Depends(require_role(["premium", "admin"]))):
    return {
        "message": f"Welcome VIP {payload['sub']}. Your role is '{payload['role']}'."
    }


@app.delete("/admin")
def admin_action(payload: dict = Depends(require_role(["admin"]))):
    return {
        "message": f"Admin {payload['sub']} executed a restricted action."
    }
