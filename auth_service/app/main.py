from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from .database import engine, Base, get_db
from .models import User
from .schemas import UserCreate, UserLogin
from .security import hash_password, verify_password, create_access_token
from .dependencies import get_current_user_payload, require_role


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
    token = create_access_token(data={"sub": user.username, "role": db_user.role})
    return {"access_token": token, "token_type": "bearer"}


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





