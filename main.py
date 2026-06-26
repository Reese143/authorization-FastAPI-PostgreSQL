import bcrypt
import os
import uvicorn
from authx import AuthX, AuthXConfig
from fastapi import FastAPI, HTTPException, Response, Depends
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine, String, Integer, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from starlette.responses import RedirectResponse

main = FastAPI()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:batonSQL@localhost:5432/crm_db"
)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql://",
        1
    )

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass

class UserDB(Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="manager", nullable=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

config = AuthXConfig()
config.JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
config.JWT_ACCESS_COOKIE_NAME = "ACCESS_TOKEN"
config.JWT_TOKEN_LOCATION = ["cookies"]

security = AuthX(config=config)

class UserLoginSchema(BaseModel):
    username: str
    password: str

class UserResponseSchema(BaseModel):
    id: int
    username: str
    role: str

    class Config:
        from_attributes = True

def get_current_user(
        payload=Depends(security.access_token_required),
        db: Session = Depends(get_db)
) -> type[UserDB]:
    user_id = payload.sub
    user = db.get(UserDB, int(user_id))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@main.get("/")
async def redirect_to_docs():
    return RedirectResponse(url="/docs")


@main.post('/setup_database')
def setup_database():
    Base.metadata.create_all(bind=engine)
    return {'message': 'database setup successfully'}

@main.post('/register', response_model=UserResponseSchema)
def register(creds: UserLoginSchema, db: Session = Depends(get_db)):
    existing_user = db.execute(select(UserDB).where(UserDB.username == creds.username)).scalar_one_or_none()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    new_user = UserDB(
        username=creds.username,
        hashed_password=hash_password(creds.password),
        role="manager"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@main.post('/login')
def login(creds: UserLoginSchema, response: Response, db: Session = Depends(get_db)):
    user = db.execute(select(UserDB).where(UserDB.username == creds.username)).scalar_one_or_none()

    if not user or not verify_password(creds.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token = security.create_access_token(uid=str(user.id))

    response.set_cookie(
        key=config.JWT_ACCESS_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax"
    )
    return {"access_token": token, "token_type": "bearer"}

@main.get('/protected', response_model=UserResponseSchema)
def protected(current_user: UserDB = Depends(get_current_user)):
    return current_user


if __name__ == "__main__":
    uvicorn.run("main:main", reload=True)
