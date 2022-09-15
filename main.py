from datetime import datetime, timedelta
from typing import Optional

import databases
import enum

import jwt
import sqlalchemy
from pydantic import BaseModel, validator
from fastapi import FastAPI, HTTPException, dependencies, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from decouple import config
from email_validator import validate_email as validate_e, EmailNotValidError
from passlib.context import CryptContext
from starlette.requests import Request

DATABASE_URL = f"postgresql://{config('DB_USER')}:{config('DB_PASSWORD')}@localhost:5432/clothes"

database = databases.Database(DATABASE_URL)

metadata = sqlalchemy.MetaData()


class UserRole(enum.Enum):
    super_admin = "super admin"
    admin = "admin"
    user = "user"


users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("email", sqlalchemy.String(120), unique=True),
    sqlalchemy.Column("password", sqlalchemy.String(255)),
    sqlalchemy.Column("full_name", sqlalchemy.String(200)),
    sqlalchemy.Column("phone", sqlalchemy.String(13)),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, nullable=False, server_default=sqlalchemy.func.now()),
    sqlalchemy.Column(
        "last_modified_at",
        sqlalchemy.DateTime,
        nullable=False,
        server_default=sqlalchemy.func.now(),
        onupdate=sqlalchemy.func.now(),
    ),
    sqlalchemy.Column("role", sqlalchemy.Enum(UserRole), nullable=False, server_default=UserRole.user.name)
)


class ColorEnum(enum.Enum):
    pink = "pink"
    black = "black"
    white = "white"
    yellow = "yellow"


class SizeEnum(enum.Enum):
    xs = "xs"
    s = "s"
    m = "m"
    l = "l"
    xl = "xl"
    xxl = "xxl"


clothes = sqlalchemy.Table(
    "clothes",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String(120)),
    sqlalchemy.Column("color", sqlalchemy.Enum(ColorEnum), nullable=False),
    sqlalchemy.Column("size", sqlalchemy.Enum(SizeEnum), nullable=False),
    sqlalchemy.Column("photo_url", sqlalchemy.String(255)),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, nullable=False, server_default=sqlalchemy.func.now()),
    sqlalchemy.Column(
        "last_modified_at",
        sqlalchemy.DateTime,
        nullable=False,
        server_default=sqlalchemy.func.now(),
        onupdate=sqlalchemy.func.now(),
    ),
)


# Custom email validator class/field responsible for validating email addresses
class EmailField(str):
    @classmethod
    def __get_validator__(cls):    # This responsible for fetching the validator
        yield cls.validate

    @classmethod
    def validate(cls, v) -> str:  # This validator is fetched from the function above
        try:
            validate_e(v)  # validate the v
            return v  # if everything is okay, return the value
        except EmailNotValidError:
            raise ValueError("Email is not valid")  # value error from python


# Implementing input schemas which are responsible for shaping and
# validating our incoming data on the incoming request
class BaseUser(BaseModel):
    email: EmailField
    full_name: Optional[str]

    @validator("full_name")
    def validate_full_name(cls, v):
        try:
            first_name, last_name = v.split()
            return v
        except Exception:
            raise ValueError("Provide at least two names")


class UserSignIn(BaseUser):
    password: str


# A schema to shape the response object
class UserSignOut(BaseUser):
    phone: Optional[str]
    created_at: datetime
    last_modified_at: datetime


app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# logic for jwt authentication
class CustomHTTPBearer(HTTPBearer):
    async def __call__(
            self, request: Request
    ) -> Optional[HTTPAuthorizationCredentials]:
        res = await super().__call__(request)

        try:
            payload = jwt.decode(res.credentials, config("JWT_SECRET"), algorithms=["HS256"])
            user = await database.fetch_one(users.select().where(users.c.id == payload["sub"]))
            request.state.user = user
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "Token is expired")
        except jwt.InvalidTokenError:
            raise HTTPException(401, "Invalid token")


oauth2_scheme = CustomHTTPBearer()


def create_access_token(user):
    """
    Create an access token for the given user.
    """
    try:
        payload = {"sub": user["id"], "exp": datetime.utcnow() + timedelta(minutes=120)}
        return jwt.encode(payload, config("JWT_SECRET"), algorithm="HS256")
    except Exception as ex:
        raise ex


# Middlewares
# On startup of app, connect to database
@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


# Endpoint to fetch all clothes
@app.get("/clothes/", dependencies=[Depends(oauth2_scheme)])
async def get_all_clothes():
    """
    Get all clothes.
    """
    return await database.fetch_all(clothes.select())


# endpoint for users sign in
@app.post("/register/")
async def create_user(user: UserSignIn):  # validate type of data before entering function
    user.password = pwd_context.hash(user.password)
    # Insert values into users table
    q = users.insert().values(**user.dict())  # user is an object. So converting to dict. The ** means kwargs?
    # Last thing is to execute the query above
    id_ = await database.execute(q)
    created_user = await database.fetch_one(users.select().where(users.c.id == id_))
    token = create_access_token(created_user)
    return {"token": token}
