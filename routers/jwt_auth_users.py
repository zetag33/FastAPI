import schedule
import templates
from fastapi import APIRouter, Depends, HTTPException, status, Header
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta

from jinja2 import Environment, FileSystemLoader
from starlette.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from starlette.requests import Request


from db.client import db_client, tokens
import time

# pip install "python-jose[cryptography]"
# pip install "passlib[bcrypt]"
ALGORITHM = "HS256"
ACCESS_TOKEN_DURATION = 3
SECRET = "201d573bd7d1344d3a3bfce1550b69102fd11be3db6d379508b6cccc58ea230b"

router = APIRouter(prefix="/jwtauth",
                   tags=["jwtauth"],
                   responses={status.HTTP_404_NOT_FOUND: {"message": "No encontrado"}})

oauth2 = OAuth2PasswordBearer(tokenUrl="login")

crypt = CryptContext(schemes=["bcrypt"])

mongo = db_client
revoked_tokens = tokens

exception = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario no es correcto")


class User(BaseModel):
    username: str
    full_name: str
    email: str
    disabled: bool


class UserDB(User):
    password: str


def search_user_db(username: str):
    user_data = mongo.find_one({"username": username})

    if user_data:
        return UserDB(**user_data)


def search_user(username: str):
    user_data = mongo.find_one({"username": username})

    if user_data:
        return User(**user_data)


async def auth_user(token: str = Depends(oauth2)):
    exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales de autenticación inválidas",
        headers={"WWW-Authenticate": "Bearer"})
    exception_invalidated = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Has modificado los datos del usuario, log in again",
        headers={"WWW-Authenticate": "Bearer"})
    exception_deleted = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="El usuario ya no existe",
        headers={"WWW-Authenticate": "Bearer"})

    try:
        username = jwt.decode(token, SECRET, algorithms=[ALGORITHM]).get("sub")
        if username is None:
            raise exception
        if tokens.find_one({token: {"$exists": True}}):
            raise exception_invalidated
        if not search_user(username):
            raise exception_deleted


    except JWTError:
        raise exception

    return search_user(username)


async def current_user(user: User = Depends(auth_user)):
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario inactivo")

    return user


async def get_token(authorization: str = Header(None, convert_underscores=True)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split("Bearer ")[1]
    return token


# Login page
@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    env = Environment(loader=FileSystemLoader('templates'))
    templates = Jinja2Templates(directory='templates')
    # Render the login form HTML template
    template = env.get_template('login_teamplate.html')
    context = {'request': request}
    html = template.render(context)
    return HTMLResponse(html)


@router.post("/login")
async def login(request: Request , form: OAuth2PasswordRequestForm = Depends()):
    try:
        env = Environment(loader=FileSystemLoader('templates'))
        templates = Jinja2Templates(directory='templates')

        user_db = search_user(form.username)
        if not user_db:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario no es correcto")

        user = search_user_db(form.username)

        if not crypt.verify(form.password, user.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña no es correcta")

        access_token = {"sub": user.username,
                        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_DURATION)}
        token = jwt.encode(access_token, SECRET, algorithm=ALGORITHM)
        template = env.get_template('succesful_login.html')
        context = {'request': request}
        html = template.render(context)
        return HTMLResponse(html,headers={"token": f"Bearer {token}"})
    except HTTPException as e:
        # Handle login errors
        return HTMLResponse(e.detail, status_code=e.status_code)


@router.get("/users/me")
async def me(user: User = Depends(current_user)):
    return user


@router.post("/create_user")
async def me(user: UserDB):
    if type(search_user(user.username)) == User:
        raise Exception
    password = crypt.hash(user.password)
    user.password = password
    name = user.username
    mongo.insert_one(user.model_dump())
    returned_user = User(**user.model_dump())
    return returned_user


@router.delete("/delete_user")
async def delete(user: User = Depends(current_user)):
    if type(search_user(user.username)) != User:
        raise Exception
    mongo.delete_one({"username": user.username})
    return {"Success": "Deleted user succesfully"}


@router.put("/update_user")
async def update_user(updated_user: UserDB, current_user: User = Depends(current_user),
                      token: str = Depends(get_token)):
    if current_user.username != updated_user.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permisos para actualizar este usuario")
    password = crypt.hash(updated_user.password)
    updated_user.password = password

    mongo.delete_one({"username": updated_user.username})
    mongo.insert_one(updated_user.model_dump())
    revoked_tokens.insert_one({token: {}})

    # Return the updated user information and the new token
    return {"user": User(updated_user.model_dump())}


def empty_tokens_database():
    # Remove all documents from the 'tokens' collection
    tokens.delete_many({})


