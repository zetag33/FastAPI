import schedule
import templates
from fastapi import APIRouter, Depends, HTTPException, status, Header, Cookie, Form
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta

from jinja2 import Environment, FileSystemLoader
from starlette.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from starlette.requests import Request
from fastapi.responses import RedirectResponse


from db.client import db_client, revoked_tokens, existing_tokens
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
tokens = existing_tokens

exception = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario no es correcto")

exception_token = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Credenciales de autenticación inválidas",
    headers={"WWW-Authenticate": "Bearer"})

class User_Delete(BaseModel):
    username: str
    password: str
class User(BaseModel):
    username: str
    full_name: str
    email: str
    disabled: bool


class UserDB(User):
    password: str

def validate_token(token):
    exception_invalidated = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Has modificado los datos del usuario, log in again",
        headers={"WWW-Authenticate": "Bearer"})
    exception_deleted = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="El usuario ya no existe",
        headers={"WWW-Authenticate": "Bearer"})
    if not token:
        raise HTTPException(status_code=401, detail="Token not provided")
    try:
        username = jwt.decode(token, SECRET, algorithms=[ALGORITHM]).get("sub")
        if tokens.find_one({token: {"$exists": True}}):
            return False
        if not search_user(username):
            return False
        db_token = existing_tokens.find_one({f"{username}": {"$exists": True}})
        db_token = db_token[f"{username}"]
        if db_token == token:
            return True
        else:
            return False
    except JWTError:
        return False

def search_user_db(username: str):
    user_data = mongo.find_one({"username": username})

    if user_data:
        return UserDB(**user_data)


def search_user(username: str):
    user_data = mongo.find_one({"username": username})

    if user_data:
        return User(**user_data)

def check_for_revoked_token(key: str):
    cursor = revoked_tokens.find()
    documents_list = []
    for document in cursor:
        documents_list.append(document)
    for dictionary in documents_list:
        if key in dictionary:
            return True
    return False


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
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
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
        db_token = existing_tokens.find_one({form.username: {"$exists": True}})
        if db_token:
            existing_tokens.delete_one({form.username: {"$exists": True}})
        data_to_insert = {f"{form.username}": f"{token}"}
        existing_tokens.insert_one(data_to_insert)
        template = env.get_template('succesful_login.html')
        context = {'request': request}
        html = template.render(context)
        return HTMLResponse(html, headers={"Set-Cookie": f"token= {token}; Path=/"})
    except HTTPException as e:
        # Handle login errors
        return HTMLResponse(e.detail, status_code=e.status_code)


@router.get("/users/me")
async def me(token: str = Cookie(None)):
    exception_invalidated = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Has modificado los datos del usuario, log in again",
        headers={"WWW-Authenticate": "Bearer"})
    exception_deleted = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="El usuario ya no existe",
        headers={"WWW-Authenticate": "Bearer"})
    if not token:
        raise HTTPException(status_code=401, detail="Token not provided")
    try:
        username = jwt.decode(token, SECRET, algorithms=[ALGORITHM]).get("sub")
        if check_for_revoked_token(token):
            raise exception_invalidated
        if not search_user(username):
            raise exception_deleted
        db_token = existing_tokens.find_one({f"{username}": {"$exists": True}})
        db_token = db_token[f"{username}"]
        if db_token == token:
            return search_user(username)
        else:
            raise HTTPException(status_code=401, detail="Token is not correct")
    except JWTError:
        raise exception_token



@router.get("/create_user")
async def me(request: Request):
    env = Environment(loader=FileSystemLoader('templates'))
    templates = Jinja2Templates(directory='templates')
    # Render the login form HTML template
    template = env.get_template('create_user.html')
    context = {'request': request}
    html = template.render(context)
    return HTMLResponse(html)

@router.post("/create_user")
async def me(request: Request, form: UserDB):
    try:
        env = Environment(loader=FileSystemLoader('templates'))
        if type(search_user(form.username)) == User:
            raise Exception
        password = crypt.hash(form.password)
        form.password = password
        user_data = {
            "username": f"{form.username}",
            "fullname": f"{form.full_name}",
            "email": f"{form.email}",
            "disabled": f"{form.disabled}",
            "password": f"{form.username}"
        }
        mongo.insert_one(form.model_dump())
        with open("templates/succesful_create_user.html", "r", encoding="utf-8") as file:
            html_content = file.read()
        return HTMLResponse(html_content)
    except HTTPException as e:
        # Handle login errors
        return HTMLResponse(e.detail, status_code=e.status_code)



@router.get("/delete_user")
async def delete(token: str = Cookie(None)):
    exception_invalidated = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Has modificado los datos del usuario, log in again",
        headers={"WWW-Authenticate": "Bearer"})
    exception_deleted = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="El usuario ya no existe",
        headers={"WWW-Authenticate": "Bearer"})
    if not token:
        raise HTTPException(status_code=401, detail="Token not provided")
    try:
        username = jwt.decode(token, SECRET, algorithms=[ALGORITHM]).get("sub")
        if tokens.find_one({token: {"$exists": True}}):
            raise exception_invalidated
        if not search_user(username):
            raise exception_deleted
        db_token = existing_tokens.find_one({f"{username}": {"$exists": True}})
        db_token = db_token[f"{username}"]
        if db_token == token:
            with open("templates/delete_user.html", "r", encoding="utf-8") as file:
                html_content = file.read()
            return HTMLResponse(html_content)
        else:
            raise HTTPException(status_code=401, detail="Token is not correct")
    except JWTError:
        raise exception_token


@router.delete("/delete_user")
async def delete(userD: User_Delete, token: str = Cookie(None)):
    try:
        token_verification = validate_token(token)
        if token_verification == False:
            raise HTTPException(status_code=401, detail="Token not correct")
        if type(search_user(userD.username)) != User:
            raise Exception

        user = search_user_db(userD.username)

        if not crypt.verify(userD.password, user.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña no es correcta")
        mongo.delete_one({"username": user.username})
        with open("templates/deleted_user_succesfully.html", "r", encoding="utf-8") as file:
            html_content = file.read()
        return HTMLResponse(html_content)
    except HTTPException as e:
        # Handle login errors
        return HTMLResponse(e.detail, status_code=e.status_code)


@router.get("/update_user")
async def update_user(token: str = Cookie(None)):
    try:
        validation = validate_token(token)
        if validation == False:
            raise HTTPException(status_code=401, detail="Token not correct")
        else:
            with open("templates/update_user.html", "r", encoding="utf-8") as file:
                html_content = file.read()
            return HTMLResponse(html_content)
    except HTTPException as e:
        # Handle login errors
        return HTMLResponse(e.detail, status_code=e.status_code)



@router.put("/update_user")
async def update_user(updated_user: UserDB, token: str = Cookie(None)):
    try:
        validation = validate_token(token)
        if validation == False:
            raise HTTPException(status_code=401, detail="Token not correct")
        username = jwt.decode(token, SECRET, algorithms=[ALGORITHM]).get("sub")
        if username != updated_user.username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos para actualizar este usuario")
        password = crypt.hash(updated_user.password)
        updated_user.password = password

        mongo.delete_one({"username": updated_user.username})
        mongo.insert_one(updated_user.model_dump())
        revoked_tokens.insert_one({token: {}})
        with open("templates/modified_user_succesfully.html", "r", encoding="utf-8") as file:
            html_content = file.read()
        return HTMLResponse(html_content)

    except HTTPException as e:
        # Handle login errors
        return HTMLResponse(e.detail, status_code=e.status_code)
