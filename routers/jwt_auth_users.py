from fastapi import APIRouter, Depends, HTTPException, status, Header
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
#pip install "python-jose[cryptography]"
#pip install "passlib[bcrypt]"
ALGORITHM = "HS256"
ACCESS_TOKEN_DURATION = 3
SECRET = "201d573bd7d1344d3a3bfce1550b69102fd11be3db6d379508b6cccc58ea230b"

router = APIRouter(prefix="/jwtauth",
                   tags=["jwtauth"],
                   responses={status.HTTP_404_NOT_FOUND: {"message": "No encontrado"}})

oauth2 = OAuth2PasswordBearer(tokenUrl="login")

crypt = CryptContext(schemes=["bcrypt"])

revoked_tokens = set()
class User(BaseModel):
    username: str
    full_name: str
    email: str
    disabled: bool


class UserDB(User):
    password: str


users_db = {
    "Jerry": {
        "username": "Jerry",
        "full_name": "Jerry del Sauzal",
        "email": "jerry.jerry.com",
        "disabled": False,
        "password": "$2a$12$m/adJzFOUAM3VPYt8yRfnOR.Psz8W2piGit9/VVePmi5smaqYAkTy"
    },
    "Carmen": {
        "username": "Carmen",
        "full_name": "Carmen Sanchez",
        "email": "carmen@gmail.com",
        "disabled": False,
        "password": "$2a$12$XHQSN8PsDjluRJYU/gZsUuRDqY5LxbFCppLlrSyA.9RXg6YkzjLTa"
    }
}

exception = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario no es correcto")

def search_user_db(username: str):
    if username in users_db:
        return UserDB(**users_db[username])


def search_user(username: str):
    if username in users_db:
        return User(**users_db[username])


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
        if token in revoked_tokens:
            raise exception_invalidated
        if username not in users_db:
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


@router.post("/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):

    user_db = users_db.get(form.username)
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario no es correcto")

    user = search_user_db(form.username)

    if not crypt.verify(form.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña no es correcta")

    access_token = {"sub": user.username,
                    "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_DURATION)}

    return {"access_token": jwt.encode(access_token, SECRET, algorithm=ALGORITHM), "token_type": "bearer"}


@router.get("/users/me")
async def me(user: User = Depends(current_user)):
    return user

@router.get("/users/all")
async def get_users(user: User = Depends(current_user)):
    return users_db

@router.post("/create_user")
async def me(user: UserDB):
    if type(search_user(user.username)) == User:
        raise Exception
    password = crypt.hash(user.password)
    user.password = password
    name = user.username
    users_db[user.username] = user.model_dump()
    returned_user = User(**users_db[user.username])
    return returned_user

@router.delete("/delete_user")
async def delete(user: User = Depends(current_user)):
    if type(search_user(user.username)) != User:
        raise Exception
    name = user.username
    del users_db[name]
    return {"Success": "Deleted user succesfully"}

@router.put("/update_user")
async def update_user(updated_user: UserDB, current_user: User = Depends(current_user), token: str = Depends(get_token)):
    if current_user.username != updated_user.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permisos para actualizar este usuario")
    password = crypt.hash(updated_user.password)
    updated_user.password = password

    del users_db[updated_user.username]
    users_db[updated_user.username] = updated_user.model_dump()
    revoked_tokens.add(token)

    # Return the updated user information and the new token
    return {"user": User(**users_db[updated_user.username])}

