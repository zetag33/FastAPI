from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

# uvicorn users:app --reload

router = APIRouter()


class User(BaseModel):
    id: int
    name: str
    surname: str
    url: str
    age: int


users_list = [User(id=1, name="Jerry", surname="Sauzal", url="https://jerry.com", age=35),
              User(id=2, name="Carmen", surname="M",
                   url="https://carmenm.com", age=35),
              User(id=3, name="Julio", surname="Martinez", url="https://juliomartinez.com", age=33)]


@router.get("/usersjson")
async def usersjson():  # Creamos un JSON a mano
    return [{"name": "Jerry", "surname": "Sauzal", "url": "https://jerry.com", "age": 35},
            {"name": "Carmen", "surname": "M",
                "url": "https://carmenm.com", "age": 35},
            {"name": "Julio", "surname": "Martinez", "url": "https://juliomartinez.com", "age": 33}]


@router.get("/users")
async def users():
    return users_list


@router.get("/user/{id}")  # Path
async def user(id: int):
    return search_user(id)


@router.get("/user/")  # Query
async def user(id: int):
    return search_user(id)



@router.post("/user/", response_model=User, status_code=201)
async def user(user: User):
    if type(search_user(user.id)) == User:
        raise HTTPException(status_code=404, detail="El usuario ya existe")

    users_list.append(user)
    return user


@router.put("/user/")
async def user(user: User):

    found = False

    for index, saved_user in enumerate(users_list):
        if saved_user.id == user.id:
            users_list[index] = user
            found = True

    if not found:
        return {"error": "No se ha actualizado el usuario"}

    return user


@router.delete("/user/{id}")
async def user(id: int):

    found = False

    for index, saved_user in enumerate(users_list):
        if saved_user.id == id:
            del users_list[index]
            found = True

    if not found:
        return {"error": "No se ha eliminado el usuario"}


def search_user(id: int):
    users = filter(lambda user: user.id == id, users_list)
    try:
        return list(users)[0]
    except:
        return {"error": "No se ha encontrado el usuario"}
