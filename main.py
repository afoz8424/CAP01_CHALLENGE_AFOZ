from fastapi import FastAPI, HTTPException
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Tuple

import jwt
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends

fake_db = {"users": {}}

app = FastAPI()


class Payload(BaseModel):
    numbers: List[int]


class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# Propósito de la Función: Recibir un listado de numeros y devolver una lista ordenada utilizando el algoritmo de Bubble Sort
# Nombre de la Función: bubble_soft_list
# Parámetros de Entrada de la Función: Listado de numeros en un array
# Acciones Esperadas: La funcion debe recorrer el listado de numeros que llegan en el array y ordenernado de forma ascendente
# Tipo de Dato de Retorno: array de numeros
# Endpoint de la API: /bubble-sort
# Notas Adicionales: en el endpoint /bubble-sort debe ser de tipo post y recibir un payload con el listado de numeros a ordenar

def bubble_sort_list(numbers: List[int]) -> List[int]:
    """
    Sorts a list of integers using the bubble sort algorithm.

    Args:
        numbers (List[int]): A list of integers to be sorted.

    Returns:
        List[int]: The sorted list of integers.
    """
    n = len(numbers)
    for i in range(n):
        for j in range(0, n-i-1):
            if numbers[j] > numbers[j+1]:
                numbers[j], numbers[j+1] = numbers[j+1], numbers[j]
    return numbers

@app.post("/bubble-sort")
def bubble_sort_endpoint(payload: Payload, token: str):
    get_current_user(token)
    sorted_numbers = bubble_sort_list(payload.numbers)
    return {"numbers": sorted_numbers}

# Propósito de la Función: Recibir un listado de numeros y devolver únicamente aquellos que son pares
# Nombre de la Función: filtrar_pares
# Parámetros de Entrada de la Función: Listado de numeros en un array
# Acciones Esperadas: La funcion debe recorrer el listado de numeros que llegan en el array y devolver únicamente aquellos que son pares
# Tipo de Dato de Retorno: array de numeros
# Endpoint de la API: /filter-even
# Notas Adicionales: en el endpoint /filter-even debe ser de tipo post y recibir un payload con el listado de numeros a filtrar

def filtrar_pares(numeros: List[int]) -> List[int]:
    """
    Filtra los números pares de una lista de enteros.

    Args:
        numeros (List[int]): Lista de números enteros.

    Returns:
        List[int]: Lista de números enteros que son pares.
    """
    return [num for num in numeros if num % 2 == 0]

@app.post("/filter-even")
def filter_even_endpoint(payload: Payload, token: str):
    get_current_user(token)
    numeros_filtrados = filtrar_pares(payload.numbers)
    return {"even_numbers": numeros_filtrados}

# Propósito de la Función: Recibir un listado de numeros y devolver la suma de sus elementos
# Nombre de la Función: suma_numeros_list
# Parámetros de Entrada de la Función: Listado de numeros en un array
# Acciones Esperadas: La funcion debe recorrer el listado de numeros que llegan en el array y devolver la suma de sus elementos
# Tipo de Dato de Retorno: numero entero
# Endpoint de la API: /sum-elements
# Notas Adicionales: en el endpoint /sum-elements debe ser de tipo post y recibir un payload con el listado de numeros a sumar
def suma_numeros_list(numeros: List[int]) -> int:
    """
    Suma todos los números en una lista.

    Args:
        numeros (List[int]): Una lista de números enteros.

    Returns:
        int: La suma de todos los números en la lista.
    """
    return sum(numeros)

@app.post("/sum-elements")
def sum_elements_endpoint(payload: Payload, token: str):
    get_current_user(token)
    valor_suma = suma_numeros_list(payload.numbers)
    return {"sum": valor_suma}

# Propósito de la Función: Recibir un listado de numeros y devolver el valor máximo
# Nombre de la Función: maximo_valor_list
# Parámetros de Entrada de la Función: Listado de numeros en un array
# Acciones Esperadas: La funcion debe recorrer el listado de numeros que llegan en el array y devolver el valor máximo
# Tipo de Dato de Retorno: numero entero
# Endpoint de la API: /max-value
# Notas Adicionales: en el endpoint /max-value debe ser de tipo post y recibir un payload con el listado de numeros a evaluar

def maximo_valor_list(numeros: List[int]) -> int:
    """
    Devuelve el valor máximo de una lista de enteros.

    Args:
        numeros (List[int]): Una lista de números enteros.

    Returns:
        int: El valor máximo en la lista de enteros.

    Raises:
        HTTPException: Si la lista está vacía, se lanza una excepción con un código de estado 400 y un mensaje de detalle.
    """
    if not numeros:
        raise HTTPException(status_code=400, detail="La lista no puede estar vacía")
    return max(numeros)

@app.post("/max-value")
def max_value_endpoint(payload: Payload, token: str):
    get_current_user(token)
    valor_maximo = maximo_valor_list(payload.numbers)
    return {"max": valor_maximo}

# Propósito de la Función: Debe recibir un numero y un listado de numeros ordenados. true y el índice si el número está en la lista, de lo contrario false y -1 como index
# Nombre de la Función: busqueda binaria
# Parámetros de Entrada de la Función: 
# *numeros: array
# Acciones Esperadas: Recorrer cada uno de los numeros que estan en el array, encontrar el valor maximo entre cada uno de los numeros que estan en el array y retornar el valor
# Tipo de Dato de Retorno: 
# * valor_maximo: integer
# Endpoint de la API: /max-value
# Notas Adicionales: El endpoint debe ser de tipo post
def busqueda_binaria(numbers: List[int], target: int) -> Tuple[bool, int]:
    """
    Perform a binary search on a sorted list of integers to find a target value.

    Args:
        numbers (List[int]): A list of integers sorted in ascending order.
        target (int): The integer value to search for in the list.

    Returns:
        Tuple[bool, int]: A tuple where the first element is a boolean indicating
                          whether the target was found, and the second element is
                          the index of the target in the list if found, otherwise -1.
    """
    left, right = 0, len(numbers) - 1
    while left <= right:
        mid = (left + right) // 2
        if numbers[mid] == target:
            return True, mid
        elif numbers[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return False, -1

@app.post("/binary-search")
def binary_search_endpoint(payload: BinarySearchPayload, token: str):
    get_current_user(token)
    found, index = busqueda_binaria(payload.numbers, payload.target)
    return {"found": found, "index": index}

class User(BaseModel):
    username: str
    password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    """
    Verify if a plain text password matches a hashed password.

    Args:
        plain_password (str): The plain text password to verify.
        hashed_password (str): The hashed password to compare against.

    Returns:
        bool: True if the plain password matches the hashed password, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """
    Hashes a given password using the pwd_context hashing algorithm.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)

# Propósito de la Función: A partir de un sistema de autenticación básico utilizando tokens JWT, se debe crear un endpoint para el registro de usuarios y otro para el inicio de sesión.
# Nombre de la Función: register_user, login_user
# Parámetros de Entrada de la Función:
# *user: User
# Acciones Esperadas:
# *register_user: Recibe un objeto User con un nombre de usuario y contraseña, verifica si el usuario ya existe en la base de datos y si no, guarda el nombre de usuario y la contraseña en la base de datos.
# *login_user: Recibe un objeto User con un nombre de usuario y contraseña, verifica si el usuario existe en la base de datos y si la contraseña es correcta, si es así, genera un token JWT y lo devuelve.
# Tipo de Dato de Retorno:# *register_user: Retorna un mensaje de éxito si el usuario se registró correctamente.
# *login_user: Retorna un token JWT si el usuario se autenticó correctamente.
# Endpoint de la API: /register, /login
# Notas Adicionales: El endpoint /register debe ser de tipo post y recibir un payload con el nombre de usuario y contraseña del usuario a registrar. El endpoint /login debe ser de tipo post y recibir un payload con el nombre de usuario y contraseña del usuario a autenticar.
@app.post("/register")
def register_user(user: User):
    if user.username in fake_db["users"]:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    hashed_password = get_password_hash(user.password)
    fake_db["users"][user.username] = hashed_password
    return {"message": "Registro exitoso"}

@app.post("/login")
def login_user(user: User):
    if user.username not in fake_db["users"]:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    hashed_password = fake_db["users"][user.username]
    if not verify_password(user.password, hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    
    token_data = {"sub": user.username}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token}

def get_current_user(token):
    """
    Decodes the provided JWT token to retrieve the current user's username.

    Args:
        token (str): The JWT token to decode.

    Returns:
        str: The username of the current user if the token is valid.

    Raises:
        HTTPException: If the token is invalid, expired, or the user does not exist in the database.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
        if username not in fake_db["users"].keys():
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
    except:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )