
from pydantic import BaseModel

class LoginRequest(BaseModel):
    # Упрощённо, без ограничений длины/формата — это тоже часть "дырок" для S06
    username: str
    password: str

class Item(BaseModel):
    id: int
    name: str
    description: str | None = None
