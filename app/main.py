
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_401_UNAUTHORIZED

from .models import LoginRequest
from .db import query, query_one

app = FastAPI(title="secdev-seed-s06-s08")
templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
def index(request: Request, msg: str | None = None):
    # XSS: намеренно рендерим message без экранирования через шаблон (см. index.html)
    return templates.TemplateResponse("index.html", {"request": request, "message": msg or "Hello!"})

@app.get("/echo", response_class=HTMLResponse)
def echo(request: Request, msg: str | None = None):
    return templates.TemplateResponse("index.html", {"request": request, "message": msg or ""})

@app.get("/search")
def search(q: str | None = None):
    # SQLi: намеренно подставляем строку без параметров
    if q:
        sql = f"SELECT id, name, description FROM items WHERE name LIKE '%{q}%'"
    else:
        sql = "SELECT id, name, description FROM items LIMIT 10"
    return JSONResponse(content={"items": query(sql)})

@app.post("/login")
def login(payload: LoginRequest):
    # SQLi: обход авторизации через username="admin'-- " или password-инъекции
    sql = f"SELECT id, username FROM users WHERE username = '{payload.username}' AND password = '{payload.password}'"
    row = query_one(sql)
    if not row:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    # фиктивный токен
    return {"status": "ok", "user": row["username"], "token": "dummy"}
