import re
import json
import logging
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST

from .models import LoginRequest
from .db import query, query_one

app = FastAPI(title="secdev-seed-s06-s08")
templates = Jinja2Templates(directory="app/templates")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    filename="log.log",
    filemode="w",
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").disabled = True


_SENSITIVE_KEYWORDS = (
    "password",
    "pass",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "authorization",
)


def _mask_value_for_key(key: str, value: Any) -> Any:
    """
    Простая маскировка: если ключ выглядит секретным -> заменяем на "****".
    Для прочих значений возвращаем как есть (строки/числа).
    """
    if key is None:
        return value
    kl = key.lower()
    if any(k in kl for k in _SENSITIVE_KEYWORDS):
        return "****"
    return value


def _mask_query_params(params: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _mask_value_for_key(k, v) for k, v in params.items()}


def _mask_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Возвращаем только небольшой набор заголовков и маскируем чувствительные из них.
    Не включаем все заголовки (чтобы не дампить).
    """
    allowed = ("host", "user-agent", "content-type", "authorization")
    out = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in allowed:
            out[k] = "****" if any(s in kl for s in _SENSITIVE_KEYWORDS) else v
    return out


def mask_json(
    obj: Any,
    mask: str = "****",
    return_json_str: bool = False,
) -> Any:
    """
    Маскирует значения в JSON-like объекте или JSON-строке.
    - obj: dict/list или JSON-строка
    - sensitive_keywords: tuple ключевых подстрок (регистрозависимость игнорируется)
    - mask: строка для замены секретов
    - max_str_len: усекает строки длиннее этого порога
    - return_json_str: если True и вход была строкой — вернёт JSON-строку, иначе Python-объект

    Пример:
      mask_json('{"username":"bob","password":"p"}', return_json_str=True)
      -> '{"username": "bob", "password": "****"}'
    """
    # Если obj — строка, попробуем распарсить как JSON
    is_input_str = isinstance(obj, str)
    parsed = obj
    if is_input_str:
        try:
            parsed = json.loads(obj)
        except Exception:
            # если не валидный JSON — возвращаем исходное значение (или можно поднять ошибку)
            return obj if not return_json_str else json.dumps(obj)

    def _mask(o: Any) -> Any:
        # dict -> рекурсивно обрабатываем ключи/значения
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                kl = str(k).lower()
                if any(
                    sk in kl
                    for sk in (
                        "password",
                        "pass",
                        "pwd",
                        "token",
                        "secret",
                        "api_key",
                        "apikey",
                        "access_token",
                        "authorization",
                    )
                ):
                    # маскируем полностью значение под секретным ключом
                    out[k] = mask
                else:
                    out[k] = _mask(v)
            return out

        # list/tuple -> маскируем элементы
        if isinstance(o, list):
            return [_mask(x) for x in o]
        if isinstance(o, tuple):
            return tuple(_mask(x) for x in o)

        # числа, bool, None — без изменений
        return o

    masked = _mask(parsed)

    if return_json_str:
        return json.dumps(masked, ensure_ascii=False)
    return masked


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    # логируем кратко, без чувствительных данных

    # logger.info(f"Got error for request. \nRequest.url: {request.url} \nRequest.json: {request_json}")
    qp = dict(request.query_params)
    masked_qp = _mask_query_params(qp)
    headers = _mask_headers(dict(request.headers))
    client = request.client.host if request.client else None

    logger.info(
        "Unhandled error: %s | method=%s url=%s client=%s query=%s headers=%s args=%s",
        exc.__class__.__name__,
        request.method,
        str(request.url),
        client,
        masked_qp,
        headers,
        mask_json(exc.args),
    )

    return JSONResponse({"detail": "Internal error"}, status_code=500)


@app.get("/", response_class=HTMLResponse)
def index(request: Request, msg: str | None = None):
    # XSS: намеренно рендерим message без экранирования через шаблон (см. index.html)
    return templates.TemplateResponse(
        "index.html", {"request": request, "message": msg or "Hello!"}
    )


@app.get("/error")
def error(request: Request):
    raise Exception


@app.get("/echo", response_class=HTMLResponse)
def echo(request: Request, msg: str | None = None):
    return templates.TemplateResponse(
        "index.html", {"request": request, "message": msg or ""}
    )


@app.get("/search")
def search(q: str | None = None):
    # SQLi: намеренно подставляем строку без параметров
    if q:
        if len(q) > 20:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST, detail="Request str too long"
            )

        # fix для S06-02 - SQL Injection (search LIKE)
        pattern = f"%{q}%"
        items = query(
            "SELECT id, name, description FROM items WHERE name LIKE ?", (pattern,)
        )

    else:
        sql = "SELECT id, name, description FROM items LIMIT 10"
        items = query(sql)

    return JSONResponse(content={"items": items})


@app.post("/login")
def login(payload: LoginRequest):
    # SQLi: обход авторизации через username="admin'-- " или password-инъекции

    sql = f"SELECT id, username FROM users WHERE username = '{payload.username}' AND password = '{payload.password}'"
    row = query_one(sql)
    if not row:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    # фиктивный токен
    return {"status": "ok", "user": row["username"], "token": "dummy"}


@app.post("/login_w_error")
def login_w_error(payload: LoginRequest):

    raise Exception(payload.model_dump())
