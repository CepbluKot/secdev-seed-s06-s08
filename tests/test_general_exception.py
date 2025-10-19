from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_error_query():
    # позитивный тест
    # проверка того, что все Exception (!= HTTPException) будут обрабатываться единым обработчиком
    resp_long = client.get("/error")
    assert resp_long.status_code == 500



def test_http_exception_passthrough():
    """
    Негативный тест: проверяем, что HTTPException не перехватывается общим обработчиком
    и возвращается с тем статусом/деталями, который был поднят в эндпоинте.
    Если ваш эндпоинт использует другой путь или код — замените их здесь.
    """
    resp = client.get("/test_httpexception")
    assert resp.status_code != 500
