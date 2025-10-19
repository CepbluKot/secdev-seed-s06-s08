from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_error_query():
    # проверка того, что все Exception (!= HTTPException) будут обрабатываться единым обработчиком
    resp_long = client.get("/error")
    assert resp_long.status_code == 500
