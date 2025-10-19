from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_should_not_allow_sql_injection():
    # Ожидаем, что вход с username, содержащим SQL-комментарий, должен БЫТЬ запрещён.
    # В текущем состоянии приложения тест упадёт (и это нормально до S06).
    payload = {"username": "admin'-- ", "password": "x"}
    resp = client.post("/login", json=payload)
    print(resp.status_code)
    assert resp.status_code == 401, "SQLi-бэйпас логина должен быть закрыт"


def test_login():
    payload = {"username": "admin", "password": "admin"}
    resp = client.post("/login", json=payload)
    print(resp.status_code)
    assert resp.status_code == 200
