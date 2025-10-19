from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app, raise_server_exceptions=False)

def test_logging_hide_password():
    payload = {"username": "usr", "password": "pwd"}
    resp = client.post("/login_w_error", json=payload)
    print(resp.status_code)
    assert resp.status_code == 500

    with open('app.log', 'r') as f:
        file = f.read()
        assert "pwd" not in file
