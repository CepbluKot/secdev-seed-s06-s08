
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_echo_should_escape_script_tags():
    resp = client.get("/echo", params={"msg": "<script>alert(1)</script>"})
    # В защищённом варианте скрипт не должен оказаться в ответе как тег.
    assert "<script>" not in resp.text, "Вывод должен экранировать потенциальную XSS-последовательность"
