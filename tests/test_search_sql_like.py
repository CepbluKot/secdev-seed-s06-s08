
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_search_should_not_return_all_on_injection():
    # По бессмысленному запросу ожидаем 0, а по инъекции — тоже 0 (не все элементы)
    resp_noise = client.get("/search", params={"q": "zzzzzzzzz"}).json()
    inj = client.get("/search", params={"q": "' OR '1'='1"}).json()
    assert len(inj["items"]) <= len(resp_noise["items"]), "Инъекция в LIKE не должна приводить к выдаче всех элементов"
