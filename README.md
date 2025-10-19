
# secdev-seed-s06-s08 (учебный шаблон)

**Назначение:** минимальный учебный проект для семинаров **S06–S08** (Secure Coding → Containerization → CI).
Шаблон **намеренно небезопасен** (SQL injection, XSS, слабая аутентификация), чтобы у студентов были патчи для S06.

## Стек
- Python 3.11+
- FastAPI + Uvicorn
- SQLite (в файле `app.db`)
- Jinja2 (шаблоны)
- pytest (+ httpx) для автотестов

## Быстрый старт (локально)
> ⚠️ Тут приведён примерный порядок; **ваш one-liner** под DV вы сформулируете сами на S06.

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/init_db.py
uvicorn app.main:app --reload
```

Откройте: http://127.0.0.1:8000/  и попробуйте:

- `/echo?msg=<script>alert(1)</script>` — XSS (намеренно небезопасно)
- `POST /login` с JSON `{"username": "admin'-- ", "password": "x"}` — обход логина за счёт SQLi
- `/search?q=' OR '1'='1` — выдаёт все записи (SQLi)

## Тесты
```bash
pytest -q
```
Из коробки тесты **падают**, пока вы не примените патчи безопасности.

## Что править на S06 (минимум)
- Параметризация SQL (sqlite параметризованные запросы)
- Убрать небезопасный `|safe` в шаблоне (или экранировать вывод)
- Усилить валидацию входных данных и обработку ошибок
- Довести тесты до зелёных и сформировать **one-liner** для DV
- Складывать отчёты/логи в `EVIDENCE/S06/`

## Лицензия
MIT (только в учебных целях; уязвимости добавлены намеренно).


---

## S07 — Containerization (болванка)
Быстрый старт:
```bash
docker build -t secdev-seed:latest .
docker run --rm -p 8000:8000 secdev-seed:latest
# или
docker compose up --build
```
TODO на S07:
- Убедиться, что ваш **one-liner** из S06 переносится в контейнерный сценарий (entrypoint/команда).
- Добавить настройки безопасности (user non-root, ограничение прав, healthcheck).

## S08 — CI Minimal (болванка)
В репозитории уже есть `.github/workflows/ci.yml` с шагами: checkout → python → cache pip → deps → init DB → pytest → upload artifacts.
TODO на S08:
- Довести тесты до зелёных (иначе CI красный — это нормально на старте).
- Проверить, что артефакты попадают в `EVIDENCE/S08/` и доступны в job artifacts.
- (Опционально) добавить публикацию HTML-отчётов, coverage и т. п.
