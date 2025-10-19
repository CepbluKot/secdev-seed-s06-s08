
.PHONY: venv deps init run test ci

PY?=python

venv:
	$(PY) -m venv .venv

deps:
	pip install -r requirements.txt

init:
	$(PY) scripts/init_db.py

run:
	uvicorn app.main:app --host 127.0.0.1 --port 8000

test:
	pytest -q

ci:
	mkdir -p EVIDENCE/S08
	pytest --junitxml=EVIDENCE/S08/test-report.xml -q

ci-s06:
	python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt && python scripts/init_db.py && pytest -q --junitxml=EVIDENCE/S06/test-report.xml
