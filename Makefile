SHELL := /bin/bash

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.PHONY: setup install run test clean fmt

setup:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

install: setup

run:
	./run.sh

test:
	source $(VENV)/bin/activate && pytest -q

clean:
	rm -rf $(VENV) __pycache__ **/__pycache__ *.pyc *.pyo data/ansiaudit.db data/tmp logs/app.log

fmt:
	@echo "Lightweight project; consider adding black/ruff if needed."
