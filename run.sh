#!/usr/bin/env bash
set -euo pipefail
if [ ! -d .venv ]; then
  python3 -m venv .venv
  . .venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
else
  . .venv/bin/activate
fi
export FLASK_APP=app/app.py
python - <<'PY'
from app.app import create_app
create_app()
PY
