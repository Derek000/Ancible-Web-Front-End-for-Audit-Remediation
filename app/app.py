import os
from flask import Flask
from .security import apply_security_headers, csrf, load_env, init_auth
from .db import init_db
from .routes.ui import ui_bp
from .routes.api import api_bp
from .jobs import job_manager
import logging

def create_app():
    load_env()
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))
    app.config["WTF_CSRF_TIME_LIMIT"] = None

    # Logging
    log_path = os.path.join("logs", "app.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        handlers=[logging.FileHandler(log_path), logging.StreamHandler()],
    )

    csrf.init_app(app)
    apply_security_headers(app)
    init_db(app)
    init_auth(app)

    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    job_manager.start()

    bind = os.environ.get("BIND", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app.logger.info(f"Ansiaudit UI listening on http://{bind}:{port}")
    app.run(host=bind, port=port, threaded=True)
    return app
