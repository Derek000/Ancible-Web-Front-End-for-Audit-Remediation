from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

def init_db(app):
    import os
    db_uri = os.environ.get("SQLITE", "sqlite:///data/ansiaudit.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = db_uri if db_uri.startswith("sqlite:///") else f"sqlite:///{db_uri}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    from .models import NetworkScan, Host, Credential, LockdownRole, AnsibleRun, BulkJob, Schedule
    os.makedirs("data", exist_ok=True)
    db.init_app(app)
    with app.app_context():
        db.create_all()
