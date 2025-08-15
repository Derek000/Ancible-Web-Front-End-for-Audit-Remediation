from datetime import datetime
from .db import db

class NetworkScan(db.Model):
    __tablename__ = "network_scans"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    targets = db.Column(db.String(512), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.String(512), nullable=True)
    result_path = db.Column(db.String(256), nullable=True)
    status = db.Column(db.String(32), default="pending")

class Host(db.Model):
    __tablename__ = "hosts"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), index=True, nullable=False)
    hostname = db.Column(db.String(256))
    os_name = db.Column(db.String(256))
    os_family = db.Column(db.String(64))
    mac = db.Column(db.String(64))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    network_scan_id = db.Column(db.Integer, db.ForeignKey("network_scans.id", ondelete="SET NULL"))

class Credential(db.Model):
    __tablename__ = "credentials"
    id = db.Column(db.Integer, primary_key=True)
    host_ip = db.Column(db.String(64), index=True, nullable=False)
    username = db.Column(db.String(128), nullable=False)
    secret_enc = db.Column(db.Text, nullable=False)
    auth_type = db.Column(db.String(16), default="password")
    become = db.Column(db.Boolean, default=True)
    port = db.Column(db.Integer, default=22)
    is_windows = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LockdownRole(db.Model):
    __tablename__ = "lockdown_roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), unique=True, nullable=False)
    path = db.Column(db.String(512), nullable=False)
    commit = db.Column(db.String(64), nullable=True)
    discovered_tags = db.Column(db.Text, nullable=True)

class BulkJob(db.Model):
    __tablename__ = "bulk_jobs"
    id = db.Column(db.Integer, primary_key=True)
    mode = db.Column(db.String(16), nullable=False)  # audit|remediate
    role_name = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(32), default="running")
    host_ips = db.Column(db.Text, nullable=False)        # JSON list
    run_ids = db.Column(db.Text, nullable=True)          # JSON list

class AnsibleRun(db.Model):
    __tablename__ = "ansible_runs"
    id = db.Column(db.Integer, primary_key=True)
    host_ip = db.Column(db.String(64), nullable=False)
    role_name = db.Column(db.String(256), nullable=False)
    mode = db.Column(db.String(16), nullable=False)  # audit|remediate
    tags = db.Column(db.Text, nullable=True)  # JSON selected tag list
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), default="pending")
    artifact_path = db.Column(db.String(256), nullable=True)
    report_path = db.Column(db.String(256), nullable=True)
    bulk_job_id = db.Column(db.Integer, db.ForeignKey("bulk_jobs.id", ondelete="SET NULL"), nullable=True)

class Schedule(db.Model):
    __tablename__ = "schedules"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    role_name = db.Column(db.String(256), nullable=False)
    host_ips = db.Column(db.Text, nullable=False)  # JSON list
    cadence = db.Column(db.String(64), nullable=False)  # daily|weekly|interval|cron
    cron = db.Column(db.String(64), nullable=True)  # m h dom mon dow
    interval_seconds = db.Column(db.Integer, nullable=True)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notify = db.Column(db.Boolean, default=False)


class PortJob(db.Model):
    __tablename__ = "port_jobs"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(32), default="running")
    host_ips = db.Column(db.Text, nullable=False)  # JSON list
    options = db.Column(db.Text, nullable=True)    # JSON tcp/udp/version
    result_ids = db.Column(db.Text, nullable=True) # JSON list

class PortResult(db.Model):
    __tablename__ = "port_results"
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("port_jobs.id", ondelete="SET NULL"))
    host_ip = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(32), default="pending")
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)
    artifact_path = db.Column(db.String(256), nullable=True)
    open_tcp = db.Column(db.Text, nullable=True)   # JSON list
    open_udp = db.Column(db.Text, nullable=True)   # JSON list


class PortProfile(db.Model):
    __tablename__ = "port_profiles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    description = db.Column(db.String(256), nullable=True)
    tcp_ports = db.Column(db.String(256), nullable=True)
    udp_ports = db.Column(db.String(256), nullable=True)
    version_probe = db.Column(db.Boolean, default=False)
    timing = db.Column(db.String(4), default="T4")         # T0..T5
    host_timeout = db.Column(db.String(16), default="90s")  # e.g., 60s, 5m
