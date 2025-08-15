from flask import Blueprint, jsonify
from ..jobs import job_manager
from ..models import BulkJob, AnsibleRun
import json

api_bp = Blueprint("api", __name__)

@api_bp.get("/job/<int:job_id>")
def job_status(job_id):
    p = job_manager.progress(job_id)
    bj = BulkJob.query.get(job_id)
    runs = []
    if bj and bj.run_ids:
        ids = json.loads(bj.run_ids)
        rows = AnsibleRun.query.filter(AnsibleRun.id.in_(ids)).all()
        for r in rows:
            runs.append({"id": r.id, "host": r.host_ip, "role": r.role_name, "mode": r.mode, "status": r.status})
    return jsonify({"progress": p, "runs": runs})


@api_bp.get("/preflight")
def preflight_api():
    from ..preflight import run_preflight, decorate_with_fixes
    result = decorate_with_fixes(run_preflight())
    return jsonify(result)


@api_bp.get("/ports/profile/<int:pid>")
def ports_profile_get(pid):
    from ..models import PortProfile
    p = PortProfile.query.get(pid)
    if not p:
        return jsonify({"error":"not found"}), 404
    return jsonify({
        "id": p.id,
        "name": p.name,
        "description": p.description or "",
        "tcp_ports": p.tcp_ports or "",
        "udp_ports": p.udp_ports or "",
        "version_probe": bool(p.version_probe),
        "timing": p.timing or "T4",
        "host_timeout": p.host_timeout or "90s"
    })
