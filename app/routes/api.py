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
