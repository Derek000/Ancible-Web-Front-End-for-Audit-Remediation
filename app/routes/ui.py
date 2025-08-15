from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from ..db import db
from ..models import NetworkScan, Host, Credential, LockdownRole, AnsibleRun, BulkJob, Schedule
from ..scanner import NmapScanner
from ..ansible_exec import AnsibleExecutor
from ..reporting import ReportBuilder, compose_change_plan
from ..security import SecretBox
from ..jobs import job_manager
from ..notifier import notify as notify_fn
import json, os, datetime

ui_bp = Blueprint("ui", __name__)

@ui_bp.route("/")
def index():
    scans = NetworkScan.query.order_by(NetworkScan.started_at.desc()).limit(10).all()
    hosts = Host.query.order_by(Host.last_seen.desc()).limit(50).all()
    roles = LockdownRole.query.order_by(LockdownRole.name.asc()).all()
    runs = AnsibleRun.query.order_by(AnsibleRun.started_at.desc()).limit(20).all()
    return render_template("index.html", scans=scans, hosts=hosts, roles=roles, runs=runs)

@ui_bp.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        name = request.form["name"].strip()
        targets = request.form["targets"].strip()
        s = NetworkScan(name=name, targets=targets, status="running")
        db.session.add(s); db.session.commit()
        scanner = NmapScanner()
        outdir = scanner.scan(s)
        s.result_path = outdir
        s.status = "complete"
        db.session.add(s); db.session.commit()
        flash("Scan complete", "success")
        return redirect(url_for("ui.index"))
    return render_template("scan.html")

@ui_bp.route("/assets")
def assets():
    hosts = Host.query.order_by(Host.last_seen.desc()).all()
    creds = {c.host_ip: c for c in Credential.query.all()}
    return render_template("assets.html", hosts=hosts, creds=creds)

@ui_bp.route("/credentials/<ip>", methods=["GET", "POST"])
def credentials(ip):
    box = SecretBox()
    cred = Credential.query.filter_by(host_ip=ip).first()
    if request.method == "POST":
        username = request.form["username"]
        auth_type = request.form["auth_type"]
        secret = request.form["secret"]
        port = int(request.form.get("port", "22"))
        become = True if request.form.get("become") == "on" else False
        is_windows = True if request.form.get("is_windows") == "on" else False
        token = box.encrypt(secret.encode("utf-8"), aad=ip.encode())
        if not cred:
            cred = Credential(host_ip=ip, username=username, auth_type=auth_type, secret_enc=token, port=port, become=become, is_windows=is_windows)
        else:
            cred.username = username
            cred.auth_type = auth_type
            cred.secret_enc = token
            cred.port = port
            cred.become = become
            cred.is_windows = is_windows
        db.session.add(cred); db.session.commit()
        flash("Credentials saved", "success")
        return redirect(url_for("ui.assets"))
    return render_template("credentials.html", ip=ip, cred=cred)

@ui_bp.route("/content/lockdown", methods=["GET", "POST"])
def content_lockdown():
    import subprocess, os
    root = os.environ.get("CONTENT_ROOT", "content/ansible-lockdown")
    os.makedirs(root, exist_ok=True)
    if request.method == "POST":
        repo = request.form["repo"].strip()
        url = f"https://github.com/ansible-lockdown/{repo}.git"
        dest = os.path.join(root, repo)
        if not os.path.exists(dest):
            subprocess.run(["git", "clone", "--depth", "1", url, dest], check=False)
        else:
            subprocess.run(["git", "-C", dest, "pull", "--ff-only"], check=False)
        role = LockdownRole.query.filter_by(name=repo).first()
        if not role:
            role = LockdownRole(name=repo, path=os.path.abspath(dest))
        try:
            commit = subprocess.check_output(["git", "-C", dest, "rev-parse", "HEAD"], text=True).strip()
            role.commit = commit
        except Exception:
            pass
        db.session.add(role); db.session.commit()
        flash(f"Fetched/updated {repo}", "success")
    roles = LockdownRole.query.order_by(LockdownRole.name.asc()).all()
    return render_template("content_lockdown.html", roles=roles, root=root)

@ui_bp.route("/audit/<ip>", methods=["GET", "POST"])
def audit(ip):
    cred = Credential.query.filter_by(host_ip=ip).first()
    roles = LockdownRole.query.order_by(LockdownRole.name.asc()).all()
    if request.method == "POST":
        role_id = int(request.form["role_id"])
        role = LockdownRole.query.get(role_id)
        run = AnsibleRun(host_ip=ip, role_name=role.name, mode="audit", status="running")
        db.session.add(run); db.session.commit()
        executor = AnsibleExecutor()
        rundir, summary = executor.run_role(run, cred, role, mode="audit")
        rep = ReportBuilder(rundir).build(summary)
        run.report_path = rep["html"]
        db.session.add(run); db.session.commit()
        return redirect(url_for("ui.report", run_id=run.id))
    return render_template("audit.html", ip=ip, cred=cred, roles=roles)

@ui_bp.route("/report/<int:run_id>")
def report(run_id):
    run = AnsibleRun.query.get(run_id)
    import json, os
    summary = {}
    if run and run.artifact_path:
        p = os.path.join(run.artifact_path, "summary.json")
        if os.path.exists(p):
            with open(p) as f:
                summary = json.load(f)
    return render_template("report.html", run=run, summary=summary)

@ui_bp.route("/remediate/<int:run_id>", methods=["GET", "POST"])
def remediate(run_id):
    prev = AnsibleRun.query.get(run_id)
    cred = Credential.query.filter_by(host_ip=prev.host_ip).first()
    role = LockdownRole.query.filter_by(name=prev.role_name).first()
    import json, os
    with open(os.path.join(prev.artifact_path, "summary.json")) as f:
        summary = json.load(f)
    failed = [r for r in summary.get("noncompliant", []) if r.get("control_id")]
    unique_controls = sorted(set([r["control_id"] for r in failed if r.get("control_id")]))
    if request.method == "POST":
        selected = request.form.getlist("controls")
        run = AnsibleRun(host_ip=prev.host_ip, role_name=role.name, mode="remediate", tags=json.dumps(selected), status="running")
        db.session.add(run); db.session.commit()
        execu = AnsibleExecutor()
        rundir, summ = execu.run_role(run, cred, role, mode="remediate", selected_tags=selected)
        rep = ReportBuilder(rundir).build(summ)
        run.report_path = rep["html"]
        db.session.add(run); db.session.commit()
        return redirect(url_for("ui.report", run_id=run.id))
    return render_template("remediate.html", run=prev, controls=unique_controls, role=role)

def _bulk_worker(run_id, mode, role, selected_tags, host_ip):
    from ..ansible_exec import AnsibleExecutor
    from ..models import Credential, AnsibleRun
    from ..reporting import ReportBuilder
    from ..db import db
    cred = Credential.query.filter_by(host_ip=host_ip).first()
    run = AnsibleRun.query.get(run_id)
    execu = AnsibleExecutor()
    rundir, summary = execu.run_role(run, cred, role, mode=mode, selected_tags=selected_tags)
    rep = ReportBuilder(rundir).build(summary)
    run.report_path = rep["html"]
    db.session.add(run); db.session.commit()
    return run_id

@ui_bp.route("/bulk", methods=["GET", "POST"])
def bulk():
    q_net = request.args.get("network", "").strip()
    q_os = request.args.get("os", "").strip()
    hosts_query = Host.query
    if q_os:
        hosts_query = hosts_query.filter((Host.os_family.ilike(f"%{q_os}%")) | (Host.os_name.ilike(f"%{q_os}%")))
    if q_net:
        scans = NetworkScan.query.filter(NetworkScan.name.ilike(f"%{q_net}%")).all()
        ids = [s.id for s in scans]
        if ids:
            hosts_query = hosts_query.filter(Host.network_scan_id.in_(ids))
        else:
            hosts_query = hosts_query.filter(Host.id == -1)
    hosts = hosts_query.order_by(Host.last_seen.desc()).all()
    roles = LockdownRole.query.order_by(LockdownRole.name.asc()).all()
    if request.method == "POST":
        mode = request.form["mode"]
        role_id = int(request.form["role_id"])
        selected_ips = request.form.getlist("ips")
        use_last_audit = request.form.get("use_last_audit") == "on"
        tags_csv = request.form.get("tags_csv", "").strip()
        role = LockdownRole.query.get(role_id)

        bj = BulkJob(mode=mode, role_name=role.name, status="running", host_ips=json.dumps(selected_ips), run_ids=json.dumps([]))
        db.session.add(bj); db.session.commit()

        futures = []
        created_ids = []
        for ip in selected_ips:
            cred = Credential.query.filter_by(host_ip=ip).first()
            if not cred:
                continue
            selected_tags = []
            if mode == "remediate":
                if use_last_audit:
                    prev = (AnsibleRun.query
                            .filter_by(host_ip=ip, role_name=role.name, mode="audit")
                            .order_by(AnsibleRun.started_at.desc()).first())
                    if prev and prev.artifact_path:
                        import json as _json, os as _os
                        with open(_os.path.join(prev.artifact_path, "summary.json")) as f:
                            summ = _json.load(f)
                        failed = [r for r in summ.get("noncompliant", []) if r.get("control_id")]
                        selected_tags = sorted(set([r["control_id"] for r in failed if r.get("control_id")]))
                if tags_csv:
                    selected_tags += [t.strip() for t in tags_csv.split(",") if t.strip()]
                    selected_tags = sorted(set(selected_tags))

            run = AnsibleRun(host_ip=ip, role_name=role.name, mode=mode, tags=json.dumps(selected_tags) if selected_tags else None, status="running", bulk_job_id=bj.id)
            db.session.add(run); db.session.commit()
            created_ids.append(run.id)
            fut = job_manager.submit(_bulk_worker, run.id, mode, role, selected_tags if selected_tags else None, ip)
            futures.append(fut)

        bj.run_ids = json.dumps(created_ids)
        db.session.add(bj); db.session.commit()
        job_manager.submit_bulk(bj.id, futures)
        return redirect(url_for("ui.bulk_progress", job_id=bj.id))
    return render_template("bulk.html", hosts=hosts, roles=roles, q_net=q_net, q_os=q_os)

@ui_bp.route("/bulk/<int:job_id>/progress")
def bulk_progress(job_id):
    bj = BulkJob.query.get(job_id)
    runs = []
    avg_sec = None
    if bj and bj.run_ids:
        ids = json.loads(bj.run_ids)
        runs = AnsibleRun.query.filter(AnsibleRun.id.in_(ids)).order_by(AnsibleRun.started_at.desc()).all()
        durations = []
        for r in runs:
            if r.finished_at and r.started_at:
                durations.append((r.finished_at - r.started_at).total_seconds())
        if durations:
            avg_sec = sum(durations)/len(durations)
    p = job_manager.progress(job_id)
    eta = None
    if avg_sec and p["total"]:
        remaining = max(0, p["total"] - p["done"])
        eta = int(remaining * avg_sec)
    return render_template("bulk_progress.html", job=bj, runs=runs, eta=eta, progress=p)

@ui_bp.route("/bulk/<int:job_id>/fragment")
def bulk_fragment(job_id):
    bj = BulkJob.query.get(job_id)
    runs = []
    if bj and bj.run_ids:
        ids = json.loads(bj.run_ids)
        runs = AnsibleRun.query.filter(AnsibleRun.id.in_(ids)).order_by(AnsibleRun.started_at.desc()).all()
    p = job_manager.progress(job_id)
    eta = None
    return render_template("_bulk_table.html", job=bj, runs=runs, eta=eta, progress=p)

@ui_bp.route("/export/run/<int:run_id>")
def export_run(run_id):
    run = AnsibleRun.query.get(run_id)
    if not run or not run.artifact_path:
        flash("Run not found", "error")
        return redirect(url_for("ui.index"))
    builder = ReportBuilder(run.artifact_path)
    pkg = builder.export_change_package()
    return send_file(pkg, as_attachment=True, download_name=f"CAB_run_{run.id}.zip")

@ui_bp.route("/export/change_plan/<int:remediate_run_id>")
def export_change_plan(remediate_run_id):
    r = AnsibleRun.query.get(remediate_run_id)
    if not r or r.mode != "remediate":
        flash("Invalid remediation run", "error")
        return redirect(url_for("ui.index"))
    before = (AnsibleRun.query
              .filter_by(host_ip=r.host_ip, role_name=r.role_name, mode="audit")
              .filter(AnsibleRun.started_at <= r.started_at)
              .order_by(AnsibleRun.started_at.desc()).first())
    after = (AnsibleRun.query
             .filter_by(host_ip=r.host_ip, role_name=r.role_name, mode="audit")
             .filter(AnsibleRun.started_at >= r.finished_at if r.finished_at else r.started_at)
             .order_by(AnsibleRun.started_at.asc()).first())
    out = os.path.join("data/artifacts", f"ChangePlan_{r.id}_{datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.zip")
    before_dir = before.artifact_path if before and before.artifact_path else None
    after_dir = after.artifact_path if after and after.artifact_path else None
    remediate_dir = r.artifact_path
    pkg = compose_change_plan(out, before_dir, after_dir, remediate_dir)
    return send_file(pkg, as_attachment=True, download_name=os.path.basename(pkg))

@ui_bp.route("/export/bulk", methods=["GET", "POST"])
def export_bulk():
    runs = AnsibleRun.query.order_by(AnsibleRun.started_at.desc()).limit(200).all()
    if request.method == "POST":
        selected = [int(x) for x in request.form.getlist("run_ids")]
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        root = "data/artifacts"
        out = os.path.join(root, f"CAB_bulk_{ts}.zip")
        import zipfile
        if os.path.exists(out):
            os.remove(out)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for rid in selected:
                r = AnsibleRun.query.get(rid)
                if not r or not r.artifact_path:
                    continue
                pkg = ReportBuilder(r.artifact_path).export_change_package()
                z.write(pkg, arcname=f"run_{rid}.zip")
        return send_file(out, as_attachment=True, download_name=os.path.basename(out))
    return render_template("export_bulk.html", runs=runs)

@ui_bp.route("/preflight")
def preflight():
    from ..preflight import run_preflight
    result = run_preflight()
    return render_template("preflight.html", result=result)

@ui_bp.route("/schedules", methods=["GET", "POST"])
def schedules():
    hosts = Host.query.order_by(Host.last_seen.desc()).all()
    roles = LockdownRole.query.order_by(LockdownRole.name.asc()).all()
    if request.method == "POST":
        name = request.form["name"].strip()
        role_id = int(request.form["role_id"])
        cadence = request.form["cadence"]
        interval = int(request.form.get("interval", "0"))
        cron = request.form.get("cron", "").strip()
        notify = request.form.get("notify") == "on"
        selected_ips = request.form.getlist("ips")
        role = LockdownRole.query.get(role_id)
        sc = Schedule(name=name, role_name=role.name, host_ips=json.dumps(selected_ips), cadence=cadence, interval_seconds=interval or None, cron=cron or None, notify=notify, enabled=True)
        db.session.add(sc); db.session.commit()
        def _job(sc_id=sc.id):
            s = Schedule.query.get(sc_id)
            if not s or not s.enabled:
                return
            ips = json.loads(s.host_ips)
            bj = BulkJob(mode="audit", role_name=s.role_name, status="running", host_ips=json.dumps(ips), run_ids=json.dumps([]))
            db.session.add(bj); db.session.commit()
            role = LockdownRole.query.filter_by(name=s.role_name).first()
            futures = []
            created_ids = []
            for ip in ips:
                cred = Credential.query.filter_by(host_ip=ip).first()
                if not cred: 
                    continue
                run = AnsibleRun(host_ip=ip, role_name=role.name, mode="audit", status="running", bulk_job_id=bj.id)
                db.session.add(run); db.session.commit()
                fut = job_manager.submit(_bulk_worker, run.id, "audit", role, None, ip)
                futures.append(fut); created_ids.append(run.id)
            bj.run_ids = json.dumps(created_ids)
            db.session.add(bj); db.session.commit()
            job_manager.submit_bulk(bj.id, futures)
            if s.notify:
                subject = f"Ansiaudit schedule '{s.name}' started"
                body = f"Role: {s.role_name}\nHosts: {', '.join(ips)}"
                notify_fn(subject, body)
        job_id = f"schedule-{sc.id}"
        from ..jobs import job_manager
        if cadence == "daily":
            job_manager.schedule_cron(job_id, _job, hour=3, minute=0)
        elif cadence == "weekly":
            job_manager.schedule_cron(job_id, _job, day_of_week="sun", hour=3, minute=0)
        elif cadence == "interval" and interval > 0:
            job_manager.schedule_interval(job_id, _job, seconds=interval)
        elif cadence == "cron" and cron:
            m,h,dom,mon,dow = cron.split()
            job_manager.scheduler.add_job(_job, "cron", id=job_id, replace_existing=True, minute=m, hour=h, day=dom, month=mon, day_of_week=dow)
        flash("Schedule created", "success")
        return redirect(url_for("ui.schedules"))
    from ..models import Schedule as S
    scheds = S.query.order_by(S.created_at.desc()).all()
    return render_template("schedules.html", hosts=hosts, roles=roles, scheds=scheds)
