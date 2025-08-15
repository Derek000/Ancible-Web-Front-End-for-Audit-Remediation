import os, json, csv, datetime, zipfile
from jinja2 import Template

class ReportBuilder:
    def export_change_package(self):
        import zipfile, time
        ts = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        out = os.path.join(self.outdir, f'cab_{ts}.zip')
        if os.path.exists(out):
            os.remove(out)
        with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
            for name in ['summary.json','report.json','report.csv','report.html','plan.txt','inventory.ini','site.yml','ansible.json']:
                p = os.path.join(self.outdir, name)
                if os.path.exists(p):
                    z.write(p, arcname=name)
        return out


    def __init__(self, outdir):
        self.outdir = outdir
        os.makedirs(self.outdir, exist_ok=True)

    def build(self, summary: dict):
        json_path = os.path.join(self.outdir, "report.json")
        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)

        csv_path = os.path.join(self.outdir, "report.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["control_id", "task", "host", "status"])
            for r in summary.get("tasks", []):
                w.writerow([r.get("control_id"), r.get("task"), r.get("host"), r.get("status")])

        html_tmpl = Template("""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Ansiaudit Report — {{ summary.role }} — {{ summary.host }} — {{ summary.mode|upper }}</title>
  <link rel="stylesheet" href="../static/app.css">
</head>
<body>
  <header><h1>Ansiaudit Report — {{ summary.role }} — {{ summary.host }} — {{ summary.mode|upper }}</h1></header>
  <section>
    <p>Return Code: {{ summary.return_code }}, Generated: {{ now }}</p>
    <h2>Summary</h2>
    <ul>
      <li>Total tasks: {{ summary.tasks|length }}</li>
      <li>Compliant (ok/skipped): {{ summary.compliant|length }}</li>
      <li>Non-compliant (changed/failed): {{ summary.noncompliant|length }}</li>
    </ul>
  </section>
  <section>
    <h2>Non-Compliant Controls</h2>
    <table>
      <thead><tr><th>Control ID</th><th>Task</th><th>Status</th></tr></thead>
      <tbody>
      {% for r in summary.noncompliant %}
        <tr>
          <td>{{ r.control_id or '-' }}</td>
          <td>{{ r.task }}</td>
          <td>{{ r.status }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </section>
  <section>
    <h2>All Tasks</h2>
    <table>
      <thead><tr><th>Status</th><th>Control ID</th><th>Task</th></tr></thead>
      <tbody>
      {% for r in summary.tasks %}
        <tr>
          <td>{{ r.status }}</td>
          <td>{{ r.control_id or '-' }}</td>
          <td>{{ r.task }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </section>
</body>
</html>""")
        html_path = os.path.join(self.outdir, "report.html")
        with open(html_path, "w") as f:
            f.write(html_tmpl.render(summary=summary, now=datetime.datetime.utcnow().isoformat()+"Z"))
        return {"json": json_path, "csv": csv_path, "html": html_path}

def _load_csv_controls(csv_path):
    data = {}
    if not os.path.exists(csv_path):
        return data
    with open(csv_path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            cid = row.get("control_id") or ""
            data[cid] = row.get("status")
    return data

def compose_change_plan(zip_out, before_dir, after_dir, remediate_dir=None):
    def load_summary(d):
        p = os.path.join(d, "summary.json")
        if os.path.exists(p):
            with open(p) as f:
                return json.load(f)
        return {}

    before = load_summary(before_dir) if before_dir else {}
    after = load_summary(after_dir) if after_dir else {}
    before_csv = _load_csv_controls(os.path.join(before_dir, "report.csv")) if before_dir else {}
    after_csv = _load_csv_controls(os.path.join(after_dir, "report.csv")) if after_dir else {}

    import tempfile, csv as _csv
    tmpdir = tempfile.mkdtemp()
    diff_csv = os.path.join(tmpdir, "controls_diff.csv")
    with open(diff_csv, "w", newline="") as f:
        w = _csv.writer(f)
        w.writerow(["control_id", "before_status", "after_status", "changed"])
        all_ids = sorted(set(list(before_csv.keys()) + list(after_csv.keys())))
        for cid in all_ids:
            b = before_csv.get(cid, "")
            a = after_csv.get(cid, "")
            w.writerow([cid, b, a, "YES" if (b and a and b!=a) else ""])

    plan_md = os.path.join(tmpdir, "change_plan.md")
    role = after.get("role") or before.get("role") or ""
    host = after.get("host") or before.get("host") or ""
    with open(plan_md, "w") as f:
        f.write(f"# Change Plan\n\n")
        f.write(f"- Role: {role}\n- Host: {host}\n- Before run: {os.path.basename(before_dir) if before_dir else '-'}\n- After run: {os.path.basename(after_dir) if after_dir else '-'}\n")
        f.write("\n## Summary\n")
        f.write(f"- Before non-compliant: {len(before.get('noncompliant', [])) if before else 0}\n")
        f.write(f"- After non-compliant: {len(after.get('noncompliant', [])) if after else 0}\n")

    if os.path.exists(zip_out):
        os.remove(zip_out)
    with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as z:
        for label, d in [("before", before_dir), ("after", after_dir)]:
            if d and os.path.exists(os.path.join(d, "summary.json")):
                for name in ["summary.json", "report.json", "report.csv", "report.html", "plan.txt", "inventory.ini", "site.yml", "ansible.json"]:
                    p = os.path.join(d, name)
                    if os.path.exists(p):
                        z.write(p, arcname=f"{label}/{name}")
        if remediate_dir and os.path.exists(os.path.join(remediate_dir, "summary.json")):
            for name in ["summary.json", "plan.txt", "ansible.json"]:
                p = os.path.join(remediate_dir, name)
                if os.path.exists(p):
                    z.write(p, arcname=f"remediation/{name}")
        z.write(diff_csv, arcname="controls_diff.csv")
        z.write(plan_md, arcname="change_plan.md")
    return zip_out
