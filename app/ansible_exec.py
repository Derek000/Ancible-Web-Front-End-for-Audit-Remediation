import os, json, subprocess, datetime, shutil, re, glob, tempfile
from .security import SecretBox
from .db import db
from .models import Credential, LockdownRole, AnsibleRun

class AnsibleExecutor:
    def __init__(self, artifact_root='data/artifacts'):
        self.artifact_root = artifact_root
        os.makedirs(self.artifact_root, exist_ok=True)
        self.secrets = SecretBox()

    def _prep_inventory(self, host_ip, cred: Credential) -> str:
        inv_dir = os.path.join(self.artifact_root, "inventories")
        os.makedirs(inv_dir, exist_ok=True)
        inv_path = os.path.join(inv_dir, f"host_{host_ip.replace(':','_').replace('.','_')}.ini")
        lines = []
        if cred.is_windows:
            lines.append("[windows]")
            lines.append(f"{host_ip} ansible_user={cred.username} ansible_password={self.secrets.decrypt(cred.secret_enc).decode()} ansible_connection=winrm ansible_port={cred.port} ansible_winrm_transport=ntlm")
        else:
            lines.append("[linux]")
            if cred.auth_type == "password":
                lines.append(f"{host_ip} ansible_user={cred.username} ansible_password={self.secrets.decrypt(cred.secret_enc).decode()} ansible_port={cred.port} ansible_become={'yes' if cred.become else 'no'} ansible_become_method=sudo")
            else:
                keyfile = self._write_temp_key(self.secrets.decrypt(cred.secret_enc))
                lines.append(f"{host_ip} ansible_user={cred.username} ansible_ssh_private_key_file={keyfile} ansible_port={cred.port} ansible_become={'yes' if cred.become else 'no'} ansible_become_method=sudo")
        with open(inv_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return inv_path

    def _write_temp_key(self, key_bytes: bytes) -> str:
        keydir = os.path.join(self.artifact_root, "keys")
        os.makedirs(keydir, exist_ok=True)
        path = os.path.join(keydir, f"id_{os.urandom(4).hex()}")
        with open(path, "wb") as f:
            f.write(key_bytes)
        os.chmod(path, 0o600)
        return path

    def _detect_audit_tags(self, role_path: str):
        tags = set()
        for yml in glob.glob(os.path.join(role_path, "**", "*.yml"), recursive=True):
            try:
                with open(yml, "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read()
                for m in re.finditer(r"tags:\s*\n((?:\s*-\s*[^\n]+\n)+)", txt):
                    block = m.group(1)
                    for t in re.findall(r"-\s*([A-Za-z0-9_.:\-]+)", block):
                        tags.add(t.strip())
            except Exception:
                continue
        return list(sorted(tags))

    def run_role(self, run: AnsibleRun, cred: Credential, role: LockdownRole, mode="audit", selected_tags=None):
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        rundir = os.path.join(self.artifact_root, f"ansible_{run.id}_{ts}")
        os.makedirs(rundir, exist_ok=True)

        inventory = self._prep_inventory(run.host_ip, cred)
        role_path = role.path
        role_tags = self._detect_audit_tags(role_path)
        prefer_audit = "audit" in role_tags

        wrapper_playbook = os.path.join(rundir, "site.yml")
        with open(wrapper_playbook, "w") as f:
            f.write("---\n- hosts: all\n  gather_facts: yes\n  become: true\n  roles:\n    - { role: \"%s\" }\n" % role_path)

        cmd = ["ansible-playbook", "-i", inventory]
        if mode == "audit":
            if prefer_audit:
                cmd += ["--tags", "audit"]
            else:
                cmd += ["--check"]
        elif mode == "remediate" and selected_tags:
            cmd += ["--tags", ",".join(selected_tags)]
        cmd += ["-vvv", wrapper_playbook]

        env = os.environ.copy()
        roles_path = env.get("ANSIBLE_ROLES_PATH", "")
        env["ANSIBLE_ROLES_PATH"] = f"{roles_path}:{os.path.abspath('content/ansible-lockdown')}" if roles_path else os.path.abspath("content/ansible-lockdown")

        plan_path = os.path.join(rundir, "plan.txt")
        with open(plan_path, "w") as pf:
            pf.write("Command:\n")
            pf.write(" ".join(cmd) + "\n\n")
            pf.write(f"Role: {role.name}\nCommit: {role.commit or ''}\nMode: {mode}\nHost: {run.host_ip}\n")
            if selected_tags:
                pf.write(f"Tags: {','.join(selected_tags)}\n")

        jsonlog = os.path.join(rundir, "ansible.json")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        lines = []
        with open(jsonlog, "w") as jf:
            for line in proc.stdout:
                lines.append(line)
                jf.write(line)
        rc = proc.wait()

        summary = self._parse_ansible_output("\n".join(lines))
        summary["return_code"] = rc
        summary["mode"] = mode
        summary["role"] = role.name
        summary["host"] = run.host_ip
        summary["role_commit"] = role.commit

        inv_copy = os.path.join(rundir, "inventory.ini")
        try:
            shutil.copy(inventory, inv_copy)
        except Exception:
            pass

        summary_path = os.path.join(rundir, "summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        run.artifact_path = rundir
        run.status = "complete" if rc == 0 else "failed"
        from datetime import datetime as _dt
        run.finished_at = _dt.utcnow()
        db.session.add(run)
        db.session.commit()
        return rundir, summary

    def _parse_ansible_output(self, text: str):
        results = []
        current_task = None
        for line in text.splitlines():
            if line.strip().startswith("TASK ["):
                current_task = re.sub(r"^TASK \[", "", line.strip()).split("]")[0]
            m = re.search(r"(ok|changed|failed|skipping): \[(.+?)\]", line)
            if m and current_task:
                status = m.group(1)
                host = m.group(2)
                cid = None
                m2 = re.search(r"([A-Z]{3,5}[-_]\d{2}[-_]\d{5})", current_task)
                if not m2:
                    m3 = re.search(r"(CIS[-_:]\d+\.\d+(\.\d+)*)", current_task, re.I)
                    if m3:
                        cid = m3.group(1)
                else:
                    cid = m2.group(1)
                results.append({"task": current_task, "host": host, "status": status, "control_id": cid})
        compliant = [r for r in results if r["status"] in ("ok", "skipping")]
        noncompliant = [r for r in results if r["status"] in ("changed", "failed")]
        return {"tasks": results, "compliant": compliant, "noncompliant": noncompliant}
