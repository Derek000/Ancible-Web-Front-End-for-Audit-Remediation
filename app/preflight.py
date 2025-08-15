import os, shutil, subprocess

def _which(cmd):
    p = shutil.which(cmd)
    return p or ""

def _run(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return 0, out.strip()
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output.strip()
    except Exception as e:
        return 1, str(e)

def _import(module):
    try:
        __import__(module)
        return True, ""
    except Exception as e:
        return False, str(e)

def run_preflight():
    checks = []

    for label, cmd, ver_args in [
        ("ansible-playbook", "ansible-playbook", ["--version"]),
        ("ansible", "ansible", ["--version"]),
        ("nmap", "nmap", ["--version"]),
        ("git", "git", ["--version"]),
        ("python3", "python3", ["--version"]),
    ]:
        path = _which(cmd)
        ok = bool(path)
        detail = f"path={path}" if path else "not found on PATH"
        if ok and ver_args:
            rc, out = _run([cmd] + ver_args)
            detail += f"; version={out.splitlines()[0] if out else ''}"
            ok = ok and rc == 0
        checks.append({"category": "binaries", "name": label, "ok": ok, "detail": detail})

    nmap_path = _which("nmap")
    if nmap_path:
        rc, out = _run(["getcap", nmap_path])
        caps = out.split("=", 1)[1] if "=" in out else ""
        ok_caps = ("cap_net_raw" in caps and "cap_net_admin" in caps) or os.geteuid() == 0
        detail = f"caps={caps or 'none'}; ok_if_root={os.geteuid()==0}"
        checks.append({"category": "capabilities", "name": "nmap capabilities (-O)", "ok": ok_caps, "detail": detail})

    for mod in ["flask", "jinja2", "sqlalchemy", "cryptography", "apscheduler"]:
        ok, err = _import(mod)
        checks.append({"category": "python", "name": f"python:{mod}", "ok": ok, "detail": err})

    for mod in ["pywinrm"]:
        ok, err = _import(mod)
        checks.append({"category": "optional", "name": f"python:{mod}", "ok": ok, "detail": "optional; required for Windows targets" if ok else "missing (optional)"})

    data_dirs = ["data", "data/artifacts", "logs", "content/ansible-lockdown"]
    for d in data_dirs:
        try:
            os.makedirs(d, exist_ok=True)
            testfile = os.path.join(d, ".write_test")
            with open(testfile, "w") as f:
                f.write("ok")
            os.remove(testfile)
            checks.append({"category": "filesystem", "name": d, "ok": True, "detail": "writable"})
        except Exception as e:
            checks.append({"category": "filesystem", "name": d, "ok": False, "detail": f"not writable: {e}"})

    roles_root = "content/ansible-lockdown"
    present = []
    if os.path.isdir(roles_root):
        for entry in os.listdir(roles_root):
            if os.path.isdir(os.path.join(roles_root, entry)):
                present.append(entry)
    checks.append({"category": "roles", "name": "ansible-lockdown roles present", "ok": len(present) > 0, "detail": ", ".join(sorted(present)) or "none found; use Content>Lockdown Roles"})

    required = [c for c in checks if c["category"] in ("binaries", "filesystem")]
    overall = all(c["ok"] for c in required)
    return {"overall_ok": overall, "checks": checks}


def build_suggestion(check):
    name = check.get("name","")
    cat = check.get("category","")
    cmds = []
    tip = ""

    if cat == "binaries":
        if name in ("ansible-playbook", "ansible"):
            tip = "Install Ansible via APT or inside the project venv."
            cmds = [
                "sudo apt update && sudo apt install -y ansible",
                "python3 -m venv .venv && source .venv/bin/activate && pip install --upgrade pip && pip install 'ansible-core>=2.16,<2.18' 'ansible>=9,<10'"
            ]
        elif name == "nmap":
            tip = "Install Nmap (and grant capabilities for -O if desired)."
            cmds = [
                "sudo apt update && sudo apt install -y nmap",
                "sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)"
            ]
        elif name == "git":
            tip = "Install Git to fetch ansible-lockdown roles."
            cmds = ["sudo apt update && sudo apt install -y git"]
        elif name == "python3":
            tip = "Install system Python 3 if missing."
            cmds = ["sudo apt update && sudo apt install -y python3 python3-venv python3-dev build-essential"]

    elif cat == "capabilities" and "nmap capabilities" in name:
        tip = "Grant Nmap OS detection capabilities or run scans with sudo."
        cmds = ["sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)"]

    elif cat == "python":
        mod = name.split("python:",1)[-1]
        tip = f"Install the Python module '{mod}' (prefer inside the project venv)."
        cmds = [f"source .venv/bin/activate && pip install {mod}"]

    elif cat == "filesystem":
        path = check.get("name")
        tip = "Create and grant write access to the required directory."
        cmds = [f"sudo mkdir -p {path} && sudo chown $USER:$USER {path}"]

    elif cat == "roles":
        tip = "Fetch a role via the UI: Content → Lockdown Roles (e.g., UBUNTU22-CIS, DEBIAN12-CIS)."
        cmds = []

    return {"tip": tip, "cmds": cmds}

def decorate_with_fixes(result: dict):
    for c in result.get("checks", []):
        if not c.get("ok"):
            c["fix"] = build_suggestion(c)
        else:
            c["fix"] = {"tip": "", "cmds": []}
    return result
