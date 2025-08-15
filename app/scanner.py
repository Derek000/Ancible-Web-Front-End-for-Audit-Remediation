import os, subprocess, json, datetime, ipaddress
from .db import db
from .models import Host, NetworkScan

class NmapScanner:
    def __init__(self, artifact_root='data/artifacts'):
        self.root = artifact_root
        os.makedirs(self.root, exist_ok=True)

    def scan(self, scan: NetworkScan):
        ts = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        outdir = os.path.join(self.root, f"scan_{scan.id}_{ts}")
        os.makedirs(outdir, exist_ok=True)
        targets = scan.targets.replace(',', ' ').split()
        cmd = ["nmap", "-O", "-sS", "-sV", "-T4", "-oX", os.path.join(outdir, "scan.xml")] + targets
        subprocess.run(cmd, check=False)
        # very light parse: record targets in DB (IP only)
        for t in targets:
            try:
                ip = str(ipaddress.ip_address(t)) if "/" not in t else None
            except Exception:
                ip = None
            if ip:
                h = Host(ip=ip, os_family=None, hostname=None, network_scan_id=scan.id)
                db.session.add(h)
        db.session.commit()
        return outdir
