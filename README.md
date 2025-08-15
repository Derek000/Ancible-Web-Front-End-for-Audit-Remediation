# Ansiaudit UI — Ansible Network Audit & Remediation
This is a work in progress.

## Why
Lift control compliance quickly with credible, repeatable evidence for CIS/STIG.

## Who
Security engineers, SREs, platform teams, and responders needing AUDIT/Remediate at scale.

## What
Local browser UI (Flask + HTMX) for Kali/Debian/Ubuntu with: scanning, credentials, ansible-lockdown AUDIT/Remediate, evidence reports, bulk ops with progress + ETA, scheduler + notifications, CAB exports, and a Preflight page.

## Prerequisites (Kali/Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y   ansible   nmap   git   python3-venv python3-dev build-essential
```

## Option B — Keep Ansible in the project venv
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install "ansible-core>=2.16,<2.18" "ansible>=9,<10"
pip install -r requirements.txt
```

## Quickstart
```bash
make install
make run
# open http://127.0.0.1:8000
```

### Nmap OS detection
Grant capabilities (or run scans with sudo):
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

## How to use
1. **Preflight** — verify environment.
2. **Content** — fetch ansible-lockdown roles (e.g., `UBUNTU22-CIS`).
3. **Scan** — discover assets.
4. **Assets** — set credentials.
5. **AUDIT** → **Report** → **Remediate** → **Change Plan**.
6. **Bulk** — run many hosts with live progress.
7. **Schedules** — recurring audits with notifications.

## Docker (optional)
Install Ansible in image:
```
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "ansible-core>=2.16,<2.18" "ansible>=9,<10"
```

## Preflight (first run)
Use **Preflight** in the navbar to validate your environment:
- Binaries present (`ansible-playbook`, `ansible`, `nmap`, `git`)
- Nmap capabilities for OS detection
- Python modules
- Writable data/logs/content paths
- ansible-lockdown roles present


### Preflight enhancements
- **Inline fix suggestions**: failing checks list specific commands to copy-paste.
- **One-click re-check**: run Preflight again without reloading the whole page.


## Ports page (TCP/UDP)
Use **Ports** to scan open services on selected or bulk targets.
- Profiles: TCP top common, TCP top 1–1024, UDP common, or custom port lists/ranges.
- Optional **service version detection** (-sV).
- Results are saved per-host under `data/artifacts/ports_*` with `nmap.xml`, `summary.json`, `ports.csv`, and `report.html`.
- Bulk runs have a live **progress page** with quick summaries and links to per-host reports.

**Notes**
- UDP scanning may need elevated privileges and is slower by nature; consider focusing on common UDP ports.
- You can run the app as your user and grant Nmap capabilities to support advanced scans:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
  ```


### Saved Port Profiles & Timing
- Create named **Port Profiles** with TCP/UDP lists, `-sV`, **timing (T0–T5)**, and **host-timeout**.
- Apply a saved profile from the **Ports** page or delete outdated ones.
- Use timing to throttle aggressiveness (T0 slow/stealth → T5 fastest). Host-timeout accepts values like `90s`, `2m`, `1h`.
