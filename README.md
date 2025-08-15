
# Ansiaudit UI — Ansible Network Audit & Remediation

## Why
Lift control compliance quickly with credible, repeatable evidence for CIS/STIG. Enable rapid approvals, safer remediations, and bulk execution during incidents.

## Who
Security engineers, SREs, platform teams, and responders needing AUDIT/Remediate at scale with strong reporting and change control artefacts.

## What
A local browser app (Flask + HTMX) for Kali/Debian/Ubuntu that:
- Scans IPv4/IPv6 ranges with Nmap, stores results by **Network Name + timestamp**.
- Manages credentials per asset (password or SSH key; WinRM optional).
- Fetches and runs **ansible-lockdown** roles for **AUDIT** and selective **Remediate**.
- Produces **evidence**: JSON/HTML/CSV reports with control IDs, task output.
- Supports **bulk** operations, progress with **live status & ETA**, and **scheduler** for recurring audits.
- Exports **CAB-ready** bundles and **before/after** **Change Plans**.

---

## Prerequisites (Kali/Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential nmap git
# Optional targets: Windows support requires WinRM on targets and 'pywinrm' in Python (pip install pywinrm)
```

## Quickstart
```bash
git clone https://github.com/your-org/AnsiauditUI.git
cd AnsiauditUI
make install
make run
# Open http://127.0.0.1:8000
```

Or without Make:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
./run.sh
```

### Nmap OS detection
OS fingerprinting (`-O`) needs privileges. Either run scans with `sudo` or grant capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

---

## Optional: Docker (experimental)
OS detection in containers needs capabilities. Example:
```bash
docker compose up --build       --remove-orphans
# App at http://localhost:8000
```
Compose grants `NET_RAW` and `NET_ADMIN` to support `nmap -O`.

---

## Configuration
Copy `.env.example` → `.env` and tune as needed.

Key settings:
- `BIND`, `PORT`, `SQLITE`, `CONTENT_ROOT`, `ARTIFACT_ROOT`, `LOG_LEVEL`, `PARALLELISM`
- Scheduler/notifications: `SMTP_*`, `SLACK_WEBHOOK`, `TEAMS_WEBHOOK`
- Secrets backend: `SECRET_BACKEND=local|vault|awskms` (+ Vault/KMS vars)
- Optional OIDC: `AUTH_MODE=oidc` + `OIDC_*`

See **Advanced features** below for samples.

---

## How to use (end-to-end)
1. **Scan** — “Scan” page → enter **Network Name** + targets (IPv4/IPv6). Results saved to `data/artifacts/scan_*`.
2. **Assets** — set host credentials (password/SSH key; WinRM). Credentials are encrypted at rest.
3. **Content** — fetch `ansible-lockdown/*` roles (e.g. `UBUNTU22-CIS`, `DEBIAN12-CIS`, `RHEL9-STIG`).
4. **AUDIT** — pick host + role → runs in **audit** mode. Evidence captured with control IDs.
5. **Report** — open HTML/CSV/JSON → review compliant vs non-compliant.
6. **Remediate** — select failed controls and run remediation using role `--tags`.
7. **Re-Audit** — verify changes.
8. **Bulk** — run across many hosts with live progress bar + ETA.
9. **Export** — per-run CAB package; or **Change Plan** (before/after + diff).

---

## Advanced features

### Bulk filters
On the **Bulk** page, filter assets by **Network Name** (from stored scans) and **OS family/name** before running.

### Scheduler + Notifications
- Create recurring **AUDIT** schedules: daily, weekly, interval, or custom cron.
- Optional email/Slack/Teams notifications at start.
- Set env vars:
  ```env
  SMTP_HOST=smtp.example.org
  SMTP_PORT=587
  SMTP_USER=ansiaudit
  SMTP_PASS=supersecret
  SMTP_TLS=1
  SMTP_FROM=ansiaudit@example.org
  SMTP_TO=secops@example.org,platform@example.org
  SLACK_WEBHOOK=https://hooks.slack.com/services/...
  TEAMS_WEBHOOK=https://outlook.office.com/webhook/...
  ```

### Secrets backends
- `SECRET_BACKEND=local` (default): AES-256-GCM master key at `~/.ansiaudit_ui/master.key` (0600).
- `SECRET_BACKEND=vault`: requires `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_KV_PATH`.
- `SECRET_BACKEND=awskms`: requires `AWS_REGION`, `KMS_KEY_ID`.

### Optional OIDC SSO/RBAC
Enable with:
```env
AUTH_MODE=oidc
OIDC_DISCOVERY_URL=https://idp/.well-known/openid-configuration
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
```

---

## Reporting & Change Control

- **Per-run CAB package:** includes plan, inventory, wrapper playbook, ansible output, and reports.
- **Before/After Change Plan:** one-click bundle from a remediation run; adds `controls_diff.csv` and `change_plan.md` with key deltas.

---

## Security alignment
- **OWASP/NIST/CIS** practices: local bind by default, CSP + anti-framing, CSRF, structured logging.
- **Credentials** encrypted at rest; per-host inventories; sanitised logs.
- **Supply chain**: roles downloaded from upstream and commit recorded.

---

## Assumptions / Limitations / Opportunities
**Assumptions**
- ansible-lockdown roles expose control IDs in names/tags for selective remediation.
- Targets reachable with provided creds; WinRM configured for Windows hosts.

**Limitations**
- Role audit semantics vary; app prefers `--tags audit`, else `--check`.
- Windows hardening requires platform-specific pre-reqs and WinRM.

**Opportunities**
- HashiCorp Vault / KMS integration at scale, SSO/RBAC hardening.
- ServiceNow/Jira export & automation.
- OpenSCAP/XCCDF adaptor for cross-evidence.

---

## Testing
```bash
make test
# or
source .venv/bin/activate && pytest -q
```

## Troubleshooting
- **Nmap OS detection fails**: ensure `sudo` or setcap on `nmap` binary.
- **Ansible SSH auth issues**: verify keys/permissions; try `ssh -v` manually.
- **Windows targets**: ensure WinRM enabled + reachable; consider `pywinrm`.

## License
MIT — see [LICENSE](LICENSE).

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports → [SECURITY.md](SECURITY.md).
