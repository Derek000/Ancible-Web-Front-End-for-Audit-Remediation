import os, requests, smtplib
from email.mime.text import MIMEText

def _smtp_send(subject, body):
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
    port = int(os.environ.get("SMTP_PORT", "25"))
    user = os.environ.get("SMTP_USER")
    pwd = os.environ.get("SMTP_PASS")
    from_addr = os.environ.get("SMTP_FROM", "ansiaudit@localhost")
    to_addrs = [x.strip() for x in os.environ.get("SMTP_TO","").split(",") if x.strip()]
    if not to_addrs:
        return False
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    s = smtplib.SMTP(host, port)
    try:
        if os.environ.get("SMTP_TLS") == "1":
            s.starttls()
        if user and pwd:
            s.login(user, pwd)
        s.sendmail(from_addr, to_addrs, msg.as_string())
    finally:
        s.quit()
    return True

def _post_json(url, payload):
    try:
        requests.post(url, json=payload, timeout=5)
        return True
    except Exception:
        return False

def notify(subject, body):
    ok = False
    if os.environ.get("SMTP_HOST"):
        ok = _smtp_send(subject, body) or ok
    if os.environ.get("SLACK_WEBHOOK"):
        ok = _post_json(os.environ["SLACK_WEBHOOK"], {"text": f"*{subject}*\n{body}"}) or ok
    if os.environ.get("TEAMS_WEBHOOK"):
        ok = _post_json(os.environ["TEAMS_WEBHOOK"], {"text": f"**{subject}**\n{body}"}) or ok
    return ok
