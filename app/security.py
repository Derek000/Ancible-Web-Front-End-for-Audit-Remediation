import os, base64, pathlib
from flask_wtf import CSRFProtect
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

csrf = CSRFProtect()

def load_env():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass

def apply_security_headers(app):
    @app.after_request
    def set_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-XSS-Protection"] = "0"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        return resp

class SecretBox:
    def __init__(self, key_path=None):
        if key_path is None:
            key_path = pathlib.Path.home() / ".ansiaudit_ui" / "master.key"
        key_path = pathlib.Path(key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if not key_path.exists():
            key_path.write_bytes(os.urandom(32))
            key_path.chmod(0o600)
        self._key = key_path.read_bytes()
        self._aead = AESGCM(self._key)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> str:
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, plaintext, aad if aad else None)
        return base64.urlsafe_b64encode(nonce + ct).decode("utf-8")

    def decrypt(self, token: str, aad: bytes = b"") -> bytes:
        raw = base64.urlsafe_b64decode(token.encode("utf-8"))
        nonce, ct = raw[:12], raw[12:]
        return self._aead.decrypt(nonce, ct, aad if aad else None)
