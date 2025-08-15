import os, base64, pathlib, json
from flask import request, session, redirect, url_for
from flask_wtf import CSRFProtect

csrf = CSRFProtect()

def load_env():
    from dotenv import load_dotenv
    load_dotenv()

def apply_security_headers(app):
    @app.after_request
    def set_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-XSS-Protection"] = "0"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        return resp

# ----- Secret backends -----
class SecretBackend:
    def encrypt(self, plaintext: bytes, context: str = "") -> str:
        raise NotImplementedError
    def decrypt(self, token: str, context: str = "") -> bytes:
        raise NotImplementedError

# Default local AES-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
class LocalSecretBox(SecretBackend):
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
    def encrypt(self, plaintext: bytes, context: str = "") -> str:
        aad = context.encode()
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, plaintext, aad)
        return base64.urlsafe_b64encode(nonce + ct).decode("utf-8")
    def decrypt(self, token: str, context: str = "") -> bytes:
        raw = base64.urlsafe_b64decode(token.encode("utf-8"))
        nonce, ct = raw[:12], raw[12:]
        return self._aead.decrypt(nonce, ct, context.encode())

# HashiCorp Vault (optional)
class VaultBackend(SecretBackend):
    def __init__(self):
        import hvac
        self.client = hvac.Client(url=os.environ.get("VAULT_ADDR"), token=os.environ.get("VAULT_TOKEN"))
        self.path = os.environ.get("VAULT_KV_PATH", "secret/data/ansiaudit")
    def encrypt(self, plaintext: bytes, context: str = "") -> str:
        # store secret at path/context and return a reference token
        name = f"{context}".replace(":", "_").replace(".", "_")
        self.client.secrets.kv.v2.create_or_update_secret(path=f"{self.path}/{name}", secret={"value": base64.b64encode(plaintext).decode()})
        return f"vault://{name}"
    def decrypt(self, token: str, context: str = "") -> bytes:
        name = token.replace("vault://", "")
        data = self.client.secrets.kv.v2.read_secret_version(path=f"{self.path}/{name}")
        v = data["data"]["data"]["value"]
        return base64.b64decode(v.encode())

# AWS KMS (optional)
class AWSKMSBackend(SecretBackend):
    def __init__(self):
        import boto3
        self.kms = boto3.client("kms", region_name=os.environ.get("AWS_REGION"))
        self.key_id = os.environ.get("KMS_KEY_ID")
    def encrypt(self, plaintext: bytes, context: str = "") -> str:
        if not self.key_id:
            raise RuntimeError("KMS_KEY_ID not set")
        resp = self.kms.encrypt(KeyId=self.key_id, Plaintext=plaintext, EncryptionContext={"context": context or "ansiaudit"})
        return "kms://" + base64.b64encode(resp["CiphertextBlob"]).decode()
    def decrypt(self, token: str, context: str = "") -> bytes:
        blob = base64.b64decode(token.replace("kms://", "").encode())
        resp = self.kms.decrypt(CiphertextBlob=blob, EncryptionContext={"context": context or "ansiaudit"})
        return resp["Plaintext"]

def get_secret_backend() -> SecretBackend:
    mode = os.environ.get("SECRET_BACKEND", "local").lower()
    if mode == "vault":
        return VaultBackend()
    if mode == "awskms":
        return AWSKMSBackend()
    return LocalSecretBox()

# Backwards-compatible helper
class SecretBox:
    def __init__(self):
        self._b = get_secret_backend()
    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> str:
        return self._b.encrypt(plaintext, context=aad.decode() if aad else "")
    def decrypt(self, token: str, aad: bytes = b"") -> bytes:
        return self._b.decrypt(token, context=aad.decode() if aad else "")

# ----- AuthZ scaffolding (optional OIDC) -----
def is_auth_enabled():
    return os.environ.get("AUTH_MODE", "none").lower() == "oidc"

def require_role(role):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            if not is_auth_enabled():
                return fn(*args, **kwargs)
            user = session.get("user")
            if not user:
                return redirect(url_for("ui.login"))
            roles = user.get("roles", [])
            if role not in roles and "admin" != role:
                return redirect(url_for("ui.index"))
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator

# Simple OIDC login/logout if enabled (Authlib)
def init_auth(app):
    if not is_auth_enabled():
        return None
    from authlib.integrations.flask_client import OAuth
    oauth = OAuth(app)
    oauth.register(
        name="oidc",
        server_metadata_url=os.environ["OIDC_DISCOVERY_URL"],
        client_id=os.environ["OIDC_CLIENT_ID"],
        client_secret=os.environ["OIDC_CLIENT_SECRET"],
        client_kwargs={"scope": "openid email profile"}
    )
    @app.route("/login")
    def login():
        redirect_uri = url_for("auth_callback", _external=True)
        return oauth.oidc.authorize_redirect(redirect_uri)
    @app.route("/auth/callback")
    def auth_callback():
        token = oauth.oidc.authorize_access_token()
        userinfo = token.get("userinfo") or {}
        session["user"] = {
            "email": userinfo.get("email"),
            "name": userinfo.get("name") or userinfo.get("preferred_username"),
            "roles": userinfo.get("roles", []),
        }
        return redirect(url_for("ui.index"))
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("ui.index"))
    return oauth
