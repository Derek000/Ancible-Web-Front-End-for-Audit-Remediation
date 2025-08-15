import os, json
from app.security import SecretBox

def test_secretbox_roundtrip(tmp_path, monkeypatch):
    keypath = tmp_path/"key"
    from importlib import reload
    box = SecretBox(key_path=keypath)
    pt = b"example-secret"
    t = box.encrypt(pt, b"host")
    assert box.decrypt(t, b"host") == pt
