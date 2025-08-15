from app.security import SecretBox
def test_secretbox_roundtrip(tmp_path):
    keypath = tmp_path/'key'
    sb = SecretBox(key_path=keypath)
    t = sb.encrypt(b'secret', b'host')
    assert sb.decrypt(t, b'host') == b'secret'
