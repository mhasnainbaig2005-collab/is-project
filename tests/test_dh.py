import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from backend.dh_core import DHParty, PARAMETER_PRESETS
from backend.crypto_layer import (IdentitySigner, derive_aes_key,
                                  encrypt_message, decrypt_message)
from backend.extras import baby_step_giant_step
from backend.main import app

client = TestClient(app)


def test_both_sides_agree_on_secret():
    p, g = PARAMETER_PRESETS["production_2048"]["p"], 2
    a, b = DHParty.create("Alice", p, g), DHParty.create("Bob", p, g)
    assert a.compute_shared_secret(b.public_key) == b.compute_shared_secret(a.public_key)


def test_rejects_out_of_range_public_key():
    a = DHParty.create("Alice", 23, 5)
    with pytest.raises(ValueError):
        a.compute_shared_secret(1)


def test_aes_roundtrip_and_tamper_detection():
    key = derive_aes_key(123456789)
    assert len(key) == 32
    pkt = encrypt_message(key, "hello")
    assert decrypt_message(key, pkt["nonce_hex"], pkt["ciphertext_hex"]) == "hello"
    bad = bytearray(bytes.fromhex(pkt["ciphertext_hex"])); bad[0] ^= 1
    with pytest.raises(InvalidTag):
        decrypt_message(key, pkt["nonce_hex"], bad.hex())


def test_signature_rejects_forged_key():
    s = IdentitySigner("Alice")
    sig = s.sign_dh_public(8)
    assert IdentitySigner.verify_dh_public(s.public_hex(), "Alice", 8, sig)
    assert not IdentitySigner.verify_dh_public(s.public_hex(), "Alice", 9, sig)


@pytest.mark.parametrize("key", ["educational_tiny", "educational_medium"])
def test_bsgs_recovers_valid_exponent(key):
    p, g = PARAMETER_PRESETS[key]["p"], PARAMETER_PRESETS[key]["g"]
    h = pow(g, 17, p)
    r = baby_step_giant_step(p, g, h)
    assert r["cracked"] and pow(g, r["x"], p) == h


def handshake(**kw):
    body = {"preset_key": "educational_medium", "mitm_enabled": False, "auth_enabled": False, **kw}
    return client.post("/api/handshake", json=body).json()


def test_handshake_secure_vs_mitm_vs_blocked():
    assert handshake()["status"] == "secure"
    assert handshake(mitm_enabled=True)["status"] == "compromised"
    assert handshake(mitm_enabled=True, auth_enabled=True)["status"] == "blocked"


def test_lab_endpoints():
    handshake()
    assert client.post("/api/tamper-test", json={}).json()["detected"] is True
    d = client.post("/api/bsgs-demo").json()
    assert d["bsgs"]["steps"] < d["brute_steps"] or d["brute_steps"] < 600
    r = client.post("/api/forward-secrecy").json()["results"]
    assert r[-1]["readable"] is True
    handshake(preset_key="production_2048")
    assert client.post("/api/bsgs-demo").json()["feasible"] is False
