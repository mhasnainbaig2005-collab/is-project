"""Extra lab endpoints: tamper test, baby-step giant-step, forward secrecy."""
import math
from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from backend.dh_core import DHParty
from backend.crypto_layer import derive_aes_key, encrypt_message, decrypt_message
from backend.attacker import brute_force_discrete_log


def baby_step_giant_step(p: int, g: int, h: int) -> dict:
    """Solve g^x = h (mod p) in about sqrt(p) steps instead of p."""
    m = math.isqrt(p - 1) + 1
    table, cur = {}, 1
    for j in range(m):                      # baby steps: store g^j -> j
        table.setdefault(cur, j)
        cur = cur * g % p
    factor, gamma = pow(g, -m, p), h        # giant steps: h * g^(-m*i)
    for i in range(m):
        if gamma in table:
            x = i * m + table[gamma]
            return {"cracked": True, "x": x, "steps": m + i + 1, "table_size": len(table)}
        gamma = gamma * factor % p
    return {"cracked": False, "steps": 2 * m, "table_size": len(table)}


class TamperRequest(BaseModel):
    plaintext: str = "Transfer 100 PKR to Bob"
    bit_index: int = 0


def register(app: FastAPI, SESSION: dict) -> None:
    def need_session():
        if not SESSION.get("alice"):
            raise HTTPException(status_code=400, detail="Run Key Exchange Handshake first.")
        return SESSION["alice"]

    @app.post("/api/tamper-test")
    def tamper_test(req: TamperRequest):
        need_session()
        if not SESSION["handshake_complete"]:
            raise HTTPException(status_code=400, detail="Handshake was blocked. Run it again.")
        if SESSION["alice_aes_key"] != SESSION["bob_aes_key"]:
            raise HTTPException(status_code=400, detail="Turn off the MITM attack so both sides share a key.")
        pkt = encrypt_message(SESSION["alice_aes_key"], req.plaintext)
        ct = bytearray(bytes.fromhex(pkt["ciphertext_hex"]))
        bit = req.bit_index % (len(ct) * 8)
        ct[bit // 8] ^= 1 << (bit % 8)       # attacker flips one bit in transit
        try:
            decrypt_message(SESSION["bob_aes_key"], pkt["nonce_hex"], ct.hex())
            detected = False
        except InvalidTag:
            detected = True
        return {"original_hex": pkt["ciphertext_hex"], "tampered_hex": ct.hex(),
                "flipped_bit": bit, "detected": detected}

    @app.post("/api/bsgs-demo")
    def bsgs_demo():
        alice = need_session()
        bits = alice.p.bit_length()
        if bits > 40:
            return {"feasible": False, "p_bits": bits,
                    "reason": f"Even baby-step giant-step needs about 2^{bits // 2} steps and that much memory."}
        brute = brute_force_discrete_log(alice.p, alice.g, alice.public_key)
        bsgs = baby_step_giant_step(alice.p, alice.g, alice.public_key)
        return {"feasible": True, "p_bits": bits, "brute_steps": brute["steps_tried"], "bsgs": bsgs}

    @app.post("/api/forward-secrecy")
    def forward_secrecy():
        alice = need_session()
        p, g = alice.p, alice.g
        sessions = []
        for i in range(1, 4):               # three sessions, each with fresh ephemeral keys
            a, b = DHParty.create("Alice", p, g), DHParty.create("Bob", p, g)
            key = derive_aes_key(a.compute_shared_secret(b.public_key))
            sessions.append((a, b.public_key, encrypt_message(key, f"Session {i}: private message")))
        stolen = sessions[-1][0]            # attacker later steals the newest ephemeral key
        results = []
        for i, (_, b_pub, pkt) in enumerate(sessions, 1):
            try:
                key = derive_aes_key(pow(b_pub, stolen.private_key, p))
                text = decrypt_message(key, pkt["nonce_hex"], pkt["ciphertext_hex"])
                results.append({"session": i, "readable": True, "text": text})
            except InvalidTag:
                results.append({"session": i, "readable": False})
        return {"results": results}
